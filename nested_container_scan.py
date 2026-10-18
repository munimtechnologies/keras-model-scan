# Copyright 2026 MV2, Munim, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Static detector for the *nested-container* model-file evasion class.

Every single-format model scanner inspects only the OUTER container of a
model file. Attackers hide a dangerous payload (a pickle, an HDF5 config, a
NumPy object array) one or more compression / archive layers deeper, or
behind a codec the scanner's standard library cannot decode, so the payload
is never examined while the model loader still reaches it. This bypass class
is documented in:

  * "The Art of Hide and Seek: Making Pickle-Based Model Supply Chain
    Poisoning Stealthy Again" (Liu et al., USENIX Security 2026,
    arXiv:2508.19774) -- gz->pkl, tar->pkl, zip->zip->pkl, gz->tar->pkl, ...
  * CVE-2025-1945 / CVE-2025-1944 (ZIP flag-bit / central-directory
    manipulation hides a pickle from the scanner while ``torch.load`` loads
    it) and CVE-2025-10156 (a bad-CRC ZIP member halts the scanner).

This module walks the container tree with the Python standard library only
(``zipfile``, ``tarfile``, ``zlib``, ``bz2``, ``lzma``) under strict depth,
size, member-count and decompression-ratio caps. It NEVER executes, imports,
unpickles or otherwise deserializes any content: it reads a small prefix of
each member and classifies it by magic bytes / name. It reports the full
nesting PATH to each hidden payload -- the actionable thing single-layer
scanners miss -- and flags members it cannot open (an exception-driven
bypass surface) and codecs the standard library cannot decode.

It is a complement to, not a replacement for, the format-specific scanners:
once a payload is located it should be handed to the right one.
"""
from __future__ import annotations

import argparse
import bz2
import io
import json
import lzma
import os
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Optional

__version__ = "0.1.0"

# -- limits (defensive: bound work on untrusted input) ----------------------
MAX_DEPTH = 6                      # nesting layers before we stop descending
MAX_MEMBER_BYTES = 64 * 1024 * 1024   # per-member decompressed read cap
MAX_TOTAL_BYTES = 256 * 1024 * 1024   # total decompressed output per scan
MAX_MEMBERS = 20000               # total members visited per scan
PEEK_BYTES = 4096                 # prefix kept of a non-container leaf

SEVERITY_ORDER = {
    "NONE": 0,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Container magic -----------------------------------------------------------
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
# Codecs the stdlib (<=3.13) cannot decode -> silently skipped by scanners.
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_LZ4_MAGIC = b"\x04\x22\x4d\x18"

# Dangerous leaf magic ------------------------------------------------------
_PICKLE_PROTO = {b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"}
_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_NPY_MAGIC = b"\x93NUMPY"

# Dangerous by name when magic is inconclusive.
_DANGEROUS_EXT = {
    ".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib",
    ".npy", ".npz", ".h5", ".hdf5", ".model", ".pdparams", ".dill",
    ".mar", ".pck", ".sav",
}
# Compression extensions stripped so the inner name can be classified.
_STRIP_EXT = {".gz", ".bz2", ".xz", ".lzma", ".z", ".zst", ".lz4"}


@dataclass
class Finding:
    rule: str
    severity: str
    key: str
    value: str
    file: str
    location: str
    message: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "key": self.key,
            "value": self.value,
            "file": self.file,
            "location": self.location,
            "message": self.message,
        }


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)
    scanned_files: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class _State:
    """Per-scan budget tracker."""

    def __init__(self) -> None:
        self.total = 0
        self.members = 0
        self.limit_hit = False


# -- classification ---------------------------------------------------------
def _container_type(data: bytes) -> Optional[str]:
    """Return 'zip' | 'gzip' | 'bz2' | 'xz' | 'tar', or None."""
    if data[:4] in _ZIP_MAGICS:
        return "zip"
    if data[:2] == _GZIP_MAGIC:
        return "gzip"
    if data[:3] == _BZ2_MAGIC:
        return "bz2"
    if data[:6] == _XZ_MAGIC:
        return "xz"
    # tar has no leading magic (ustar sits at offset 257); validate structurally
    if len(data) >= 512:
        try:
            if tarfile.is_tarfile(io.BytesIO(data)):
                return "tar"
        except Exception:
            return None
    return None


def _unsupported_codec(data: bytes) -> Optional[str]:
    if data[:4] == _ZSTD_MAGIC:
        return "zstd"
    if data[:4] == _LZ4_MAGIC:
        return "lz4"
    return None


def _dangerous_leaf(data: bytes, name: str):
    """Return (kind, magic_confirmed) if the leaf looks dangerous, else None."""
    if data[:2] in _PICKLE_PROTO:
        return ("pickle", True)
    if data[:8] == _HDF5_MAGIC:
        return ("hdf5", True)
    if data[:6] == _NPY_MAGIC:
        return ("numpy-array", True)
    ext = os.path.splitext(name.lower())[1]
    if ext in _DANGEROUS_EXT:
        return (ext.lstrip("."), False)
    return None


def _inner_name(name: str) -> str:
    """Strip one trailing compression extension for leaf classification."""
    base, ext = os.path.splitext(name)
    if ext.lower() in _STRIP_EXT:
        return base
    return name


# -- bounded decompression --------------------------------------------------
def _decompress_capped(kind: str, data: bytes):
    """Decompress a single-stream blob to at most MAX_MEMBER_BYTES.

    Returns (out_bytes, truncated). Never raises for truncated streams; may
    raise for malformed input (caller converts that to an NC011 finding).
    """
    cap = MAX_MEMBER_BYTES
    if kind == "gzip":
        d = zlib.decompressobj(31)  # 16 + MAX_WBITS -> gzip framing
        out = d.decompress(data, cap + 1)
        truncated = bool(d.unconsumed_tail) or len(out) > cap
        return out[:cap], truncated
    if kind == "bz2":
        d = bz2.BZ2Decompressor()
        out = d.decompress(data, cap + 1)
        return out[:cap], len(out) > cap
    if kind == "xz":
        d = lzma.LZMADecompressor()
        out = d.decompress(data, cap + 1)
        return out[:cap], len(out) > cap
    raise ValueError(f"unknown stream kind {kind!r}")


# -- walker -----------------------------------------------------------------
def _mk(rule, severity, key, value, file, trail, message) -> Finding:
    return Finding(rule, severity, key, value, file,
                   " > ".join(trail), message)


def _flag_payload(kind, confirmed, layers, file, trail, findings) -> None:
    """Emit NC001 when a payload is hidden by nesting a plain scanner misses."""
    # A payload sitting directly inside ONE outer zip is the ordinary PyTorch
    # case that standard scanners already handle -> not an evasion.
    if layers == ["zip"]:
        return
    path = "->".join(layers + [kind])
    if confirmed:
        sev = "HIGH"
        detail = f"magic-confirmed {kind}"
    else:
        sev = "MEDIUM"
        detail = f"{kind} by name"
    msg = (
        f"Dangerous payload ({detail}) hidden under nesting path {path}; "
        "single-format scanners inspect only the outer container and miss it "
        "(arXiv:2508.19774; CVE-2025-1945). Route this member to the matching "
        "format scanner before loading."
    )
    findings.append(_mk("NC001", sev, "nested_payload", kind, file, trail, msg))


def _walk(data, name, layers, trail, file, state, findings) -> None:
    if state.limit_hit:
        return
    if state.members > MAX_MEMBERS or state.total > MAX_TOTAL_BYTES:
        state.limit_hit = True
        findings.append(_mk(
            "NC003", "LOW", "limit", "budget", file, trail,
            "Scan budget (member count or total decompressed size) exhausted; "
            "remaining nested members were not inspected (possible decompression "
            "bomb or pathological nesting)."))
        return

    codec = _unsupported_codec(data)
    if codec is not None:
        if layers:  # a nested member stdlib cannot decode -> blind spot
            findings.append(_mk(
                "NC010", "MEDIUM", "unsupported_codec", codec, file, trail,
                f"Nested member is {codec}-compressed; the Python standard "
                "library cannot decode it, so stdlib-based scanners skip it "
                "silently -- an evasion surface (arXiv:2508.19774). Decode with "
                f"the {codec} codec and rescan the contents."))
        return

    ctype = _container_type(data)

    if ctype is None:
        leaf = _dangerous_leaf(data, name)
        if leaf is not None and layers:
            kind, confirmed = leaf
            _flag_payload(kind, confirmed, layers, file, trail, findings)
        return

    # It is a container. A container nested inside another container is itself
    # the chained-nesting structure the bypass relies on.
    if layers:
        findings.append(_mk(
            "NC002", "MEDIUM", "nested_container", ctype, file, trail,
            f"Container-within-container: a {ctype} archive nested inside "
            f"{'->'.join(layers)}. Chained containers are used to push a "
            "payload past single-layer scanners (arXiv:2508.19774)."))

    if len(layers) >= MAX_DEPTH:
        findings.append(_mk(
            "NC003", "LOW", "limit", "depth", file, trail,
            f"Maximum nesting depth ({MAX_DEPTH}) reached; deeper members were "
            "not inspected (possible anti-analysis nesting)."))
        return

    if ctype in ("gzip", "bz2", "xz"):
        try:
            inner, truncated = _decompress_capped(ctype, data)
        except Exception as exc:  # malformed stream the loader may still read
            findings.append(_mk(
                "NC011", "MEDIUM", "unreadable_member", ctype, file, trail,
                f"Nested {ctype} stream could not be decoded by the standard "
                f"library ({type(exc).__name__}); a model loader using a "
                "different decoder may still read it, so it is an exception-"
                "driven blind spot (cf. CVE-2025-10156)."))
            return
        if truncated:
            findings.append(_mk(
                "NC003", "LOW", "limit", "ratio", file, trail,
                f"Nested {ctype} stream exceeds the per-member decompression "
                "cap; only a prefix was inspected (possible decompression "
                "bomb)."))
        state.total += len(inner)
        state.members += 1
        _walk(inner, _inner_name(name), layers + [ctype],
              trail + [f"{name}#{ctype}"], file, state, findings)
        return

    if ctype == "zip":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            infos = zf.infolist()
        except Exception as exc:
            findings.append(_mk(
                "NC011", "MEDIUM", "unreadable_member", "zip", file, trail,
                f"Nested zip could not be parsed by the standard library "
                f"({type(exc).__name__}); loaders tolerant of malformed zips "
                "may still read it (cf. CVE-2025-1944, CVE-2025-10156)."))
            return
        for info in infos:
            if state.limit_hit:
                return
            if info.is_dir():
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                findings.append(_mk(
                    "NC003", "LOW", "limit", "member_size", file,
                    trail + [info.filename],
                    "Zip member exceeds the per-member cap and was not read "
                    "(possible decompression bomb)."))
                continue
            try:
                with zf.open(info) as fh:
                    mdata = fh.read(MAX_MEMBER_BYTES + 1)
            except Exception as exc:
                # bad CRC / encrypted / bad flag bits: the exact surface of
                # the scanner-halting bypass CVEs.
                findings.append(_mk(
                    "NC011", "MEDIUM", "unreadable_member", info.filename,
                    file, trail + [info.filename],
                    f"Zip member '{info.filename}' could not be read by the "
                    f"standard library ({type(exc).__name__}); the model "
                    "loader may still extract it, hiding the member from the "
                    "scanner (CVE-2025-10156 bad CRC; CVE-2025-1944/1945)."))
                continue
            state.total += len(mdata)
            state.members += 1
            _walk(mdata[:MAX_MEMBER_BYTES], info.filename, layers + ["zip"],
                  trail + [info.filename], file, state, findings)
        return

    if ctype == "tar":
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
            members = tf.getmembers()
        except Exception as exc:
            findings.append(_mk(
                "NC011", "MEDIUM", "unreadable_member", "tar", file, trail,
                f"Nested tar could not be parsed by the standard library "
                f"({type(exc).__name__})."))
            return
        for m in members:
            if state.limit_hit:
                return
            if not m.isfile():
                continue
            if m.size > MAX_MEMBER_BYTES:
                findings.append(_mk(
                    "NC003", "LOW", "limit", "member_size", file,
                    trail + [m.name],
                    "Tar member exceeds the per-member cap and was not read "
                    "(possible decompression bomb)."))
                continue
            try:
                fo = tf.extractfile(m)
                if fo is None:
                    continue
                mdata = fo.read(MAX_MEMBER_BYTES + 1)
            except Exception as exc:
                findings.append(_mk(
                    "NC011", "MEDIUM", "unreadable_member", m.name, file,
                    trail + [m.name],
                    f"Tar member '{m.name}' could not be read by the standard "
                    f"library ({type(exc).__name__})."))
                continue
            state.total += len(mdata)
            state.members += 1
            _walk(mdata[:MAX_MEMBER_BYTES], m.name, layers + ["tar"],
                  trail + [m.name], file, state, findings)
        return


# -- public API -------------------------------------------------------------
def scan_bytes(data: bytes, file: str = "<bytes>") -> list:
    """Scan an in-memory blob for nested-container evasion. Returns findings."""
    findings: list = []
    state = _State()
    name = os.path.basename(file) or file
    _walk(data, name, [], [name], file, state, findings)
    if not findings:
        findings.append(_mk(
            "NC000", "INFO", "clean", "", file, [name],
            "No nested-container evasion detected (no payload hidden under "
            "additional compression/archive layers, no stdlib-undecodable "
            "member, no unreadable member)."))
    return findings


def scan_file(path: str, result: ScanResult) -> None:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_TOTAL_BYTES + 1)
    except OSError as exc:
        result.errors.append(f"{path}: {exc}")
        return
    result.scanned_files.append(path)
    for f in scan_bytes(data, path):
        result.findings.append(f)


def scan_paths(paths: Iterable[str]) -> ScanResult:
    result = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for n in sorted(names):
                    scan_file(os.path.join(root, n), result)
        else:
            scan_file(p, result)
    return result


def _max_severity(findings: list) -> int:
    best = 0
    for f in findings:
        best = max(best, SEVERITY_ORDER.get(f.severity, 0))
    return best


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nested_container_scan",
        description="Detect dangerous payloads hidden by nested archive / "
                    "compression layers that single-format model scanners miss.",
    )
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"],
        default="NONE",
        help="exit non-zero if a finding at or above this severity is present",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    result = scan_paths(args.paths)

    if args.json:
        print(json.dumps({
            "version": __version__,
            "scanned_files": result.scanned_files,
            "findings": [f.as_dict() for f in result.findings],
            "errors": result.errors,
        }, indent=2))
    else:
        for f in result.findings:
            print(f"[{f.severity}] {f.rule} {f.file} ({f.location}): {f.message}")
        for e in result.errors:
            print(f"[ERROR] {e}", file=sys.stderr)
        print(f"Scanned {len(result.scanned_files)} file(s); "
              f"{len(result.findings)} finding(s).")

    threshold = SEVERITY_ORDER[args.fail_on]
    if threshold > 0 and _max_severity(result.findings) >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
