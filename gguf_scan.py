# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# gguf_scan.py -- static integrity validator for GGUF model files (the llama.cpp /
# ggml container used by llama.cpp, Ollama, LM Studio, KoboldCpp and friends).
#
# This work was made with AI, by MV2 of Munim, Inc.
#
# GGUF, like safetensors, carries NO code-execution surface: it is weights plus a
# key/value metadata table, never pickled Python. The pickle scanner in this
# repository already reports that correctly. But "no code execution" is not "safe
# to parse": a GGUF header is entirely attacker-controlled data, and the hand-
# written C/C++ reader in ggml has repeatedly turned a malformed header into a
# heap out-of-bounds write via INTEGER OVERFLOW in a size calculation:
#
#   * CVE-2024-21825 / TALOS-2024-1912 -- an array/string count in the metadata
#     (``arr.n``) multiplied by ``sizeof(gguf_str)`` overflows, so the loader
#     allocates less than it then fills (heap overflow in GGUF_TYPE_ARRAY /
#     GGUF_TYPE_STRING parsing).
#   * CVE-2025-53630 -- the running ``ctx->size`` accumulated over a sequence of
#     tensors whose padded sizes overflow wraps to a small value; the later copy
#     overruns the undersized buffer.
#   * CVE-2026-27940 -- a bypass of the CVE-2025-53630 fix: the ``mem_size``
#     calculation in ``gguf_init_from_file_impl`` still overflows, undersizing a
#     malloc that a following fread overruns (tcache-tuned, exploitable).
#   * CVE-2026-33298 -- ``ggml_nbytes`` overflows when tensor dimensions are
#     crafted so ``(ne[i]-1)*nb[i]`` wraps, returning a size far smaller than the
#     tensor really needs and bypassing the memory check (heap overflow, RCE).
#
# Every one of these starts with a value this scanner can read straight out of the
# header: a declared count, a string length, an array length, or a set of tensor
# dimensions. This validator reads ONLY the header, metadata key/value table and
# tensor-info table -- it never reads tensor data, never mmaps weights, never
# imports ggml and never executes anything. It flags the header conditions that
# precede those overflows: counts and lengths that cannot fit in the file, array
# lengths whose byte size overflows, tensor dimensions whose product overflows a
# signed 64-bit element count, out-of-range type ids (an out-of-bounds index into
# the loader's type-size table), and a structure that runs off the end of the
# file. A finding means the file deserves review before a hand-written or older
# loader touches it; it is not proof of malice, and a clean result is not a
# guarantee of safety -- this is a static heuristic, not a sandbox.
#
# Spec: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
# Standard library only. No third-party dependencies.

from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional

__version__ = "0.1.0"

# Read at most this many bytes of the header region. A real GGUF header + metadata
# + tensor-info table is kilobytes to low megabytes; the weight data that follows
# is never needed here. If the declared structure runs past this cap we say so
# (GG012) rather than allocate blindly.
READ_CAP = 64 * 1024 * 1024

# gguf_metadata_value_type enum (uint32). Fixed-width scalar sizes in bytes; the
# two composite types (STRING, ARRAY) are handled separately.
_T_UINT8, _T_INT8 = 0, 1
_T_UINT16, _T_INT16 = 2, 3
_T_UINT32, _T_INT32 = 4, 5
_T_FLOAT32 = 6
_T_BOOL = 7
_T_STRING = 8
_T_ARRAY = 9
_T_UINT64, _T_INT64 = 10, 11
_T_FLOAT64 = 12

_SCALAR_SIZE = {
    _T_UINT8: 1, _T_INT8: 1, _T_BOOL: 1,
    _T_UINT16: 2, _T_INT16: 2,
    _T_UINT32: 4, _T_INT32: 4, _T_FLOAT32: 4,
    _T_UINT64: 8, _T_INT64: 8, _T_FLOAT64: 8,
}
_KNOWN_VALUE_TYPES = set(_SCALAR_SIZE) | {_T_STRING, _T_ARRAY}

# ggml_type ids are a dense enum used directly as an index into the loader's
# type-size / block-size table. The exact high end drifts as quant types are
# added and removed, but a value far above the live range is an out-of-bounds
# table index in a loader that does not range-check it. We treat ids above this
# as out-of-range (GG010); churn within the range is not flagged.
_MAX_GGML_TYPE = 39

# Per the spec: a tensor name is "at most 64 bytes" and n_dimensions is "currently
# at most 4". A loader that reads n_dimensions uint64 values into a fixed[4] array
# without checking is the first bug; we both flag it and refuse to iterate an
# absurd dimension count.
_NAME_MAX = 64
_NDIMS_SPEC_MAX = 4
_NDIMS_HARD_CAP = 1 << 16

# Signed 64-bit element-count ceiling. ggml stores ne[] (element counts) as int64;
# a product above this overflows it, the precondition for the ggml_nbytes /
# ctx->size integer-overflow family.
_INT64_MAX = (1 << 63) - 1

# Cap on how many array/string elements we will walk before giving up and
# reporting the file as abnormal, so a crafted count can never make us loop long.
_ELEM_WALK_CAP = 2_000_000

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    location: str
    cve: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "location": self.location,
            "cve": self.cve,
        }


class _Truncated(Exception):
    """Raised when a read would run past the bytes we hold."""


class _Reader:
    """A little-or-big-endian cursor over the header bytes with bounds checks.

    Every read is bounds-checked against the buffer we actually hold; a read past
    the end raises _Truncated, which the caller turns into a finding and stops.
    No read ever allocates based on an attacker-declared length."""

    def __init__(self, raw: bytes, little_endian: bool = True):
        self.raw = raw
        self.pos = 0
        self.end = len(raw)
        self._pfx = "<" if little_endian else ">"

    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise _Truncated()
        chunk = self.raw[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u32(self) -> int:
        return struct.unpack(self._pfx + "I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack(self._pfx + "Q", self._take(8))[0]

    def raw_len(self) -> int:
        """Read a gguf_string length (uint64) WITHOUT reading the bytes."""
        return self.u64()

    def skip(self, n: int) -> None:
        if n < 0 or self.pos + n > self.end:
            raise _Truncated()
        self.pos += n


def _skip_value(r: "_Reader", vtype: int, file_size: int,
                loc: str, out: List[Finding], depth: int = 0) -> bool:
    """Advance past one metadata value of type ``vtype``. Returns True to keep
    parsing, False if an unrecoverable condition was found and the caller should
    stop. Appends findings for the array-overflow / string-overrun classes."""
    if depth > 64:
        out.append(Finding(
            "GG005", "MEDIUM", "Metadata nested too deeply",
            "A metadata value nests arrays past a sane depth; a recursive reader "
            "can exhaust its stack on it.", loc, "CWE-674"))
        return False

    if vtype in _SCALAR_SIZE:
        r.skip(_SCALAR_SIZE[vtype])
        return True

    if vtype == _T_STRING:
        n = r.raw_len()
        if n > r.end or n > file_size:
            out.append(Finding(
                "GG004", "HIGH", "Metadata string overruns the file",
                f"A metadata string declares {n} bytes, past the end of the "
                f"file ({file_size} bytes). A loader that trusts the length "
                "reads out of bounds (the CVE-2024-21825 string class).",
                loc, "CWE-125"))
            return False
        r.skip(n)
        return True

    if vtype == _T_ARRAY:
        elem_type = r.u32()
        count = r.u64()
        if elem_type not in _KNOWN_VALUE_TYPES:
            out.append(Finding(
                "GG005", "MEDIUM", "Unknown metadata array element type",
                f"A metadata array declares element type id {elem_type}, which "
                "is not a GGUF value type (0-12). A loader may mis-size its "
                "elements.", loc, "CWE-20"))
            return False
        if elem_type in _SCALAR_SIZE:
            elem_size = _SCALAR_SIZE[elem_type]
            total = count * elem_size
            # Overflow of the allocation size (count * sizeof(elem)) is the exact
            # CVE-2024-21825 class; also flag a byte length that cannot fit.
            if count < 0 or total > (1 << 64) or total > r.end or total > file_size:
                out.append(Finding(
                    "GG006", "HIGH", "Metadata array length overflows allocation",
                    f"A metadata array declares {count} elements of {elem_size} "
                    f"byte(s) = {total} bytes, which overflows or exceeds the "
                    f"file ({file_size} bytes). count * sizeof(element) is the "
                    "size an unchecked loader allocates (CVE-2024-21825).",
                    loc, "CWE-190"))
                return False
            r.skip(total)
            return True
        # Array of strings or arrays: must walk, but never more than the cap.
        if count > _ELEM_WALK_CAP:
            out.append(Finding(
                "GG006", "HIGH", "Metadata array length implausibly large",
                f"A metadata array declares {count} composite elements, above "
                f"the {_ELEM_WALK_CAP} sanity cap. Validation stopped rather "
                "than walk an attacker-chosen element count.", loc, "CWE-190"))
            return False
        for _ in range(count):
            if not _skip_value(r, elem_type, file_size, loc, out, depth + 1):
                return False
        return True

    out.append(Finding(
        "GG005", "MEDIUM", "Unknown metadata value type",
        f"A metadata value declares type id {vtype}, which is not a GGUF value "
        "type (0-12). A loader may mis-parse every field after it.",
        loc, "CWE-20"))
    return False


def _detect_endianness(raw: bytes) -> Optional[bool]:
    """Return True for little-endian, False for big-endian, or None if the version
    looks sane under neither (so the magic is present but the file is corrupt)."""
    ver_le = struct.unpack("<I", raw[4:8])[0]
    if ver_le in (1, 2, 3):
        return True
    ver_be = struct.unpack(">I", raw[4:8])[0]
    if ver_be in (2, 3):
        return False
    return None


def scan_bytes(raw: bytes, file_size: int, loc: str) -> List[Finding]:
    """Validate the GGUF header region in ``raw`` (``file_size`` is the true file
    size, which may exceed ``len(raw)`` when the file is larger than the read
    cap). Pure: no file I/O."""
    out: List[Finding] = []

    if len(raw) < 8 or raw[:4] != b"GGUF":
        return [Finding(
            "GG001", "MEDIUM", "Not a GGUF file (bad magic)",
            "The file does not begin with the GGUF magic (47 47 55 46). It is "
            "corrupt, truncated, or mislabelled; do not feed it to a GGUF "
            "loader.", loc, "CWE-20")]

    little = _detect_endianness(raw)
    if little is None:
        return [Finding(
            "GG002", "MEDIUM", "Unsupported GGUF version",
            "The version field is not 1, 2 or 3 under either byte order; the "
            "header is corrupt or from an unknown GGUF revision.", loc, "CWE-20")]

    r = _Reader(raw, little_endian=little)
    r.skip(4)  # magic
    version = r.u32()
    if version == 1:
        # v1 used uint32 counts and a different tensor-info layout. We do not
        # deep-parse it; flag it as legacy so the caller does not trust a clean.
        out.append(Finding(
            "GG002", "LOW", "Legacy GGUF v1 header",
            "This is a GGUF v1 file (uint32 counts, older tensor-info layout). "
            "Integrity checks here target v2/v3; re-save to a current GGUF "
            "version before trusting it.", loc, "CWE-20"))
        return out

    try:
        tensor_count = r.u64()
        kv_count = r.u64()
    except _Truncated:
        return out + [Finding(
            "GG012", "MEDIUM", "Truncated GGUF header",
            "The file ends inside the fixed header (tensor/metadata counts).",
            loc, "CWE-20")]

    # The simplest malformed-counts class: a declared count that cannot fit in the
    # file. Each KV pair is at least 8 (key len) + 0 (empty key) + 4 (type) = 12
    # bytes; each tensor_info is at least 8 (name len) + 4 (n_dims) + 4 (type) +
    # 8 (offset) = 24 bytes. A count whose minimum footprint exceeds the file is
    # the allocation-DoS / wrap bait behind CVE-2025-53630 / CVE-2026-27940.
    _MIN_KV = 12
    _MIN_TI = 24
    if kv_count * _MIN_KV > file_size or kv_count > file_size:
        return out + [Finding(
            "GG003", "HIGH", "Metadata count exceeds file size",
            f"Header declares {kv_count} metadata entries, whose minimum "
            f"footprint ({kv_count * _MIN_KV} bytes) exceeds the file "
            f"({file_size} bytes). A loader sizing arrays by this count "
            "over-allocates or wraps (CVE-2025-53630 class).",
            loc, "CWE-130")]
    if tensor_count * _MIN_TI > file_size or tensor_count > file_size:
        return out + [Finding(
            "GG003", "HIGH", "Tensor count exceeds file size",
            f"Header declares {tensor_count} tensors, whose minimum footprint "
            f"({tensor_count * _MIN_TI} bytes) exceeds the file ({file_size} "
            "bytes). A loader sizing its tensor table by this count "
            "over-allocates or wraps (CVE-2025-53630 class).",
            loc, "CWE-130")]

    # ---- metadata key/value table -----------------------------------------
    alignment = 32  # general.alignment default; overridden if present and sane.
    truncated = False
    for _ in range(kv_count):
        try:
            key_len = r.raw_len()
            if key_len > r.end or key_len > file_size:
                out.append(Finding(
                    "GG004", "HIGH", "Metadata key length overruns the file",
                    f"A metadata key declares {key_len} bytes, past the end of "
                    f"the file ({file_size} bytes).", loc, "CWE-125"))
                truncated = True
                break
            key = r._take(key_len)
            vtype = r.u32()
            # Capture general.alignment (uint32) to check tensor offsets below.
            if key == b"general.alignment" and vtype == _T_UINT32:
                save = r.pos
                alignment = r.u32()
                r.pos = save  # let _skip_value advance normally
                if alignment == 0 or (alignment & (alignment - 1)) != 0:
                    out.append(Finding(
                        "GG011", "MEDIUM", "Invalid general.alignment",
                        f"general.alignment is {alignment}; it must be a nonzero "
                        "power of two. A zero or non-power-of-two alignment "
                        "breaks the offset arithmetic in a loader.",
                        loc, "CWE-20"))
                    alignment = 32
            if not _skip_value(r, vtype, file_size, loc, out):
                truncated = True
                break
        except _Truncated:
            out.append(Finding(
                "GG012", "MEDIUM", "Truncated metadata table",
                "The file ends inside the metadata key/value table; a loader "
                "reading the declared count runs off the end.", loc, "CWE-20"))
            truncated = True
            break

    if truncated:
        return out

    # ---- tensor-info table -------------------------------------------------
    for _ in range(tensor_count):
        try:
            name_len = r.raw_len()
            if name_len > r.end or name_len > file_size:
                out.append(Finding(
                    "GG004", "HIGH", "Tensor name length overruns the file",
                    f"A tensor name declares {name_len} bytes, past the end of "
                    f"the file ({file_size} bytes).", loc, "CWE-125"))
                break
            r.skip(name_len)
            if name_len > _NAME_MAX:
                out.append(Finding(
                    "GG007", "LOW", "Tensor name exceeds the 64-byte limit",
                    f"A tensor name is {name_len} bytes; the GGUF spec caps it "
                    f"at {_NAME_MAX}. A loader copying it into a fixed buffer "
                    "overflows.", loc, "CWE-120"))
            n_dims = r.u32()
            if n_dims > _NDIMS_HARD_CAP:
                out.append(Finding(
                    "GG008", "HIGH", "Tensor dimension count implausible",
                    f"A tensor declares {n_dims} dimensions; validation stopped "
                    "rather than read an attacker-chosen number of dimension "
                    "words.", loc, "CWE-20"))
                break
            if n_dims > _NDIMS_SPEC_MAX:
                out.append(Finding(
                    "GG008", "MEDIUM", "Tensor dimension count out of range",
                    f"A tensor declares {n_dims} dimensions; the GGUF spec "
                    f"allows at most {_NDIMS_SPEC_MAX}. A loader reading them "
                    "into a fixed[4] array overflows it.", loc, "CWE-787"))
            product = 1
            for _d in range(n_dims):
                product *= r.u64()
            ttype = r.u32()
            offset = r.u64()
            if product > _INT64_MAX:
                out.append(Finding(
                    "GG009", "HIGH", "Tensor dimensions overflow element count",
                    f"A tensor's dimensions multiply to {product} elements, "
                    "above the signed 64-bit ceiling. ggml stores element "
                    "counts as int64 and derives byte sizes from them, so this "
                    "is the ggml_nbytes integer-overflow precondition "
                    "(CVE-2026-33298).", loc, "CWE-190"))
            if ttype > _MAX_GGML_TYPE:
                out.append(Finding(
                    "GG010", "MEDIUM", "Out-of-range tensor type id",
                    f"A tensor declares ggml type id {ttype}, above the known "
                    f"range (0-{_MAX_GGML_TYPE}). A loader uses the id to index "
                    "its type-size table; an out-of-range id reads out of "
                    "bounds.", loc, "CWE-125"))
            if alignment and offset % alignment != 0:
                out.append(Finding(
                    "GG011", "LOW", "Tensor offset not aligned",
                    f"A tensor data offset ({offset}) is not a multiple of the "
                    f"alignment ({alignment}). The GGUF spec requires aligned "
                    "offsets; a loader assuming alignment miscomputes bounds.",
                    loc, "CWE-20"))
        except _Truncated:
            out.append(Finding(
                "GG012", "MEDIUM", "Truncated tensor-info table",
                "The file ends inside the tensor-info table; a loader reading "
                "the declared tensor count runs off the end.", loc, "CWE-20"))
            break

    if not out:
        out.append(Finding(
            "GG000", "INFO", "Well-formed GGUF header",
            f"GGUF v{version}: {tensor_count} tensors and {kv_count} metadata "
            "entries parse within the file with no count, length, dimension, "
            "type-id or alignment anomaly. GGUF carries no code-execution "
            "surface; this checks the header-integrity class behind the "
            "ggml/llama.cpp heap-overflow CVEs.", loc, ""))
    return out


def scan_file(path: str) -> List[Finding]:
    loc = os.fspath(path)
    try:
        file_size = os.path.getsize(path)
    except OSError as exc:
        return [Finding("GG012", "LOW", "Unreadable file",
                        f"Could not stat file: {exc}", loc, "CWE-20")]
    try:
        with open(path, "rb") as fh:
            raw = fh.read(READ_CAP)
    except OSError as exc:
        return [Finding("GG012", "LOW", "Unreadable file",
                        f"Could not read file: {exc}", loc, "CWE-20")]
    return scan_bytes(raw, file_size, loc)


def scan_path(path: str) -> List[Finding]:
    """Scan one file, or walk a directory tree for *.gguf files."""
    if os.path.isdir(path):
        out: List[Finding] = []
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(".gguf"):
                    out.extend(scan_file(os.path.join(root, fn)))
        return out
    return scan_file(path)


def _max_severity(findings: Iterable[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gguf-scan",
        description="Static integrity validator for GGUF model files. Flags the "
                    "header conditions (bad counts, overrunning lengths, "
                    "overflowing array/dimension sizes, out-of-range type ids) "
                    "behind the ggml/llama.cpp heap-overflow CVEs. Never reads "
                    "tensor data or executes a model. Made with AI by MV2 of "
                    "Munim, Inc.")
    parser.add_argument("paths", nargs="*", help="files or directories to scan")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit findings as JSON")
    parser.add_argument("--fail-on", default="MEDIUM",
                        choices=list(SEVERITY_ORDER),
                        help="exit 1 if any finding is at least this severity "
                             "(default MEDIUM)")
    parser.add_argument("--version", action="version",
                        version=f"gguf-scan {__version__}")
    args = parser.parse_args(argv)

    if not args.paths:
        parser.print_help()
        return 2

    all_findings: List[Finding] = []
    for p in args.paths:
        all_findings.extend(scan_path(p))

    if args.as_json:
        import json
        print(json.dumps([f.as_dict() for f in all_findings], indent=2))
    else:
        for f in all_findings:
            cve = f" [{f.cve}]" if f.cve else ""
            print(f"{f.severity:>8}  {f.rule}{cve}  {f.title}")
            print(f"          {f.detail}")
            print(f"          @ {f.location}")

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if _max_severity(all_findings) >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
