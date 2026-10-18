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
"""Static detector for the GGUF tensor *data-region* out-of-bounds class.

GGUF carries no code-execution surface, but "no code execution" is not "safe to
parse." Every tensor info in the header declares an ``offset`` into the file's
data section. Loaders that memory-map the file (the default, fast path) compute a
pointer ``mmap_base + data_section_start + offset`` and hand it to the caller
*without* checking that ``offset`` (let alone ``offset + tensor_nbytes``) stays
inside the file. A crafted GGUF whose tensor offset points past end-of-file makes
the loader return a data pointer outside the mapping: an out-of-bounds read of
process memory as soon as the tensor is touched.

This is CVE-2026-108955 (Tiiny-AI PowerInfer ``gguf_init_from_file`` in ggml.c,
VulDB VDB-416774, CWE-125 out-of-bounds read; disclosed 2026-10-13). The same
root cause mirrors the upstream llama.cpp GGUF tensor-offset issue, so it is a
*class* across GGUF loaders, not one project's bug. The documented mitigation is
exactly "add offset validation and boundary checks when loading GGUF models":
with ``--no-mmap`` the bad file already errors; under default mmap it does not.

keras-model-scan's GGUF integrity validator (gguf_scan.py) already caps header
and metadata counts (GG003/GG006), tensor dimension overflow (GG009) and offset
*alignment* (GG011) -- but it does not validate that a tensor's data region lies
within the file. This module fills precisely that gap. It reads ONLY the magic,
header, metadata key/value table and tensor-info table (never the tensor data),
never executes, imports, unpickles or deserializes anything, and bounds-checks
every read so a hostile file is reported, not crashed on.

Rules:
  GDR000  INFO    No GGUF tensor data-region issues found (or not a GGUF file).
  GDR001  HIGH    Tensor data region starts at or beyond end-of-file
                  (data_section_start + offset >= file_size). CVE-2026-108955.
  GDR002  HIGH    Tensor data region ends beyond end-of-file
                  (start + exact nbytes > file_size) for a plainly-sized type.
  GDR010  MEDIUM  GGUF structure truncated/implausible before the data region;
                  bounds could not be validated.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

__version__ = "0.1.0"

GGUF_MAGIC = b"GGUF"
_DEFAULT_ALIGNMENT = 32

# Sanity caps so a hostile count never drives an unbounded loop/allocation.
_MAX_KV = 1_000_000
_MAX_TENSORS = 1_000_000
_MAX_DIMS = 16          # GGML uses <= 4; anything far above is malformed.
_MAX_ARRAY = 100_000_000

# GGUF metadata value types -> fixed byte size (STRING=8 and ARRAY=9 handled apart).
_SCALAR_SIZES = {
    0: 1,   # UINT8
    1: 1,   # INT8
    2: 2,   # UINT16
    3: 2,   # INT16
    4: 4,   # UINT32
    5: 4,   # INT32
    6: 4,   # FLOAT32
    7: 1,   # BOOL
    10: 8,  # UINT64
    11: 8,  # INT64
    12: 8,  # FLOAT64
}
_GGUF_TYPE_UINT32 = 4
_GGUF_TYPE_STRING = 8
_GGUF_TYPE_ARRAY = 9

# GGML tensor types whose byte size is unambiguous (block size 1), so an exact
# end-of-region check carries no false-positive risk. Quantized/block types are
# deliberately omitted: GDR001 still covers them, and skipping their size table
# avoids ever flagging a legitimate quantized tensor by a mis-stated block size.
_EXACT_ELEM_SIZE = {
    0: 4,   # F32
    1: 2,   # F16
    24: 1,  # I8
    25: 2,  # I16
    26: 4,  # I32
    27: 8,  # I64
    28: 8,  # F64
    30: 2,  # BF16
}

SEVERITY_ORDER = {"NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


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
    findings: List[Finding] = field(default_factory=list)
    scanned_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class _Truncated(Exception):
    """Raised when a structural read would run past the end of the buffer."""


class _Reader:
    """Little-endian cursor over ``data`` with strict bounds checks."""

    def __init__(self, data: bytes) -> None:
        self.d = data
        self.n = len(data)
        self.p = 0

    def _uint(self, k: int) -> int:
        if self.p + k > self.n:
            raise _Truncated()
        v = int.from_bytes(self.d[self.p:self.p + k], "little")
        self.p += k
        return v

    def u32(self) -> int:
        return self._uint(4)

    def u64(self) -> int:
        return self._uint(8)

    def take(self, k: int) -> bytes:
        if k < 0 or self.p + k > self.n:
            raise _Truncated()
        b = self.d[self.p:self.p + k]
        self.p += k
        return b

    def skip(self, k: int) -> None:
        if k < 0 or self.p + k > self.n:
            raise _Truncated()
        self.p += k


def _read_string(r: _Reader) -> bytes:
    ln = r.u64()
    return r.take(ln)


def _skip_value(r: _Reader, vtype: int) -> Optional[int]:
    """Advance past one metadata value; return its int for scalar UINT32 only."""
    size = _SCALAR_SIZES.get(vtype)
    if size is not None:
        b = r.take(size)
        if vtype == _GGUF_TYPE_UINT32:
            return int.from_bytes(b, "little")
        return None
    if vtype == _GGUF_TYPE_STRING:
        ln = r.u64()
        r.skip(ln)
        return None
    if vtype == _GGUF_TYPE_ARRAY:
        elem_type = r.u32()
        count = r.u64()
        elem_size = _SCALAR_SIZES.get(elem_type)
        if elem_size is not None:
            r.skip(elem_size * count)
            return None
        if elem_type == _GGUF_TYPE_STRING:
            if count > _MAX_ARRAY:
                raise _Truncated()
            for _ in range(count):
                ln = r.u64()
                r.skip(ln)
            return None
        # Array of array, or an unknown element type: cannot be parsed safely.
        raise _Truncated()
    # Unknown value type.
    raise _Truncated()


def _align_up(n: int, a: int) -> int:
    if a <= 0:
        a = _DEFAULT_ALIGNMENT
    return ((n + a - 1) // a) * a


def _name_str(name: bytes) -> str:
    try:
        return name.decode("utf-8", "replace")
    except Exception:
        return repr(name)


def _scan_gguf(data: bytes, file: str) -> List[Finding]:
    findings: List[Finding] = []
    if len(data) < 4 or data[:4] != GGUF_MAGIC:
        return findings  # Not a GGUF file: nothing for this scanner to say.

    r = _Reader(data)
    try:
        r.skip(4)  # magic
        _version = r.u32()
        tensor_count = r.u64()
        kv_count = r.u64()
        if tensor_count > _MAX_TENSORS or kv_count > _MAX_KV:
            findings.append(Finding(
                "GDR010", "MEDIUM", "header", str(kv_count), file,
                f"tensor_count={tensor_count} kv_count={kv_count}",
                "Implausible tensor/metadata count; data-region bounds not validated.",
            ))
            return findings

        alignment = _DEFAULT_ALIGNMENT
        for _ in range(kv_count):
            key = _read_string(r)
            vtype = r.u32()
            val = _skip_value(r, vtype)
            if key == b"general.alignment" and vtype == _GGUF_TYPE_UINT32 and val:
                alignment = val

        tensors = []
        for _ in range(tensor_count):
            name = _read_string(r)
            n_dims = r.u32()
            if n_dims > _MAX_DIMS:
                findings.append(Finding(
                    "GDR010", "MEDIUM", _name_str(name), str(n_dims), file,
                    f"n_dims={n_dims}",
                    "Implausible tensor dimension count; data-region bounds not validated.",
                ))
                return findings
            dims = [r.u64() for _ in range(n_dims)]
            ttype = r.u32()
            offset = r.u64()
            tensors.append((name, dims, ttype, offset))
        after_tensor_info = r.p
    except _Truncated:
        findings.append(Finding(
            "GDR010", "MEDIUM", "structure", "", file, "",
            "GGUF structure truncated or unparseable before the tensor data "
            "region; data-region bounds could not be validated.",
        ))
        return findings

    file_size = len(data)
    data_start = _align_up(after_tensor_info, alignment)
    if data_start > file_size:
        findings.append(Finding(
            "GDR010", "MEDIUM", "data_section", str(data_start), file,
            f"data_section_start={data_start} file_size={file_size}",
            "GGUF data section begins past end-of-file (truncated); data-region "
            "bounds could not be validated.",
        ))
        return findings

    for name, dims, ttype, offset in tensors:
        start = data_start + offset
        if start >= file_size:
            findings.append(Finding(
                "GDR001", "HIGH", _name_str(name), str(offset), file,
                f"data_offset={offset} abs_start={start} file_size={file_size}",
                "Tensor data offset places its start at or beyond end-of-file: an "
                "out-of-bounds read under the default mmap load path "
                "(CVE-2026-108955 class, CWE-125).",
            ))
            continue
        elem_size = _EXACT_ELEM_SIZE.get(ttype)
        if elem_size is not None:
            nelem = 1
            for d in dims:
                nelem *= d
            nbytes = nelem * elem_size
            if start + nbytes > file_size:
                findings.append(Finding(
                    "GDR002", "HIGH", _name_str(name), str(offset), file,
                    f"abs_start={start} nbytes={nbytes} file_size={file_size}",
                    "Tensor data region ends beyond end-of-file "
                    "(offset + tensor size exceeds the file): an out-of-bounds "
                    "read under the default mmap load path (CWE-125).",
                ))
    return findings


def scan_bytes(data: bytes, file: str = "<bytes>") -> List[Finding]:
    findings = _scan_gguf(data, file)
    if not findings:
        findings.append(Finding(
            "GDR000", "INFO", "", "", file, "",
            "No GGUF tensor data-region issues found.",
        ))
    return findings


def scan_file(path: str, result: ScanResult) -> None:
    result.scanned_files.append(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        result.errors.append(f"{path}: {exc}")
        return
    for finding in _scan_gguf(data, path):
        result.findings.append(finding)


def scan_paths(paths: Iterable[str]) -> ScanResult:
    result = ScanResult()
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for fname in sorted(files):
                    scan_file(os.path.join(root, fname), result)
        else:
            scan_file(path, result)
    return result


def _max_severity(findings: Iterable[Finding]) -> str:
    worst = "NONE"
    for f in findings:
        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(worst, 0):
            worst = f.severity
    return worst


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gguf_data_region_scan",
        description="Flag GGUF tensors whose data region falls outside the file "
                    "(CVE-2026-108955 out-of-bounds class). Static; never loads.",
    )
    parser.add_argument("paths", nargs="+", help="GGUF files or directories")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"],
        default="NONE",
        help="Exit 1 if a finding at or above this severity is present.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args(argv)

    result = scan_paths(args.paths)

    if args.json:
        print(json.dumps({
            "version": __version__,
            "scanned_files": result.scanned_files,
            "errors": result.errors,
            "findings": [f.as_dict() for f in result.findings],
        }, indent=2))
    else:
        for f in result.findings:
            loc = f" [{f.location}]" if f.location else ""
            print(f"{f.severity:8} {f.rule} {f.file}{loc}: {f.message}")
        for err in result.errors:
            print(f"ERROR    {err}")

    threshold = SEVERITY_ORDER.get(args.fail_on, 0)
    if threshold > 0 and SEVERITY_ORDER.get(_max_severity(result.findings), 0) >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
