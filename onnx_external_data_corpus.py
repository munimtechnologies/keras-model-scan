"""Crafted-ONNX corpus generator for external_data path-traversal regression tests.

An .onnx file is a protobuf ``ModelProto``. It carries no code of its own, but a
tensor marked ``data_location = EXTERNAL`` names the file holding its weights in a
repeated ``external_data`` map whose ``location`` entry is, per the ONNX spec, a
RELATIVE path that must resolve *inside* the model directory. A loader that joins
that untrusted value onto the model directory without sanitising it can be steered
to read (or, in some loaders, write) an arbitrary local file at load time -- CWE-22
path traversal. Public cases:

  * onnx < 1.13.0  -- CVE-2022-25882 / GHSA-ffxj-547x-5j7c (fixed in 1.13.0)
  * tract-onnx     -- CVE-2026-55832 / GHSA-h668-6x6g-f8r5 (fixed 0.21.17/0.22.3/0.23.2)

Both are CWE-22, both fixed by forcing ``location`` to a relative, in-directory path.

This module writes a small, reproducible corpus of *header-only* crafted .onnx files
-- one per traversal technique plus one clean control -- so any ONNX loader (or a
scanner such as this project's ``onnx_external_data_scan.py``) can be regression-tested
against external_data path handling. The files contain NO tensor payload and NO exploit
code: only a protobuf header whose single external tensor names a malicious ``location``
string. A safe loader rejects every malicious file and accepts the clean one.

Standard library only -- no onnx, no protobuf runtime. The protobuf wire format is
emitted by hand so the corpus has no dependencies.

Made with AI by MV2 of Munim, Inc. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

__version__ = "0.1.0"

# --- ONNX protobuf field numbers (from the ONNX protobuf specification) ---------
# These match the numbers that onnx_external_data_scan.py parses.
_F_MODEL_IR_VERSION = 1      # ModelProto.ir_version      (varint)
_F_MODEL_GRAPH = 7           # ModelProto.graph           (message)
_F_MODEL_OPSET_IMPORT = 8    # ModelProto.opset_import    (message, repeated)

_F_GRAPH_NAME = 2            # GraphProto.name            (string)
_F_GRAPH_INIT = 5           # GraphProto.initializer     (message, repeated)

_F_TENSOR_DIMS = 1          # TensorProto.dims           (varint, repeated)
_F_TENSOR_DATA_TYPE = 2     # TensorProto.data_type      (varint)
_F_TENSOR_NAME = 8          # TensorProto.name           (string)
_F_TENSOR_EXTDATA = 13      # TensorProto.external_data  (message, repeated)
_F_TENSOR_DATALOC = 14      # TensorProto.data_location  (varint)

_F_SSE_KEY = 1              # StringStringEntryProto.key   (string)
_F_SSE_VALUE = 2           # StringStringEntryProto.value (string)

_F_OPSET_DOMAIN = 1        # OperatorSetIdProto.domain  (string)
_F_OPSET_VERSION = 2       # OperatorSetIdProto.version (varint)

_DATA_LOCATION_EXTERNAL = 1  # TensorProto.DataLocation.EXTERNAL
_TENSOR_FLOAT = 1            # TensorProto.DataType.FLOAT
_IR_VERSION = 8             # a plausible modern ONNX IR version


# --- protobuf wire-format encoders (wire types: 0 = varint, 2 = length-delimited)
def _varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field_no: int, wire: int) -> bytes:
    return _varint((field_no << 3) | wire)


def _f_varint(field_no: int, value: int) -> bytes:
    return _tag(field_no, 0) + _varint(value)


def _f_bytes(field_no: int, payload: bytes) -> bytes:
    return _tag(field_no, 2) + _varint(len(payload)) + payload


def _f_string(field_no: int, s: str) -> bytes:
    return _f_bytes(field_no, s.encode("utf-8", "surrogatepass"))


# --- ONNX message builders ------------------------------------------------------
def _string_string_entry(key: str, value: str) -> bytes:
    return _f_string(_F_SSE_KEY, key) + _f_string(_F_SSE_VALUE, value)


def _external_tensor(name: str, location: str, dims: Tuple[int, ...] = (2, 3)) -> bytes:
    body = b""
    for d in dims:
        body += _f_varint(_F_TENSOR_DIMS, d)
    body += _f_varint(_F_TENSOR_DATA_TYPE, _TENSOR_FLOAT)
    body += _f_string(_F_TENSOR_NAME, name)
    body += _f_bytes(_F_TENSOR_EXTDATA, _string_string_entry("location", location))
    body += _f_varint(_F_TENSOR_DATALOC, _DATA_LOCATION_EXTERNAL)
    return body


def _opset(domain: str = "", version: int = 14) -> bytes:
    return _f_string(_F_OPSET_DOMAIN, domain) + _f_varint(_F_OPSET_VERSION, version)


def _graph(tensor: bytes, name: str = "corpus_graph") -> bytes:
    return _f_string(_F_GRAPH_NAME, name) + _f_bytes(_F_GRAPH_INIT, tensor)


def build_model(location: str, tensor_name: str = "weight") -> bytes:
    """Build a minimal valid ModelProto whose single external tensor's
    ``external_data`` location entry is *location*."""
    model = _f_varint(_F_MODEL_IR_VERSION, _IR_VERSION)
    model += _f_bytes(_F_MODEL_OPSET_IMPORT, _opset())
    model += _f_bytes(_F_MODEL_GRAPH, _graph(_external_tensor(tensor_name, location)))
    return model


# --- corpus cases ---------------------------------------------------------------
@dataclass
class Case:
    name: str
    location: str
    rules: List[str] = field(default_factory=list)
    severity: str = "high"
    note: str = ""

    @property
    def filename(self) -> str:
        return self.name + ".onnx"

    @property
    def malicious(self) -> bool:
        return bool(self.rules)


# Each malicious case isolates one scanner rule where possible. Severities are this
# corpus's own CWE-22 classification, not a promise about any specific scanner's output.
CASES: List[Case] = [
    Case("traversal_posix", "../../../../../../etc/passwd", ["OED001"], "high",
         "parent-directory segment escapes the model directory"),
    Case("absolute_posix", "/etc/shadow", ["OED002"], "high",
         "absolute POSIX path ignores the model directory entirely"),
    Case("url_http", "http://169.254.169.254/latest/meta-data/iam/", ["OED003"], "high",
         "remote URL scheme turns a load into an outbound/SSRF fetch"),
    Case("url_file", "file:///etc/passwd", ["OED003"], "high",
         "file:// URL scheme reaches an arbitrary local path"),
    Case("nul_byte", "weights.bin\x00.png", ["OED004"], "medium",
         "embedded NUL can truncate the path in C string handling"),
    Case("control_byte", "weights\x07.bin", ["OED004"], "medium",
         "control byte in a path, often a sign of smuggling"),
    Case("backslash", "subdir\\weights.bin", ["OED005"], "medium",
         "backslash separator traverses on Windows loaders"),
    Case("windows_drive", "C:\\Windows\\System32\\config\\sam", ["OED005"], "medium",
         "Windows drive-absolute path (a scanner may also flag it as absolute)"),
    Case("clean_control", "weights.bin", [], "none",
         "clean, spec-conformant relative in-directory path (control)"),
]


def build_corpus() -> Dict[str, bytes]:
    """Return {filename: onnx_bytes} for every case."""
    return {c.filename: build_model(c.location) for c in CASES}


def manifest() -> List[dict]:
    """Return a machine-readable description of the corpus (CC BY 4.0 metadata)."""
    out = []
    for c in CASES:
        out.append({
            "file": c.filename,
            "location": c.location,
            "malicious": c.malicious,
            "rules": c.rules,
            "severity": c.severity,
            "cwe": "CWE-22" if c.malicious else None,
            "note": c.note,
        })
    return out


def write_corpus(out_dir: str) -> List[str]:
    """Write every crafted .onnx file plus manifest.json to *out_dir*.

    Returns the list of file paths written (relative to *out_dir*)."""
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []
    for fname, data in build_corpus().items():
        path = os.path.join(out_dir, fname)
        with open(path, "wb") as fh:
            fh.write(data)
        written.append(fname)
    man_path = os.path.join(out_dir, "manifest.json")
    with open(man_path, "w", encoding="utf-8") as fh:
        json.dump({
            "tool": "onnx-external-data-corpus",
            "version": __version__,
            "cwe": "CWE-22",
            "references": [
                "CVE-2022-25882", "GHSA-ffxj-547x-5j7c",
                "CVE-2026-55832", "GHSA-h668-6x6g-f8r5",
            ],
            "note": "Header-only crafted ONNX files; no tensor payload, no exploit code. "
                    "Made with AI by MV2 of Munim, Inc.",
            "cases": manifest(),
        }, fh, indent=2)
    written.append("manifest.json")
    return written


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="onnx-external-data-corpus",
        description="Write a corpus of crafted header-only .onnx files that exercise "
                    "external_data path traversal (CWE-22), to regression-test ONNX "
                    "loaders and scanners. No exploit payload; stdlib only.",
    )
    p.add_argument("--out-dir", required=True, help="directory to write the corpus into")
    p.add_argument("--version", action="version",
                   version="onnx-external-data-corpus " + __version__)
    args = p.parse_args(argv)
    written = write_corpus(args.out_dir)
    malicious = sum(1 for c in CASES if c.malicious)
    print("Wrote {} files ({} malicious + {} clean control) + manifest.json to {}".format(
        len(CASES), malicious, len(CASES) - malicious, args.out_dir))
    for w in written:
        print("  ", w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
