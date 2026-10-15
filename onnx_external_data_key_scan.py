"""Static, no-execution scanner for unexpected keys in an ONNX tensor's
``external_data`` metadata -- the attribute-injection vector behind CVE-2026-34445.

Background
----------
An ``.onnx`` file is a protobuf message with no code of its own. A tensor whose
``data_location`` is ``EXTERNAL`` stores its weights in a separate file named by a
list of key/value string pairs in the tensor's ``external_data`` field. The ONNX
spec recognises only four keys -- ``location``, ``offset``, ``length`` and
``checksum`` -- and onnx >= 1.21.0 additionally keeps ``basepath`` for round-trips.

Before 1.21.0, ``onnx``'s ``ExternalDataInfo`` loaded those entries by calling
``setattr(self, key, value)`` for every key WITHOUT validating it against that set
(CVE-2026-34445 / GHSA-538c-55jv-c5g9, CWE-20 / CWE-400 / CWE-915, fixed in 1.21.0
by an allowlist ``_ALLOWED_EXTERNAL_DATA_KEYS = {location, offset, length,
checksum, basepath}``). A crafted model carrying an unexpected key -- a Python
dunder such as ``__class__`` or any attribute name -- could therefore overwrite
internal object state and crash a model-serving process at load time.

This scanner flags the precondition statically, before any loader runs: it parses
the protobuf wire format itself (no ``onnx`` dependency, standard library only),
walks every tensor including those nested in node attributes, subgraphs and sparse
initializers, and reports any ``external_data`` key that is not in the recognised
set (rule OEK001). It describes detection, not exploitation: it reads only the key
strings and never materialises, loads or executes anything. A clean scan does not
prove a file is safe.

Every public identifier referenced here is already public; nothing below is a
zero-day. Made with AI by MV2 of Munim, Inc. Licence: Apache-2.0.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass

__version__ = "0.1.0"

# onnx >= 1.21.0 `_ALLOWED_EXTERNAL_DATA_KEYS`. The ONNX IR spec documents the first
# four for TensorProto.external_data; "basepath" is onnx's internal round-trip key.
ALLOWED_KEYS = frozenset({"location", "offset", "length", "checksum", "basepath"})

# ONNX IR protobuf field numbers (onnx.proto, verified against v1.21.0).
_MODEL_GRAPH = 7
_GRAPH_NODE = 1
_GRAPH_INITIALIZER = 5
_GRAPH_SPARSE_INITIALIZER = 15
_NODE_ATTRIBUTE = 5
_ATTR_T = 5
_ATTR_G = 6
_ATTR_TENSORS = 10
_ATTR_GRAPHS = 11
_ATTR_SPARSE_TENSOR = 22
_ATTR_SPARSE_TENSORS = 23
_SPARSE_VALUES = 1
_SPARSE_INDICES = 2
_TENSOR_EXTERNAL_DATA = 13
_TENSOR_DATA_LOCATION = 14
_SSE_KEY = 1
_SSE_VALUE = 2

_MAX_DEPTH = 64  # guard against hostile deeply-nested subgraphs

SEVERITY = {"OEK000": "ERROR", "OEK001": "HIGH"}


class _WireError(Exception):
    """Raised when the protobuf byte stream is malformed."""


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    key: str
    value: str
    data_location: int
    message: str


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise _WireError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            raise _WireError("varint too long")


def _iter_fields(buf: bytes):
    """Yield (field_number, wire_type, value) for a protobuf message.

    value is an int for varint, else the raw bytes (length-delimited / fixed).
    """
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        field_no = tag >> 3
        wire = tag & 0x07
        if wire == 0:
            val, pos = _read_varint(buf, pos)
            yield field_no, wire, val
        elif wire == 1:
            if pos + 8 > n:
                raise _WireError("truncated 64-bit field")
            yield field_no, wire, buf[pos:pos + 8]
            pos += 8
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            if length < 0 or pos + length > n:
                raise _WireError("truncated length-delimited field")
            yield field_no, wire, buf[pos:pos + length]
            pos += length
        elif wire == 5:
            if pos + 4 > n:
                raise _WireError("truncated 32-bit field")
            yield field_no, wire, buf[pos:pos + 4]
            pos += 4
        else:
            raise _WireError("unsupported wire type %d" % wire)


def _parse_sse(buf: bytes) -> tuple[str | None, str | None]:
    key = value = None
    for fn, wt, val in _iter_fields(buf):
        if fn == _SSE_KEY and wt == 2:
            key = val.decode("utf-8", "replace")
        elif fn == _SSE_VALUE and wt == 2:
            value = val.decode("utf-8", "replace")
    return key, value


def _scan_tensor(buf: bytes, path: str, findings: list[Finding]) -> None:
    data_location = 0
    entries: list[bytes] = []
    for fn, wt, val in _iter_fields(buf):
        if fn == _TENSOR_DATA_LOCATION and wt == 0:
            data_location = val
        elif fn == _TENSOR_EXTERNAL_DATA and wt == 2:
            entries.append(val)
    for raw in entries:
        key, value = _parse_sse(raw)
        if key is None:
            continue
        if key not in ALLOWED_KEYS:
            dunder = key.startswith("__") and key.endswith("__")
            note = "attribute-injection" if dunder else "unrecognised"
            findings.append(Finding(
                rule="OEK001",
                severity=SEVERITY["OEK001"],
                path=path,
                key=key,
                value=(value or "")[:120],
                data_location=data_location,
                message=("external_data carries %s key %r (not in %s); "
                         "a loader that setattr()s it is the CVE-2026-34445 vector"
                         % (note, key, sorted(ALLOWED_KEYS))),
            ))


def _walk_sparse(buf: bytes, path: str, findings: list[Finding], depth: int) -> None:
    if depth > _MAX_DEPTH:
        return
    for fn, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if fn == _SPARSE_VALUES:
            _scan_tensor(val, path + ".values", findings)
        elif fn == _SPARSE_INDICES:
            _scan_tensor(val, path + ".indices", findings)


def _walk_attribute(buf: bytes, path: str, findings: list[Finding], depth: int) -> None:
    if depth > _MAX_DEPTH:
        return
    for fn, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if fn == _ATTR_T:
            _scan_tensor(val, path + ".t", findings)
        elif fn == _ATTR_TENSORS:
            _scan_tensor(val, path + ".tensors", findings)
        elif fn == _ATTR_G:
            _walk_graph(val, path + ".g", findings, depth + 1)
        elif fn == _ATTR_GRAPHS:
            _walk_graph(val, path + ".graphs", findings, depth + 1)
        elif fn in (_ATTR_SPARSE_TENSOR, _ATTR_SPARSE_TENSORS):
            _walk_sparse(val, path + ".sparse", findings, depth + 1)


def _walk_node(buf: bytes, path: str, findings: list[Finding], depth: int) -> None:
    if depth > _MAX_DEPTH:
        return
    for fn, wt, val in _iter_fields(buf):
        if wt == 2 and fn == _NODE_ATTRIBUTE:
            _walk_attribute(val, path + ".attr", findings, depth + 1)


def _walk_graph(buf: bytes, path: str, findings: list[Finding], depth: int) -> None:
    if depth > _MAX_DEPTH:
        return
    for fn, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if fn == _GRAPH_INITIALIZER:
            _scan_tensor(val, path + ".initializer", findings)
        elif fn == _GRAPH_SPARSE_INITIALIZER:
            _walk_sparse(val, path + ".sparse_initializer", findings, depth + 1)
        elif fn == _GRAPH_NODE:
            _walk_node(val, path + ".node", findings, depth + 1)


def scan_bytes(data: bytes, source: str = "<bytes>") -> list[Finding]:
    """Return findings for one serialised ModelProto."""
    findings: list[Finding] = []
    try:
        for fn, wt, val in _iter_fields(data):
            if wt == 2 and fn == _MODEL_GRAPH:
                _walk_graph(val, source + ":graph", findings, depth=0)
    except _WireError as exc:
        findings.append(Finding(
            rule="OEK000", severity=SEVERITY["OEK000"], path=source, key="",
            value="", data_location=0,
            message="could not parse as ONNX protobuf: %s" % exc,
        ))
    return findings


def scan_file(path: str) -> list[Finding]:
    with open(path, "rb") as fh:
        return scan_bytes(fh.read(), source=path)


def _iter_onnx_files(target: str):
    if os.path.isdir(target):
        for root, _dirs, names in os.walk(target):
            for name in sorted(names):
                if name.lower().endswith(".onnx"):
                    yield os.path.join(root, name)
    else:
        yield target


_LEVELS = {"ERROR": 3, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="onnx-external-data-key-scan",
        description="Flag unexpected external_data keys in ONNX files "
                    "(CVE-2026-34445 attribute-injection precondition).")
    ap.add_argument("target", help="an .onnx file or a directory to walk")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=["INFO", "LOW", "MEDIUM", "HIGH", "ERROR"],
                    help="exit non-zero if a finding at or above this level is seen")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--version", action="version",
                    version="onnx-external-data-key-scan %s" % __version__)
    args = ap.parse_args(argv)

    all_findings: list[Finding] = []
    for path in _iter_onnx_files(args.target):
        try:
            all_findings.extend(scan_file(path))
        except OSError as exc:
            all_findings.append(Finding(
                rule="OEK000", severity="ERROR", path=path, key="", value="",
                data_location=0, message="could not read file: %s" % exc))

    if args.json:
        print(json.dumps([asdict(f) for f in all_findings], indent=2))
    else:
        if not all_findings:
            print("onnx-external-data-key-scan: no findings")
        for f in all_findings:
            print("%s %s %s key=%r %s" % (f.severity, f.rule, f.path, f.key, f.message))

    threshold = _LEVELS[args.fail_on]
    worst = max((_LEVELS.get(f.severity, 0) for f in all_findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
