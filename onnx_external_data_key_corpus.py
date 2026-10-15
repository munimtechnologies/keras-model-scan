#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""onnx_external_data_key_corpus.py - benign crafted-file corpus for CVE-2026-34445.

Made with AI by MV2 of Munim, Inc. License: Apache-2.0.

This module emits a small set of HEADER-ONLY ``.onnx`` files that each carry an
*unexpected* ``external_data`` key - the exact attribute-injection vector of
CVE-2026-34445 (GHSA-538c-55jv-c5g9; onnx < 1.21.0; CWE-20 / CWE-400 / CWE-915).

Background, stated honestly - everything here is already public:
  An ``.onnx`` file is a protobuf with no code of its own. A tensor marked
  EXTERNAL names its weights through a repeated list of key/value string pairs
  (``StringStringEntryProto``) in the tensor's ``external_data`` field. The ONNX
  IR spec recognises only four keys - ``location``, ``offset``, ``length``,
  ``checksum`` - and onnx >= 1.21.0 also keeps its internal round-trip key
  ``basepath``. Before 1.21.0, ``ExternalDataInfo.__init__`` called
  ``setattr(self, key, value)`` for EVERY entry without validating the key, so a
  crafted model carrying an unexpected key (a Python dunder such as ``__class__``,
  or any attribute name at all) could overwrite internal object state and crash a
  model-serving process at load time. onnx 1.21.0 fixed it by allow-listing the
  recognised keys.

Each file produced here holds NO tensor payload and NO exploit code - only a
protobuf header whose tensor carries one or more unexpected ``external_data``
keys. They are a reproducible regression corpus: run any static key checker (or
MV2's ``onnx_external_data_key_scan.py``, which flags unexpected keys as
``OEK001`` HIGH) over the written directory and every malicious file should flag
while the clean control passes.

This corpus describes DETECTION, not exploitation. A clean scan proves nothing;
the real fix is upgrading onnx to >= 1.21.0.

Usage:
    python onnx_external_data_key_corpus.py --out-dir ./corpus_keys
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

__version__ = "0.1.0"

# The keys recognised by the ONNX IR spec plus onnx's internal round-trip key.
# Any external_data key OUTSIDE this set is the CVE-2026-34445 vector.
ALLOWED_KEYS = frozenset({"location", "offset", "length", "checksum", "basepath"})

# --- protobuf field numbers (ONNX IR, verified against onnx 1.21.0) -----------
_F_MODEL_IR_VERSION = 1      # ModelProto.ir_version (int64)
_F_MODEL_GRAPH = 7           # ModelProto.graph (GraphProto)
_F_MODEL_OPSET = 8           # ModelProto.opset_import (repeated OperatorSetIdProto)

_F_GRAPH_NODE = 1           # GraphProto.node (repeated NodeProto)
_F_GRAPH_NAME = 2           # GraphProto.name (string)
_F_GRAPH_INITIALIZER = 5    # GraphProto.initializer (repeated TensorProto)

_F_NODE_OP_TYPE = 4         # NodeProto.op_type (string)
_F_NODE_ATTRIBUTE = 5       # NodeProto.attribute (repeated AttributeProto)

_F_ATTR_NAME = 1            # AttributeProto.name (string)
_F_ATTR_T = 5              # AttributeProto.t (TensorProto)
_F_ATTR_TYPE = 20          # AttributeProto.type (enum)
_ATTR_TYPE_TENSOR = 4      # AttributeProto.AttributeType.TENSOR

_F_TENSOR_DIMS = 1         # TensorProto.dims (repeated int64)
_F_TENSOR_DATA_TYPE = 2    # TensorProto.data_type (int32)
_F_TENSOR_NAME = 8         # TensorProto.name (string)
_F_TENSOR_EXTERNAL_DATA = 13   # TensorProto.external_data (repeated SSE)
_F_TENSOR_DATA_LOCATION = 14   # TensorProto.data_location (enum)

_F_SSE_KEY = 1             # StringStringEntryProto.key (string)
_F_SSE_VALUE = 2           # StringStringEntryProto.value (string)

_F_OPSET_DOMAIN = 1        # OperatorSetIdProto.domain (string)
_F_OPSET_VERSION = 2       # OperatorSetIdProto.version (int64)

_DATA_LOCATION_EXTERNAL = 1  # TensorProto.DataLocation.EXTERNAL
_TENSOR_FLOAT = 1            # TensorProto.DataType.FLOAT
_IR_VERSION = 8

_WIRE_VARINT = 0
_WIRE_LEN = 2


# --- wire-format encoders -----------------------------------------------------
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
    return _tag(field_no, _WIRE_VARINT) + _varint(value)


def _f_bytes(field_no: int, payload: bytes) -> bytes:
    return _tag(field_no, _WIRE_LEN) + _varint(len(payload)) + payload


def _f_string(field_no: int, s: str) -> bytes:
    return _f_bytes(field_no, s.encode("utf-8"))


# --- message builders ---------------------------------------------------------
def _string_string_entry(key: str, value: str) -> bytes:
    return _f_string(_F_SSE_KEY, key) + _f_string(_F_SSE_VALUE, value)


def _external_tensor(name: str, entries: List[Tuple[str, str]],
                     dims: Tuple[int, ...] = (2, 3)) -> bytes:
    """A TensorProto marked EXTERNAL whose external_data holds `entries`."""
    body = b""
    for d in dims:
        body += _f_varint(_F_TENSOR_DIMS, d)
    body += _f_varint(_F_TENSOR_DATA_TYPE, _TENSOR_FLOAT)
    body += _f_string(_F_TENSOR_NAME, name)
    for key, value in entries:
        body += _f_bytes(_F_TENSOR_EXTERNAL_DATA, _string_string_entry(key, value))
    body += _f_varint(_F_TENSOR_DATA_LOCATION, _DATA_LOCATION_EXTERNAL)
    return body


def _node_with_tensor_attr(tensor: bytes, attr_name: str = "value") -> bytes:
    """A Constant NodeProto carrying `tensor` in a TENSOR-typed attribute.

    Used to place a crafted tensor one level deeper than the graph's
    initializer list, exercising a scanner's node/attribute recursion.
    """
    attr = _f_string(_F_ATTR_NAME, attr_name)
    attr += _f_varint(_F_ATTR_TYPE, _ATTR_TYPE_TENSOR)
    attr += _f_bytes(_F_ATTR_T, tensor)
    node = _f_string(_F_NODE_OP_TYPE, "Constant")
    node += _f_bytes(_F_NODE_ATTRIBUTE, attr)
    return node


def _opset(domain: str = "", version: int = 14) -> bytes:
    return _f_string(_F_OPSET_DOMAIN, domain) + _f_varint(_F_OPSET_VERSION, version)


def _graph(initializers: List[bytes], nodes: List[bytes],
           name: str = "key_corpus_graph") -> bytes:
    body = b""
    for n in nodes:
        body += _f_bytes(_F_GRAPH_NODE, n)
    body += _f_string(_F_GRAPH_NAME, name)
    for t in initializers:
        body += _f_bytes(_F_GRAPH_INITIALIZER, t)
    return body


def build_model(entries: List[Tuple[str, str]], placement: str = "initializer",
                tensor_name: str = "weight") -> bytes:
    """Assemble a header-only ModelProto whose one external tensor carries
    `entries`. `placement` is 'initializer' (graph.initializer) or
    'node_attr' (graph.node -> Constant -> attribute.t)."""
    tensor = _external_tensor(tensor_name, entries)
    if placement == "node_attr":
        graph = _graph(initializers=[], nodes=[_node_with_tensor_attr(tensor)])
    elif placement == "initializer":
        graph = _graph(initializers=[tensor], nodes=[])
    else:  # pragma: no cover - guarded by Case definitions
        raise ValueError(f"unknown placement: {placement!r}")
    model = _f_varint(_F_MODEL_IR_VERSION, _IR_VERSION)
    model += _f_bytes(_F_MODEL_OPSET, _opset())
    model += _f_bytes(_F_MODEL_GRAPH, graph)
    return model


# --- the corpus ---------------------------------------------------------------
@dataclass
class Case:
    name: str
    entries: List[Tuple[str, str]]
    note: str
    placement: str = "initializer"
    rules: List[str] = field(default_factory=list)
    severity: str = "HIGH"

    @property
    def filename(self) -> str:
        return f"{self.name}.onnx"

    @property
    def malicious(self) -> bool:
        return bool(self.rules)

    @property
    def unexpected_keys(self) -> List[str]:
        return [k for k, _ in self.entries if k not in ALLOWED_KEYS]


_LEGIT = ("location", "weights.bin")  # a recognised entry present in most cases

CASES: List[Case] = [
    Case("dunder_class", [_LEGIT, ("__class__", "os.system")], rules=["OEK001"],
         note="Classic attribute injection: the Python dunder __class__ as an "
              "external_data key, the archetype the unvalidated setattr abuses."),
    Case("dunder_dict", [_LEGIT, ("__dict__", "x")], rules=["OEK001"],
         note="__dict__ key - overwriting an object's attribute namespace."),
    Case("dunder_reduce", [_LEGIT, ("__reduce__", "y")], rules=["OEK001"],
         note="__reduce__ key - a dunder associated with deserialization hooks."),
    Case("arbitrary_attr", [_LEGIT, ("payload", "z")], rules=["OEK001"],
         note="An ordinary unrecognised attribute name; not a dunder but still "
              "outside the allow-list, so still the CVE-2026-34445 vector."),
    Case("case_variant", [("Location", "weights.bin")], rules=["OEK001"],
         note="'Location' (capital L) is NOT 'location'; the allow-list is "
              "case-sensitive, so a case-variant key is unrecognised."),
    Case("whitespace_key", [(" location", "weights.bin")], rules=["OEK001"],
         note="A leading space makes ' location' a distinct, unrecognised key."),
    Case("empty_key", [("", "weights.bin")], rules=["OEK001"],
         note="An empty-string key - unrecognised and a likely parser edge case."),
    Case("nested_node_attr", [_LEGIT, ("__class__", "os.system")], rules=["OEK001"],
         placement="node_attr",
         note="Same __class__ injection, but the tensor is nested inside a "
              "Constant node's TENSOR attribute - checks walker recursion."),
    Case("clean_control", [("location", "weights.bin"), ("offset", "0"),
                           ("length", "1024")], rules=[], severity="NONE",
         note="Control: only recognised keys (location, offset, length). A "
              "correct detector must NOT flag this file."),
]


def build_corpus() -> Dict[str, bytes]:
    return {c.filename: build_model(c.entries, c.placement) for c in CASES}


def manifest() -> List[dict]:
    return [
        {
            "file": c.filename,
            "malicious": c.malicious,
            "placement": c.placement,
            "keys": [k for k, _ in c.entries],
            "unexpected_keys": c.unexpected_keys,
            "rules": c.rules,
            "severity": c.severity,
            "note": c.note,
        }
        for c in CASES
    ]


def write_corpus(out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []
    for fn, data in build_corpus().items():
        path = os.path.join(out_dir, fn)
        with open(path, "wb") as fh:
            fh.write(data)
        written.append(fn)
    meta = {
        "tool": "onnx_external_data_key_corpus.py",
        "version": __version__,
        "made_with": "AI, by MV2 of Munim, Inc.",
        "license": "Apache-2.0",
        "cve": "CVE-2026-34445",
        "ghsa": "GHSA-538c-55jv-c5g9",
        "cwe": ["CWE-20", "CWE-400", "CWE-915"],
        "allowed_keys": sorted(ALLOWED_KEYS),
        "detector": "onnx_external_data_key_scan.py (OEK001)",
        "cases": manifest(),
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
    written.append("manifest.json")
    return written


# --- verification helper (used by the test; no scanner dependency) ------------
def _read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _iter_fields(buf: bytes):
    """Yield (field_no, wire_type, value) for a protobuf message.
    For wire type 2 `value` is bytes; for 0 it is an int; others are skipped
    with value None (none appear in this corpus)."""
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        field_no = tag >> 3
        wire = tag & 0x07
        if wire == _WIRE_VARINT:
            val, pos = _read_varint(buf, pos)
            yield field_no, wire, val
        elif wire == _WIRE_LEN:
            ln, pos = _read_varint(buf, pos)
            val = buf[pos:pos + ln]
            if len(val) != ln:
                raise ValueError("truncated length-delimited field")
            pos += ln
            yield field_no, wire, val
        elif wire == 1:
            pos += 8
            yield field_no, wire, None
        elif wire == 5:
            pos += 4
            yield field_no, wire, None
        else:
            raise ValueError(f"unsupported wire type {wire}")


def _scan_tensor(buf: bytes, path: str, out: List[dict]) -> None:
    for fno, wire, val in _iter_fields(buf):
        if fno == _F_TENSOR_EXTERNAL_DATA and wire == _WIRE_LEN:
            key = value = None
            for sf, sw, sv in _iter_fields(val):
                if sf == _F_SSE_KEY and sw == _WIRE_LEN:
                    key = sv.decode("utf-8", "replace")
                elif sf == _F_SSE_VALUE and sw == _WIRE_LEN:
                    value = sv.decode("utf-8", "replace")
            if key is not None:
                out.append({"path": path, "key": key, "value": value})


def _scan_node(buf: bytes, path: str, out: List[dict]) -> None:
    idx = 0
    for fno, wire, val in _iter_fields(buf):
        if fno == _F_NODE_ATTRIBUTE and wire == _WIRE_LEN:
            for af, aw, av in _iter_fields(val):
                if af == _F_ATTR_T and aw == _WIRE_LEN:
                    _scan_tensor(av, f"{path}/attr[{idx}].t", out)
            idx += 1


def _scan_graph(buf: bytes, path: str, out: List[dict]) -> None:
    init_idx = 0
    node_idx = 0
    for fno, wire, val in _iter_fields(buf):
        if fno == _F_GRAPH_INITIALIZER and wire == _WIRE_LEN:
            _scan_tensor(val, f"{path}/initializer[{init_idx}]", out)
            init_idx += 1
        elif fno == _F_GRAPH_NODE and wire == _WIRE_LEN:
            _scan_node(val, f"{path}/node[{node_idx}]", out)
            node_idx += 1


def parse_external_data_keys(data: bytes) -> List[dict]:
    """Return every external_data (key, value) entry in a model, with a path.
    Walks ModelProto.graph -> initializers and nodes -> node attribute tensors.
    This is a verification aid, independent of any scanner module."""
    out: List[dict] = []
    for fno, wire, val in _iter_fields(data):
        if fno == _F_MODEL_GRAPH and wire == _WIRE_LEN:
            _scan_graph(val, "graph", out)
    return out


# --- CLI ----------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Write the CVE-2026-34445 unexpected-external_data-key "
                    "corpus (benign, header-only .onnx files).")
    parser.add_argument("--out-dir", required=True,
                        help="directory to write the .onnx files and manifest")
    parser.add_argument("--version", action="version",
                        version=f"onnx_external_data_key_corpus {__version__}")
    args = parser.parse_args(argv)
    written = write_corpus(args.out_dir)
    mal = sum(1 for c in CASES if c.malicious)
    clean = len(CASES) - mal
    print(f"Wrote {len(written)} files to {args.out_dir} "
          f"({mal} malicious, {clean} clean control) for CVE-2026-34445.")
    for fn in written:
        print(f"  {fn}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
