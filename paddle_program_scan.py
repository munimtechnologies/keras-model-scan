#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""paddle_program_scan - static scanner for PaddlePaddle program files.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

A PaddlePaddle inference model is a program plus a weights file. The program
is either a legacy ``.pdmodel`` (a ``paddle.framework.proto.ProgramDesc``
protobuf: blocks of ``OpDesc`` with typed attributes) or, from Paddle 3, a PIR
``.json`` program (regions, blocks and ``ops``; each op names itself under
``"#"`` and lists attributes under ``"A"`` as ``{"N": name, "AT": {...,
"D": value}}``). When the program runs, every op in it runs, and a few
operators touch the file system by a path stored in the op's own attributes:

- ``save`` and ``save_combine`` write tensors to ``file_path``
  (paddle/fluid/operators/save_op.cc, save_combine_op.cc).
- ``load``, ``load_combine`` read tensors from ``file_path``, and
  ``read_file`` reads raw bytes from ``filename`` (phi ops.yaml).
- ``py_func`` calls a Python function registered in the loading process,
  chosen by the integer ``forward_callable_id`` (py_func_op.cc).

A program exported for inference does not need any of these, so a CI gate
should see them. This module decodes both formats with the Python standard
library (no paddle, no protobuf package) and reports:

- PDL001 high   CWE-73   An op that writes a file (save, save_combine), with
                         the path it names.
- PDL002 high   CWE-73   An op that reads a file (load, load_combine,
                         read_file), with the path it names.
- PDL003 medium CWE-829  A py_func op (runs an in-process Python callable).
- PDL004 medium CWE-693  Not a parseable ProgramDesc or PIR program, nesting
                         too deep, or findings capped.

Every block is checked, so ops inside control-flow sub-blocks are found too.
Static review only: nothing is loaded or executed.
"""

import json
import os
import sys

__version__ = "0.1.0"

MAX_FINDINGS = 1000
MAX_DEPTH = 64
MAX_FIELDS = 1000000

_RULES = {
    "PDL001": ("high", "CWE-73"),
    "PDL002": ("high", "CWE-73"),
    "PDL003": ("medium", "CWE-829"),
    "PDL004": ("medium", "CWE-693"),
}

# Op type -> (rule, attribute that names the file).
_FILE_OPS = {
    "save": ("PDL001", "file_path"),
    "save_combine": ("PDL001", "file_path"),
    "load": ("PDL002", "file_path"),
    "load_combine": ("PDL002", "file_path"),
    "read_file": ("PDL002", "filename"),
}
_PY_FUNC = "py_func"
_PY_FUNC_ID = "forward_callable_id"

# ProgramDesc fields: blocks = 1, version = 4, op_version_map = 5 (2, 3 reserved).
_PROGRAM_FIELDS = ((1, 2), (4, 2), (5, 2))


class _Bad(Exception):
    pass


def _ascii(value, limit=300):
    text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit] + "..."


class _Findings(object):
    def __init__(self):
        self.items = []
        self._seen = {}
        self.capped = False

    def add(self, rule, message, evidence, key=None):
        if key is not None and key in self._seen:
            self._seen[key][1] += 1
            return
        if len(self.items) >= MAX_FINDINGS:
            self.capped = True
            return
        severity, cwe = _RULES[rule]
        item = {"rule": rule, "severity": severity, "cve": "", "cwe": cwe,
                "message": _ascii(message), "evidence": _ascii(evidence)}
        self.items.append(item)
        if key is not None:
            self._seen[key] = [item, 1]

    def result(self):
        for item, count in self._seen.values():
            if count > 1:
                item["evidence"] += "; %d in total" % count
        if self.capped:
            severity, cwe = _RULES["PDL004"]
            self.items.append({
                "rule": "PDL004", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


# -- protobuf wire format -----------------------------------------------------

def _varint(buf, pos, end):
    result = 0
    shift = 0
    while True:
        if pos >= end:
            raise _Bad("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise _Bad("varint too long")


def _fields(buf):
    """Decode one message into (field, wire, value) tuples. Length-delimited
    values are memoryview slices; fixed-width values are skipped as None."""
    pos = 0
    end = len(buf)
    out = []
    while pos < end:
        key, pos = _varint(buf, pos, end)
        field, wire = key >> 3, key & 7
        if field == 0:
            raise _Bad("field number 0")
        if wire == 0:
            value, pos = _varint(buf, pos, end)
        elif wire == 1:
            if end - pos < 8:
                raise _Bad("truncated fixed64")
            value, pos = None, pos + 8
        elif wire == 2:
            length, pos = _varint(buf, pos, end)
            if length > end - pos:
                raise _Bad("length-delimited field runs past the end")
            value, pos = buf[pos:pos + length], pos + length
        elif wire == 5:
            if end - pos < 4:
                raise _Bad("truncated fixed32")
            value, pos = None, pos + 4
        else:
            raise _Bad("unsupported wire type %d" % wire)
        out.append((field, wire, value))
        if len(out) > MAX_FIELDS:
            raise _Bad("more than %d fields in one message" % MAX_FIELDS)
    return out


def _string(view):
    return bytes(view).decode("utf-8", "replace")


# -- ops ----------------------------------------------------------------------

def _check_op(op_type, attrs, where, out):
    """attrs maps attribute name -> list of its string/int values."""
    base = op_type.rsplit(".", 1)[-1]
    if base in _FILE_OPS:
        rule, attr = _FILE_OPS[base]
        values = attrs.get(attr) or []
        path = values[0] if values else "(none)"
        verb = "writes" if rule == "PDL001" else "reads"
        out.add(rule, "a %s op %s a file when the program runs" % (base, verb),
                "%s: op %s, %s %s" % (where, _ascii(op_type, 80), attr,
                                      _ascii(path, 200)),
                key=(rule, base, path))
    elif base == _PY_FUNC:
        values = attrs.get(_PY_FUNC_ID) or ["0"]
        out.add("PDL003", "a py_func op calls a Python function registered "
                "in the loading process; an exported model should not need one",
                "%s: op %s, %s %s" % (where, _ascii(op_type, 80), _PY_FUNC_ID,
                                      _ascii(values[0], 20)),
                key=("PDL003", values[0]))


def _proto_attr(view):
    # OpDesc.Attr: name = 1, i = 3, s = 5, strings = 8, var_name = 17,
    # vars_name = 18.
    name = ""
    values = []
    for field, wire, value in _fields(view):
        if field == 1 and wire == 2:
            name = _string(value)
        elif field in (5, 8, 17, 18) and wire == 2:
            values.append(_string(value))
        elif field == 3 and wire == 0:
            values.append(str(value))
    return name, values


def _proto_op(view, where, out):
    # OpDesc: inputs = 1, outputs = 2, type = 3, attrs = 4.
    op_type = ""
    attrs = {}
    for field, wire, value in _fields(view):
        if field == 3 and wire == 2:
            op_type = _string(value)
        elif field == 4 and wire == 2:
            name, values = _proto_attr(value)
            attrs[name] = values
    _check_op(op_type, attrs, where, out)


def _scan_proto(data, where, out):
    view = memoryview(data)
    try:
        fields = _fields(view)
    except _Bad as exc:
        out.add("PDL004", "not a parseable PaddlePaddle ProgramDesc",
                _ascii(exc))
        return
    blocks = [value for field, wire, value in fields if (field, wire) == (1, 2)]
    if not blocks or any((field, wire) not in _PROGRAM_FIELDS
                         for field, wire, value in fields):
        out.add("PDL004", "not a PaddlePaddle ProgramDesc (no blocks, or "
                "fields a ProgramDesc does not have)", _ascii(where, 200))
        return
    for index, block in enumerate(blocks):
        # BlockDesc: ops = 4.
        for field, wire, value in _fields(block):
            if field == 4 and wire == 2:
                _proto_op(value, "%s block %d" % (where, index), out)


# -- PIR JSON -----------------------------------------------------------------

def _too_deep(where, out):
    out.add("PDL004", "nesting is deeper than %d levels; deeper parts were "
            "not checked" % MAX_DEPTH, where, key=("PDL004", "depth"))


def _json_values(attr_value):
    data = attr_value.get("D") if isinstance(attr_value, dict) else None
    items = data if isinstance(data, list) else [data]
    return [str(v) for v in items
            if isinstance(v, (str, int)) and not isinstance(v, bool)]


def _json_op(op, where, out):
    name = op.get("#")
    if not isinstance(name, str):
        return
    attrs = {}
    for attr in op.get("A") or []:
        if isinstance(attr, dict) and isinstance(attr.get("N"), str):
            attrs[attr["N"]] = _json_values(attr.get("AT"))
    _check_op(name, attrs, where, out)


def _walk_json(node, depth, where, out, state):
    if depth > MAX_DEPTH:
        _too_deep(where, out)
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "ops" and isinstance(value, list):
                state[0] += 1
                for op in value:
                    if isinstance(op, dict):
                        _json_op(op, where, out)
            _walk_json(value, depth + 1, where, out, state)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, depth + 1, where, out, state)


def _scan_json(data, where, out):
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        out.add("PDL004", "not valid JSON", _ascii(exc))
        return
    state = [0]
    _walk_json(doc, 0, where + " (PIR)", out, state)
    if not state[0]:
        out.add("PDL004", "JSON without any ops list; not a PaddlePaddle PIR "
                "program", _ascii(where, 200))


# -- entry points -------------------------------------------------------------

def _scan_blob(data, where, out):
    if bytes(data[:64]).lstrip().startswith(b"{"):
        _scan_json(data, where, out)
    else:
        _scan_proto(data, where, out)


def _guard(out, func, *args):
    """Run func(*args, out), turning a parser crash into a PDL004 finding."""
    try:
        func(*args, out)
    except OSError:
        raise
    except Exception as exc:  # hostile input must never crash the scan
        out.add("PDL004", "the program could not be parsed; findings before "
                "this point are kept",
                "%s: %s" % (type(exc).__name__, _ascii(exc)))


def scan_bytes(data, name=""):
    """Scan an in-memory .pdmodel or PIR .json program. Returns findings."""
    out = _Findings()
    _guard(out, _scan_blob, data, name or "model")
    return out.result()


def scan_file(path):
    """Scan a .pdmodel or PIR .json program file."""
    with open(path, "rb") as handle:
        data = handle.read()
    out = _Findings()
    _guard(out, _scan_blob, data, os.path.basename(path))
    return out.result()


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python paddle_program_scan.py MODEL.pdmodel|MODEL.json "
              "[...]", file=sys.stderr)
        return 2
    failed = high = False
    for path in args:
        try:
            findings = scan_file(path)
        except OSError as exc:
            print("%s: cannot read: %s" % (path, exc), file=sys.stderr)
            failed = True
            continue
        if not findings:
            print("%s: no findings" % path)
        for item in findings:
            print("%s: %s %s: %s [%s]" % (path, item["rule"], item["severity"],
                                          item["message"], item["evidence"]))
            high = high or item["severity"] == "high"
    if failed:
        return 2
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
