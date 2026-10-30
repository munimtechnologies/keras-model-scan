# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for tflite_model_scan.py.

TFLite FlatBuffers, FlexBuffers and NodeDef bytes are built by hand from the
published schemas (schema.fbs, flexbuffers.h, node_def.proto). Nothing is
loaded or executed.
"""

import contextlib
import io
import os
import shutil
import struct
import tempfile
import unittest

import tflite_model_scan as tms

_SCALARS = {"i8": "<b", "i32": "<i", "u32": "<I", "u64": "<Q"}
_KEYS = {"rule", "severity", "cve", "cwe", "message", "evidence"}


class _Builder(object):
    """Lays a FlatBuffer out front to back; every uoffset points forward."""

    def __init__(self):
        self.buf = bytearray()
        self.pending = []

    def _pad(self, n):
        while len(self.buf) % n:
            self.buf.append(0)

    def build(self, root):
        self.buf += b"\0\0\0\0" + tms.FILE_IDENTIFIER
        self.pending.append((0, root))
        while self.pending:
            pos, obj = self.pending.pop(0)
            target = self._place(obj)
            struct.pack_into("<I", self.buf, pos, target - pos)
        return bytes(self.buf)

    def _place(self, obj):
        kind, value = obj
        self._pad(4)
        start = len(self.buf)
        if kind == "table":
            return self._place_table(value)
        if kind == "str":
            self.buf += struct.pack("<I", len(value)) + value + b"\0"
        elif kind == "bytes":
            self.buf += struct.pack("<I", len(value)) + value
        elif kind == "ints":
            self.buf += struct.pack("<I%di" % len(value), len(value), *value)
        elif kind == "tables":
            self.buf += struct.pack("<I", len(value))
            for child in value:
                self.pending.append((len(self.buf), child))
                self.buf += b"\0\0\0\0"
        else:
            raise ValueError(kind)
        return start

    def _place_table(self, fields):
        slots = max(fields) + 1 if fields else 0
        body = bytearray()
        offsets = {}
        children = []
        for slot in sorted(fields):
            kind, value = fields[slot]
            offsets[slot] = 4 + len(body)
            if kind in _SCALARS:
                body += struct.pack(_SCALARS[kind], value)
            else:
                children.append((offsets[slot], (kind, value)))
                body += b"\0\0\0\0"
        vtable = len(self.buf)
        self.buf += struct.pack("<HH", 4 + 2 * slots, 4 + len(body))
        for slot in range(slots):
            self.buf += struct.pack("<H", offsets.get(slot, 0))
        self._pad(4)
        table = len(self.buf)
        self.buf += struct.pack("<i", table - vtable) + body
        for offset, child in children:
            self.pending.append((table + offset, child))
        return table


def _opcode(builtin=0, custom=None, deprecated=None):
    fields = {3: ("i32", builtin)}
    if deprecated is not None:
        fields[0] = ("i8", deprecated)
    if custom is not None:
        fields[1] = ("str", custom)
    return ("table", fields)


def _operator(opcode=0, inputs=(0,), outputs=(1,), options=None, extra=None):
    fields = {0: ("u32", opcode), 1: ("ints", list(inputs)),
              2: ("ints", list(outputs))}
    if options is not None:
        fields[5] = ("bytes", options)
    if extra:
        fields.update(extra)
    return ("table", fields)


def _tensor(shape=(1, 4), buffer=0):
    return ("table", {0: ("ints", list(shape)), 2: ("u32", buffer)})


def _model(codes, operators, tensors=None, buffers=None):
    tensors = [_tensor(), _tensor()] if tensors is None else tensors
    buffers = [("table", {})] if buffers is None else buffers
    subgraph = ("table", {0: ("tables", tensors), 1: ("ints", [0]),
                          2: ("ints", [1]), 3: ("tables", operators)})
    root = ("table", {0: ("u32", 3), 1: ("tables", codes),
                      2: ("tables", [subgraph]), 4: ("tables", buffers)})
    return _Builder().build(root)


def _nodedef(op, name=b"node"):
    return b"\x0a" + bytes([len(name)]) + name + b"\x12" + bytes([len(op)]) + op


def _flex_options(first, second):
    """FlexBuffer root vector [first, second] of two strings, byte width 1."""
    buf = bytearray()
    starts = []
    for text in (first, second):
        buf.append(len(text))
        starts.append(len(buf))
        buf += text + b"\0"
    buf.append(2)
    vector = len(buf)
    buf.append(vector - starts[0])
    buf.append(vector + 1 - starts[1])
    buf += bytes([tms._FBT_STRING << 2, tms._FBT_STRING << 2])
    root = len(buf)
    buf += bytes([root - vector, tms._FBT_VECTOR << 2, 1])
    assert len(buf) < 256
    return bytes(buf)


def _flex_model(code, name, op, count=1):
    options = _flex_options(name, _nodedef(op))
    return _model([_opcode(32, code)],
                  [_operator(options=options) for _ in range(count)])


def _rules(findings):
    return sorted(f["rule"] for f in findings)


class TFLiteModelScanTests(unittest.TestCase):

    def test_builtin_only_model_is_clean(self):
        self.assertEqual(tms.scan_bytes(_model([_opcode(0)], [_operator()])), [])

    def test_optional_tensor_index_is_allowed(self):
        data = _model([_opcode(0)], [_operator(inputs=(0, -1))])
        self.assertEqual(tms.scan_bytes(data), [])

    def test_flex_file_read_is_high(self):
        findings = tms.scan_bytes(_flex_model(b"FlexReadFile", b"ReadFile",
                                              b"ReadFile"))
        self.assertEqual(_rules(findings), ["TFL001"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["cve"], "")
        self.assertEqual(findings[0]["cwe"], "CWE-829")
        self.assertIn("ReadFile", findings[0]["message"])
        self.assertIn("subgraph 0 operator 0", findings[0]["evidence"])

    def test_flex_python_callback_is_high(self):
        findings = tms.scan_bytes(_flex_model(b"FlexEagerPyFunc", b"EagerPyFunc",
                                              b"EagerPyFunc"))
        self.assertEqual(_rules(findings), ["TFL001"])
        self.assertIn("Python", findings[0]["message"])

    def test_flex_plain_op_is_medium(self):
        findings = tms.scan_bytes(_flex_model(b"FlexAbs", b"Abs", b"Abs"))
        self.assertEqual(_rules(findings), ["TFL003"])
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("Abs", findings[0]["message"])

    def test_relabelled_flex_op_is_caught(self):
        findings = tms.scan_bytes(_flex_model(b"FlexAbs", b"WriteFile",
                                              b"WriteFile"))
        self.assertEqual(_rules(findings), ["TFL001", "TFL002"])
        mismatch = [f for f in findings if f["rule"] == "TFL002"][0]
        self.assertEqual(mismatch["severity"], "high")
        self.assertIn("custom_code FlexAbs", mismatch["evidence"])
        self.assertIn("NodeDef op WriteFile", mismatch["evidence"])

    def test_nodedef_alone_disagrees(self):
        findings = tms.scan_bytes(_flex_model(b"FlexAbs", b"Abs", b"WriteFile"))
        self.assertEqual(_rules(findings), ["TFL001", "TFL002"])

    def test_benign_mismatch_reports_only_the_mismatch(self):
        findings = tms.scan_bytes(_flex_model(b"FlexAbs", b"Abs", b"Neg"))
        self.assertEqual(_rules(findings), ["TFL002"])

    def test_deprecated_builtin_code_marks_custom(self):
        options = _flex_options(b"ReadFile", _nodedef(b"ReadFile"))
        data = _model([_opcode(0, b"FlexReadFile", deprecated=32)],
                      [_operator(options=options)])
        self.assertEqual(_rules(tms.scan_bytes(data)), ["TFL001"])

    def test_non_flex_custom_op_is_medium(self):
        findings = tms.scan_bytes(_model([_opcode(32, b"MyOp")], [_operator()]))
        self.assertEqual(_rules(findings), ["TFL003"])
        self.assertIn("MyOp", findings[0]["message"])

    def test_repeated_op_is_listed_once(self):
        findings = tms.scan_bytes(_flex_model(b"FlexAbs", b"Abs", b"Abs",
                                              count=2))
        self.assertEqual(_rules(findings), ["TFL003"])
        self.assertIn("2 operators in total", findings[0]["evidence"])

    def test_short_options_are_malformed(self):
        data = _model([_opcode(32, b"FlexAbs")], [_operator(options=b"\x01\x02")])
        self.assertEqual(_rules(tms.scan_bytes(data)), ["TFL005"])

    def test_bad_root_width_is_malformed(self):
        data = _model([_opcode(32, b"FlexAbs")],
                      [_operator(options=b"\x00\x00\x07")])
        self.assertEqual(_rules(tms.scan_bytes(data)), ["TFL005"])

    def test_missing_options_are_malformed(self):
        data = _model([_opcode(32, b"FlexAbs")], [_operator()])
        findings = tms.scan_bytes(data)
        self.assertEqual(_rules(findings), ["TFL005"])
        self.assertIn("no custom options", findings[0]["evidence"])

    def test_nodedef_without_op_is_malformed(self):
        options = _flex_options(b"Abs", b"\x0a\x01n")
        data = _model([_opcode(32, b"FlexAbs")], [_operator(options=options)])
        self.assertEqual(_rules(tms.scan_bytes(data)), ["TFL005"])

    def test_large_custom_options_outside_the_flatbuffer(self):
        options = _flex_options(b"ReadFile", _nodedef(b"ReadFile"))
        extra = {9: ("u64", 4096), 10: ("u64", len(options))}
        data = _model([_opcode(32, b"FlexReadFile")], [_operator(extra=extra)])
        self.assertLess(len(data), 4096)
        whole = data + b"\0" * (4096 - len(data)) + options
        self.assertEqual(_rules(tms.scan_bytes(whole)), ["TFL001"])
        self.assertEqual(_rules(tms.scan_bytes(data)), ["TFL005"])

    def test_opcode_index_out_of_range(self):
        findings = tms.scan_bytes(_model([_opcode(0)], [_operator(opcode=3)]))
        self.assertEqual(_rules(findings), ["TFL004"])
        self.assertIn("opcode_index 3 of 1", findings[0]["evidence"])

    def test_tensor_index_out_of_range(self):
        data = _model([_opcode(0)], [_operator(inputs=(0, -1, 7))])
        findings = tms.scan_bytes(data)
        self.assertEqual(_rules(findings), ["TFL004"])
        self.assertIn("tensor index 7 of 2", findings[0]["evidence"])

    def test_buffer_index_out_of_range(self):
        data = _model([_opcode(0)], [_operator()],
                      tensors=[_tensor(buffer=5), _tensor()])
        findings = tms.scan_bytes(data)
        self.assertEqual(_rules(findings), ["TFL004"])
        self.assertIn("buffer index 5 of 1", findings[0]["evidence"])

    def test_shape_below_minus_one(self):
        bad = _model([_opcode(0)], [_operator()],
                     tensors=[_tensor(shape=(1, -2)), _tensor()])
        self.assertEqual(_rules(tms.scan_bytes(bad)), ["TFL004"])
        dynamic = _model([_opcode(0)], [_operator()],
                         tensors=[_tensor(shape=(-1, 4)), _tensor()])
        self.assertEqual(tms.scan_bytes(dynamic), [])

    def test_buffer_data_outside_file(self):
        buffers = [("table", {}),
                   ("table", {1: ("u64", 10 ** 6), 2: ("u64", 16)})]
        data = _model([_opcode(0)], [_operator()], buffers=buffers)
        findings = tms.scan_bytes(data)
        self.assertEqual(_rules(findings), ["TFL004"])
        self.assertIn("buffer 1", findings[0]["evidence"])

    def test_not_tflite(self):
        self.assertEqual(_rules(tms.scan_bytes(b"\0" * 16)), ["TFL005"])
        self.assertEqual(_rules(tms.scan_bytes(b"")), ["TFL005"])

    def test_truncated_files_never_crash(self):
        data = _flex_model(b"FlexReadFile", b"ReadFile", b"ReadFile")
        for cut in range(0, len(data), 5):
            findings = tms.scan_bytes(data[:cut])
            for item in findings:
                self.assertEqual(set(item), _KEYS)
        self.assertIn("TFL005", _rules(tms.scan_bytes(data[:len(data) // 2])))

    def test_findings_are_capped(self):
        codes = [_opcode(32, b"Op%d" % i) for i in range(tms.MAX_FINDINGS + 5)]
        ops = [_operator(opcode=i) for i in range(tms.MAX_FINDINGS + 5)]
        findings = tms.scan_bytes(_model(codes, ops))
        self.assertEqual(len(findings), tms.MAX_FINDINGS + 1)
        self.assertEqual(findings[-1]["rule"], "TFL005")

    def test_output_is_ascii_with_fixed_keys(self):
        findings = tms.scan_bytes(_model([_opcode(32, b"My\xffOp")],
                                         [_operator()]))
        self.assertEqual(_rules(findings), ["TFL003"])
        for item in findings:
            self.assertEqual(set(item), _KEYS)
            item["message"].encode("ascii")
            item["evidence"].encode("ascii")

    def test_scan_file_and_main(self):
        tmp = tempfile.mkdtemp()
        try:
            risky = os.path.join(tmp, "risky.tflite")
            clean = os.path.join(tmp, "clean.tflite")
            empty = os.path.join(tmp, "empty.tflite")
            data = _flex_model(b"FlexReadFile", b"ReadFile", b"ReadFile")
            with open(risky, "wb") as handle:
                handle.write(data)
            with open(clean, "wb") as handle:
                handle.write(_model([_opcode(0)], [_operator()]))
            open(empty, "wb").close()
            self.assertEqual(tms.scan_file(risky), tms.scan_bytes(data))
            self.assertEqual(_rules(tms.scan_file(empty)), ["TFL005"])
            sink = io.StringIO()
            with contextlib.redirect_stdout(sink), \
                    contextlib.redirect_stderr(sink):
                self.assertEqual(tms.main([risky]), 1)
                self.assertEqual(tms.main([clean]), 0)
                self.assertEqual(tms.main([empty]), 0)
                self.assertEqual(tms.main([]), 2)
                self.assertEqual(tms.main([os.path.join(tmp, "missing")]), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_version(self):
        self.assertEqual(tms.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
