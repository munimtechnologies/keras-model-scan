# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for executorch_pte_scan.py.

ExecuTorch programs and their eh00 extended headers are built by hand from the
published schema (schema/program.fbs, schema/scalar_type.fbs) and the header
layout in exir/_serialize/_program.py. Nothing is loaded or executed.
"""

import contextlib
import io
import os
import shutil
import struct
import tempfile
import unittest

import executorch_pte_scan as pte

_SCALARS = {"u8": "<B", "i8": "<b", "i32": "<i", "u32": "<I", "u64": "<Q"}
_VECTORS = {"ints": "i", "u64s": "Q", "i64s": "q"}
_KEYS = {"rule", "severity", "cve", "cwe", "message", "evidence"}


class _Builder(object):
    """Lays a FlatBuffer out front to back; every uoffset points forward."""

    def __init__(self):
        self.buf = bytearray()
        self.pending = []

    def _pad(self, n):
        while len(self.buf) % n:
            self.buf.append(0)

    def build(self, root, header=False):
        self.buf += b"\0\0\0\0" + pte.FILE_IDENTIFIER
        if header:
            self.buf += pte.HEADER_MAGIC + struct.pack("<IQQQ", 32, 0, 0, 0)
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
        elif kind in _VECTORS:
            self.buf += struct.pack("<I%d%s" % (len(value), _VECTORS[kind]),
                                    len(value), *value)
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


def _attach(program, payload, base=None, data_size=None, length=32):
    """Append segment data after `program` and fill in its eh00 header."""
    data = bytearray(program)
    if base is None:
        base = (len(data) + 15) // 16 * 16
    if data_size is None:
        data_size = len(payload)
    struct.pack_into("<IQQQ", data, 12, length, len(program), base, data_size)
    data += b"\0" * max(0, base - len(data)) + payload
    return bytes(data)


def _tensor(dims=(2, 3), dtype=6, index=0, alloc=None, external=False):
    fields = {0: ("i8", dtype), 2: ("ints", list(dims)), 5: ("u32", index)}
    if alloc is not None:
        memory_id, offset = alloc
        fields[6] = ("table", {0: ("u32", memory_id),
                               1: ("u32", offset & 0xFFFFFFFF),
                               2: ("u32", offset >> 32)})
    if external:
        fields[9] = ("table", {2: ("i8", 1)})
    return ("table", {0: ("u8", 5), 1: ("table", fields)})


def _planned(offset, memory_id=1, **kwargs):
    return _tensor(alloc=(memory_id, offset), **kwargs)


def _list(kind, items):
    return ("table", {0: ("u8", kind), 1: ("table", {0: ("ints", list(items))})})


def _call(kind, *fields):
    """Instruction with union tag `kind`; int or list fields in slot order."""
    args = {}
    for slot, value in enumerate(fields):
        if isinstance(value, (list, tuple)):
            args[slot] = ("ints", list(value))
        else:
            args[slot] = ("i32", value)
    return ("table", {0: ("u8", kind), 1: ("table", args)})


def _delegate(name=b"XnnpackBackend", location=0, index=0):
    spec = ("table", {0: ("str", b"key"), 1: ("bytes", b"v")})
    return ("table", {0: ("str", name),
                      1: ("table", {0: ("i8", location), 1: ("u32", index)}),
                      2: ("tables", [spec])})


_OPERATOR = ("table", {0: ("str", b"aten::add"), 1: ("str", b"out")})


def _plan(values=None, instructions=None, delegates=(), sizes=(0, 64)):
    if values is None:
        values = [_planned(0), _planned(32)]
    if instructions is None:
        instructions = [_call(1, 0, [0, 1])]
    chain = ("table", {0: ("ints", [0]), 1: ("ints", [1]),
                       2: ("tables", list(instructions))})
    return ("table", {0: ("str", b"forward"), 2: ("tables", list(values)),
                      3: ("ints", [0]), 4: ("ints", [1]),
                      5: ("tables", [chain]), 6: ("tables", [_OPERATOR]),
                      7: ("tables", list(delegates)),
                      8: ("i64s", list(sizes))})


def _program(plan=None, segments=None, constant=None, mutable=None,
             named=None, inline=None, constant_buffer=None):
    fields = {0: ("u32", 0),
              1: ("tables", [_plan() if plan is None else plan])}
    if constant_buffer is not None:
        fields[2] = ("tables", [("table", {0: ("bytes", b)})
                                for b in constant_buffer])
    if inline is not None:
        fields[3] = ("tables", [("table", {0: ("bytes", b)}) for b in inline])
    if segments is not None:
        fields[4] = ("tables", [("table", {0: ("u64", o), 1: ("u64", s)})
                                for o, s in segments])
    if constant is not None:
        fields[5] = ("table", {0: ("u32", constant[0]),
                               1: ("u64s", list(constant[1]))})
    if mutable is not None:
        fields[6] = ("tables", [("table", {0: ("u32", i), 1: ("u64s", list(o))})
                                for i, o in mutable])
    if named is not None:
        fields[7] = ("tables", [("table", {0: ("str", k), 1: ("u32", i)})
                                for k, i in named])
    return ("table", fields)


def _pte(segment_data=None, **kwargs):
    root = _program(**kwargs)
    if segment_data is None:
        return _Builder().build(root)
    return _attach(_Builder().build(root, header=True), segment_data)


def _rules(findings):
    return sorted(f["rule"] for f in findings)


def _evidence(findings, rule):
    return [f for f in findings if f["rule"] == rule][0]["evidence"]


class ExecuTorchPteScanTests(unittest.TestCase):

    def test_plain_program_is_clean(self):
        self.assertEqual(pte.scan_bytes(_pte()), [])

    def test_constant_segment_program_is_clean(self):
        data = _pte(segment_data=b"\x01" * 32, segments=[(0, 32)],
                    constant=(0, [0, 0]),
                    plan=_plan(values=[_tensor(index=1), _planned(0)]))
        self.assertEqual(pte.scan_bytes(data), [])

    def test_delegate_is_listed_medium(self):
        data = _pte(inline=[b"\0" * 16],
                    plan=_plan(delegates=[_delegate()],
                               instructions=[_call(2, 0, [0, 1])]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE003"])
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(findings[0]["cve"], "")
        self.assertIn("XnnpackBackend", findings[0]["message"])
        self.assertIn("inline blob 0, 16 bytes", findings[0]["evidence"])
        self.assertIn("1 compile specs", findings[0]["evidence"])

    def test_delegate_blob_in_a_segment(self):
        data = _pte(segment_data=b"\0" * 64, segments=[(0, 64)],
                    plan=_plan(delegates=[_delegate(b"CoreMLBackend", 1)]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE003"])
        self.assertIn("segment 0, 64 bytes", findings[0]["evidence"])

    def test_repeated_backend_is_listed_once(self):
        data = _pte(inline=[b"\0" * 8],
                    plan=_plan(delegates=[_delegate(), _delegate()]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE003"])
        self.assertIn("2 in total", findings[0]["evidence"])

    def test_delegate_data_index_out_of_range(self):
        data = _pte(inline=[b"\0" * 8],
                    plan=_plan(delegates=[_delegate(index=3)]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE003", "PTE004"])
        self.assertIn("inline blob index 3 of 1", _evidence(findings, "PTE004"))

    def test_operator_index_out_of_range(self):
        data = _pte(plan=_plan(instructions=[_call(1, 5, [0, 1])]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE004"])
        self.assertEqual(findings[0]["cwe"], "CWE-129")
        self.assertIn("op_index: index 5 of 1", findings[0]["evidence"])

    def test_value_index_out_of_range(self):
        data = _pte(plan=_plan(instructions=[_call(1, 0, [0, 9])]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE004"])
        self.assertIn("args: index 9 of 2", findings[0]["evidence"])

    def test_jump_and_free_indexes(self):
        ok = _pte(plan=_plan(instructions=[_call(4, 0, 1)]))
        self.assertEqual(pte.scan_bytes(ok), [])
        jump = _pte(plan=_plan(instructions=[_call(4, 0, 5)]))
        self.assertEqual(_rules(pte.scan_bytes(jump)), ["PTE004"])
        free = pte.scan_bytes(_pte(plan=_plan(instructions=[_call(5, 7)])))
        self.assertEqual(_rules(free), ["PTE004"])
        self.assertIn("value_index: index 7 of 2", free[0]["evidence"])

    def test_tensor_lists(self):
        values = [_planned(0), _planned(32), _list(10, [0, 9]),
                  _list(11, [-1, 1])]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE004"])
        self.assertIn("value 2 items: index 9 of 4", findings[0]["evidence"])
        self.assertIn(": 1", findings[0]["message"])

    def test_negative_dimension(self):
        values = [_planned(0, dims=(2, -3)), _planned(32)]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE001"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["cwe"], "CWE-190")
        self.assertIn("dimension -3", findings[0]["evidence"])

    def test_size_overflow(self):
        values = [_planned(0, dims=(2 ** 31 - 1,) * 3), _planned(32)]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE001"])
        self.assertIn("2**63", findings[0]["evidence"])

    def test_negative_buffer_size(self):
        data = _pte(plan=_plan(values=[_tensor(), _tensor()], sizes=(0, -1)))
        self.assertEqual(_rules(pte.scan_bytes(data)), ["PTE001"])

    def test_planned_tensor_past_its_buffer(self):
        values = [_planned(48), _planned(0)]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE002"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["cwe"], "CWE-125")
        self.assertIn("planned buffer 1", findings[0]["evidence"])

    def test_high_offset_word_counts(self):
        values = [_planned(2 ** 32), _planned(32)]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE002"])
        self.assertIn("offset 4294967296", findings[0]["evidence"])

    def test_memory_id_out_of_range(self):
        for memory_id in (0, 2):
            values = [_planned(0, memory_id=memory_id), _planned(32)]
            findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
            self.assertEqual(_rules(findings), ["PTE004"])
            self.assertIn("memory_id %d" % memory_id, findings[0]["evidence"])

    def test_constant_past_its_segment(self):
        data = _pte(segment_data=b"\0" * 32, segments=[(0, 32)],
                    constant=(0, [0, 16]),
                    plan=_plan(values=[_tensor(index=1), _planned(0)]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE002"])
        self.assertIn("24 bytes at offset 16", findings[0]["evidence"])

    def test_constant_index_past_offsets(self):
        data = _pte(segment_data=b"\0" * 32, segments=[(0, 32)],
                    constant=(0, [0, 0]),
                    plan=_plan(values=[_tensor(index=5), _planned(0)]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE004"])
        self.assertIn("data_buffer_idx 5 of 2", findings[0]["evidence"])

    def test_segment_past_segment_data(self):
        findings = pte.scan_bytes(_pte(segment_data=b"\0" * 32,
                                       segments=[(0, 64)]))
        self.assertEqual(_rules(findings), ["PTE002"])
        self.assertIn("segment 0", findings[0]["evidence"])

    def test_segment_arithmetic_overflow(self):
        findings = pte.scan_bytes(_pte(segment_data=b"\0" * 32,
                                       segments=[(2 ** 64 - 8, 16)]))
        self.assertEqual(_rules(findings), ["PTE001"])
        self.assertIn("overflows 64 bits", findings[0]["evidence"])

    def test_segment_index_out_of_range(self):
        data = _pte(segment_data=b"\0" * 32, segments=[(0, 32)],
                    constant=(3, [0, 0]), named=[(b"w", 2)],
                    plan=_plan(values=[_tensor(index=1), _planned(0)]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE004"])
        self.assertTrue(findings[0]["message"].endswith(": 2"))
        self.assertIn("constant_segment: segment_index 3 of 1",
                      findings[0]["evidence"])
        self.assertIn("named_data[0] w: segment_index 2 of 1",
                      findings[0]["evidence"])

    def test_mutable_initial_state(self):
        values = [_planned(0, index=1), _planned(32)]
        good = _pte(segment_data=b"\0" * 32, segments=[(0, 32)],
                    mutable=[(0, [0, 0])], plan=_plan(values=values))
        self.assertEqual(pte.scan_bytes(good), [])
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE004"])
        self.assertIn("no mutable_data_segments[0]", findings[0]["evidence"])

    def test_external_tensor_skips_data_checks(self):
        values = [_tensor(index=7, external=True), _planned(0)]
        self.assertEqual(pte.scan_bytes(_pte(plan=_plan(values=values))), [])

    def test_unknown_dtype(self):
        values = [_tensor(dtype=9), _tensor()]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE004"])
        self.assertIn("scalar_type 9", findings[0]["evidence"])

    def test_legacy_constant_buffer(self):
        values = [_tensor(index=1), _planned(0)]
        ok = _pte(constant_buffer=[b"", b"\0" * 24], plan=_plan(values=values))
        self.assertEqual(pte.scan_bytes(ok), [])
        short = _pte(constant_buffer=[b"", b"\0" * 8], plan=_plan(values=values))
        self.assertEqual(_rules(pte.scan_bytes(short)), ["PTE002"])
        values = [_tensor(index=4), _planned(0)]
        missing = _pte(constant_buffer=[b"", b"\0" * 24],
                       plan=_plan(values=values))
        self.assertEqual(_rules(pte.scan_bytes(missing)), ["PTE004"])

    def test_segments_without_a_header(self):
        findings = pte.scan_bytes(_pte(segments=[(0, 32)]))
        self.assertEqual(_rules(findings), ["PTE005"])
        self.assertIn("1 segments", findings[0]["evidence"])

    def test_truncated_segment_data(self):
        full = _pte(segment_data=b"\0" * 32, segments=[(0, 32)])
        findings = pte.scan_bytes(full[:-16])
        self.assertEqual(_rules(findings), ["PTE005"])
        self.assertIn("truncated", findings[0]["message"])

    def test_segment_base_inside_program(self):
        program = _Builder().build(_program(segments=[(0, 32)]), header=True)
        data = _attach(program, b"\0" * 32, base=16)
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE002"])
        self.assertIn("segment_base_offset 16", findings[0]["evidence"])

    def test_bad_header_length(self):
        program = _Builder().build(_program(segments=[(0, 32)]), header=True)
        findings = pte.scan_bytes(_attach(program, b"\0" * 32, length=8))
        self.assertEqual(_rules(findings), ["PTE005"])
        self.assertIn("extended header length 8", findings[0]["evidence"])

    def test_not_executorch(self):
        for data in (b"", b"\0" * 16, b"\x08\0\0\0ET11" + b"\0" * 8,
                     b"\x04\0\0\0ET12" + b"\0" * 8):
            self.assertEqual(_rules(pte.scan_bytes(data)), ["PTE005"])

    def test_truncated_files_never_crash(self):
        data = _pte(segment_data=b"\0" * 64, segments=[(0, 64)],
                    inline=[b"\0" * 8], plan=_plan(delegates=[_delegate()]))
        for cut in range(0, len(data), 7):
            for item in pte.scan_bytes(data[:cut]):
                self.assertEqual(set(item), _KEYS)
        self.assertIn("PTE005", _rules(pte.scan_bytes(data[:len(data) // 2])))

    def test_findings_are_capped(self):
        delegates = [_delegate(b"B%d" % i) for i in range(pte.MAX_FINDINGS + 5)]
        data = _pte(inline=[b"x"], plan=_plan(delegates=delegates))
        findings = pte.scan_bytes(data)
        self.assertEqual(len(findings), pte.MAX_FINDINGS + 1)
        self.assertEqual(findings[-1]["rule"], "PTE005")

    def test_output_is_ascii_with_fixed_keys(self):
        data = _pte(inline=[b"x"],
                    plan=_plan(delegates=[_delegate(b"My\xffBackend")]))
        findings = pte.scan_bytes(data)
        self.assertEqual(_rules(findings), ["PTE003"])
        for item in findings:
            self.assertEqual(set(item), _KEYS)
            item["message"].encode("ascii")
            item["evidence"].encode("ascii")

    def test_scan_file_and_main(self):
        tmp = tempfile.mkdtemp()
        try:
            risky = os.path.join(tmp, "risky.pte")
            clean = os.path.join(tmp, "clean.pte")
            delegated = os.path.join(tmp, "delegated.pte")
            empty = os.path.join(tmp, "empty.pte")
            data = _pte(plan=_plan(values=[_planned(48), _planned(0)]))
            with open(risky, "wb") as handle:
                handle.write(data)
            with open(clean, "wb") as handle:
                handle.write(_pte())
            with open(delegated, "wb") as handle:
                handle.write(_pte(inline=[b"x"],
                                  plan=_plan(delegates=[_delegate()])))
            open(empty, "wb").close()
            self.assertEqual(pte.scan_file(risky), pte.scan_bytes(data))
            self.assertEqual(_rules(pte.scan_file(empty)), ["PTE005"])
            sink = io.StringIO()
            with contextlib.redirect_stdout(sink), \
                    contextlib.redirect_stderr(sink):
                self.assertEqual(pte.main([risky]), 1)
                self.assertEqual(pte.main([clean]), 0)
                self.assertEqual(pte.main([delegated]), 0)
                self.assertEqual(pte.main([empty]), 0)
                self.assertEqual(pte.main([]), 2)
                self.assertEqual(pte.main([os.path.join(tmp, "missing")]), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_version(self):
        self.assertEqual(pte.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
