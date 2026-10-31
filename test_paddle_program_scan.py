#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Self-contained tests for paddle_program_scan. Standard library only."""

import json
import os
import shutil
import tempfile
import unittest

import paddle_program_scan as pp


def _vint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _ld(field, payload):
    return _vint((field << 3) | 2) + _vint(len(payload)) + payload


def _vf(field, n):
    return _vint(field << 3) + _vint(n)


def _s(field, text):
    return _ld(field, text.encode("utf-8"))


def _attr_s(name, value):
    # OpDesc.Attr: name = 1, type = 2 (STRING = 2), s = 5.
    return _s(1, name) + _vf(2, 2) + _s(5, value)


def _attr_i(name, value):
    # OpDesc.Attr: name = 1, type = 2 (INT = 0), i = 3.
    return _s(1, name) + _vf(2, 0) + _vf(3, value)


def _op(op_type, *attrs):
    # OpDesc: inputs = 1 (Var: parameter = 1, arguments = 2), type = 3,
    # attrs = 4.
    return (_ld(1, _s(1, "X") + _s(2, "x")) + _s(3, op_type)
            + b"".join(_ld(4, a) for a in attrs))


def _block(idx, *ops):
    # BlockDesc: idx = 1, parent_idx = 2, vars = 3, ops = 4.
    var = _s(1, "x") + _ld(2, _vf(1, 7))          # VarDesc name, VarType
    return (_vf(1, idx) + _vf(2, 0) + _ld(3, var)
            + b"".join(_ld(4, op) for op in ops))


def _program(*blocks):
    # ProgramDesc: blocks = 1, version = 4 (Version.version = 1).
    return b"".join(_ld(1, b) for b in blocks) + _ld(4, _vf(1, 3000000))


def _clean_ops():
    return (_op("feed", _attr_i("col", 0)),
            _op("matmul_v2", _attr_i("trans_x", 0)),
            _op("fetch", _attr_i("col", 0)))


def _jop(op_name, **attrs):
    # op_name, not name: PIR feed/fetch ops carry a "name" attribute.
    return {"#": op_name, "I": [], "O": [],
            "A": [{"N": k, "AT": {"#": "0.a_str", "D": v}}
                  for k, v in sorted(attrs.items())]}


def _pir(*ops):
    return {"base_code": {"magic": "pir", "trainable": False, "version": 1},
            "program": {"regions": [{"#": "region_0", "blocks": [
                {"#": "block_0", "args": [], "ops": list(ops)}]}]}}


def _jbytes(doc):
    return json.dumps(doc).encode("utf-8")


def _rules(findings):
    return [f["rule"] for f in findings]


class PaddleProgramScanTests(unittest.TestCase):

    def test_version(self):
        self.assertEqual(pp.__version__, "0.1.0")

    def test_clean_program_no_findings(self):
        self.assertEqual(pp.scan_bytes(_program(_block(0, *_clean_ops()))), [])

    def test_save_combine_is_pdl001(self):
        op = _op("save_combine", _attr_s("file_path", "/home/u/.bashrc"),
                 _attr_i("overwrite", 1))
        findings = pp.scan_bytes(_program(_block(0, op)))
        self.assertEqual(_rules(findings), ["PDL001"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("/home/u/.bashrc", findings[0]["evidence"])
        self.assertIn("save_combine", findings[0]["evidence"])

    def test_save_is_pdl001(self):
        op = _op("save", _attr_s("file_path", "out/w"))
        self.assertEqual(_rules(pp.scan_bytes(_program(_block(0, op)))),
                         ["PDL001"])

    def test_read_ops_are_pdl002(self):
        for op_type, attr in (("load", "file_path"),
                              ("load_combine", "file_path"),
                              ("read_file", "filename")):
            op = _op(op_type, _attr_s(attr, "/etc/hostname"))
            findings = pp.scan_bytes(_program(_block(0, op)))
            self.assertEqual(_rules(findings), ["PDL002"], op_type)
            self.assertIn("/etc/hostname", findings[0]["evidence"])

    def test_py_func_is_pdl003(self):
        op = _op("py_func", _attr_i("forward_callable_id", 3))
        findings = pp.scan_bytes(_program(_block(0, op)))
        self.assertEqual(_rules(findings), ["PDL003"])
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("forward_callable_id 3", findings[0]["evidence"])

    def test_op_in_sub_block_is_found(self):
        inner = _op("save_combine", _attr_s("file_path", "/tmp/sub"))
        prog = _program(_block(0, *_clean_ops()), _block(1, inner))
        findings = pp.scan_bytes(prog)
        self.assertEqual(_rules(findings), ["PDL001"])
        self.assertIn("block 1", findings[0]["evidence"])

    def test_same_op_and_path_reported_once_with_count(self):
        op = _op("save_combine", _attr_s("file_path", "/tmp/a"))
        findings = pp.scan_bytes(_program(_block(0, op, op)))
        self.assertEqual(_rules(findings), ["PDL001"])
        self.assertIn("2 in total", findings[0]["evidence"])

    def test_different_paths_reported_separately(self):
        ops = (_op("save", _attr_s("file_path", "/tmp/a")),
               _op("save", _attr_s("file_path", "/tmp/b")))
        findings = pp.scan_bytes(_program(_block(0, *ops)))
        self.assertEqual(_rules(findings), ["PDL001", "PDL001"])

    def test_missing_path_attribute_still_flagged(self):
        findings = pp.scan_bytes(_program(_block(0, _op("load_combine"))))
        self.assertEqual(_rules(findings), ["PDL002"])
        self.assertIn("(none)", findings[0]["evidence"])

    def test_not_protobuf_is_pdl004(self):
        self.assertEqual(_rules(pp.scan_bytes(b"hello world")), ["PDL004"])

    def test_protobuf_that_is_not_a_program_is_pdl004(self):
        for raw in (_vf(1, 5), _ld(9, b"x"), _ld(4, b"")):
            self.assertEqual(_rules(pp.scan_bytes(raw)), ["PDL004"], raw)

    def test_empty_and_truncated_never_crash(self):
        full = _program(_block(0, *_clean_ops()))
        for raw in (b"", full[:-3], b"\xff" * 12, b"\x0a"):
            findings = pp.scan_bytes(raw)
            self.assertIsInstance(findings, list)
            self.assertIn("PDL004", _rules(findings))

    def test_parse_errors_are_not_guard_crashes(self):
        # Regression (0.1.0 was first refused by CI): a clean or malformed
        # input must reach the parser, never the guard's crash finding.
        for raw in (_program(_block(0, *_clean_ops())), b"hello world",
                    b"{oops"):
            for f in pp.scan_bytes(raw):
                self.assertNotIn("could not be parsed", f["message"])

    def test_pir_clean_no_findings(self):
        doc = _pir(_jop("1.feed", name="x"), _jop("1.matmul"),
                   _jop("1.fetch", name="out"))
        self.assertEqual(pp.scan_bytes(_jbytes(doc)), [])

    def test_pir_save_combine_is_pdl001(self):
        doc = _pir(_jop("1.feed", name="x"),
                   _jop("1.save_combine", file_path="/tmp/x", overwrite=True))
        findings = pp.scan_bytes(_jbytes(doc))
        self.assertEqual(_rules(findings), ["PDL001"])
        self.assertIn("(PIR)", findings[0]["evidence"])
        self.assertIn("/tmp/x", findings[0]["evidence"])

    def test_pir_dialect_names_and_py_func(self):
        doc = _pir(_jop("pd_op.py_func", forward_callable_id=2))
        findings = pp.scan_bytes(_jbytes(doc))
        self.assertEqual(_rules(findings), ["PDL003"])
        self.assertIn("forward_callable_id 2", findings[0]["evidence"])

    def test_pir_op_in_nested_region_is_found(self):
        inner = {"#": "region_1", "blocks": [
            {"#": "block_1", "args": [],
             "ops": [_jop("1.read_file", filename="/tmp/r")]}]}
        outer = _jop("1.if")
        outer["regions"] = [inner]
        findings = pp.scan_bytes(_jbytes(_pir(outer)))
        self.assertEqual(_rules(findings), ["PDL002"])
        self.assertIn("/tmp/r", findings[0]["evidence"])

    def test_json_without_ops_is_pdl004(self):
        self.assertEqual(_rules(pp.scan_bytes(b'{"a": [1, 2]}')), ["PDL004"])

    def test_invalid_json_is_pdl004(self):
        self.assertEqual(_rules(pp.scan_bytes(b"{oops")), ["PDL004"])

    def test_deep_json_stops_with_pdl004(self):
        node = []
        for _ in range(100):
            node = [node]
        findings = pp.scan_bytes(_jbytes({"program": node}))
        self.assertIn("PDL004", _rules(findings))

    def test_output_is_ascii_with_fixed_keys(self):
        op = _op("save", _attr_s("file_path", "/tmp/é"))
        findings = pp.scan_bytes(_program(_block(0, op)))
        self.assertTrue(findings)
        for f in findings:
            self.assertEqual(set(f), {"rule", "severity", "cve", "cwe",
                                      "message", "evidence"})
            self.assertTrue(all(ord(c) < 128 for c in f["message"]))
            self.assertTrue(all(ord(c) < 128 for c in f["evidence"]))

    def test_scan_file_and_main_exit_codes(self):
        root = tempfile.mkdtemp()
        try:
            clean = os.path.join(root, "clean.pdmodel")
            with open(clean, "wb") as handle:
                handle.write(_program(_block(0, *_clean_ops())))
            bad = os.path.join(root, "bad.pdmodel")
            with open(bad, "wb") as handle:
                handle.write(_program(_block(0, _op(
                    "save", _attr_s("file_path", "/tmp/w")))))
            pir = os.path.join(root, "model.json")
            with open(pir, "wb") as handle:
                handle.write(_jbytes(_pir(_jop("1.py_func"))))
            self.assertEqual(pp.scan_file(clean), [])
            self.assertEqual(_rules(pp.scan_file(bad)), ["PDL001"])
            self.assertEqual(_rules(pp.scan_file(pir)), ["PDL003"])
            self.assertEqual(pp.main([clean]), 0)
            self.assertEqual(pp.main([bad]), 1)
            self.assertEqual(pp.main([pir]), 0)
            self.assertEqual(pp.main([os.path.join(root, "nope.pdmodel")]), 2)
            self.assertEqual(pp.main([]), 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
