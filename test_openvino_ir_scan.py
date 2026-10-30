#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Self-contained tests for openvino_ir_scan. Standard library only."""

import os
import shutil
import tempfile
import unittest

import openvino_ir_scan as ov


def _net(layers_xml):
    return ('<?xml version="1.0"?>'
            '<net name="m" version="11"><layers>%s</layers><edges/></net>'
            % layers_xml).encode("utf-8")


def _const(data_attrs, op_type="Const"):
    attrs = " ".join('%s="%s"' % (k, v) for k, v in data_attrs.items())
    return _net('<layer id="0" name="c" type="%s" version="opset1">'
                '<data %s/><output><port id="0"/></output></layer>'
                % (op_type, attrs))


def _rules(findings):
    return [f["rule"] for f in findings]


class OpenVinoIrScanTests(unittest.TestCase):

    def test_version(self):
        self.assertEqual(ov.__version__, "0.1.0")

    def test_clean_const_no_findings(self):
        xml = _const({"element_type": "f32", "shape": "2,3",
                      "offset": "0", "size": "24"})
        self.assertEqual(ov.scan_bytes(xml, bin_size=24), [])

    def test_range_past_bin_is_ovi003(self):
        xml = _const({"element_type": "f32", "shape": "2,3",
                      "offset": "0", "size": "100"})
        findings = ov.scan_bytes(xml, bin_size=50)
        self.assertIn("OVI003", _rules(findings))
        self.assertTrue(all(f["severity"] == "high" for f in findings
                            if f["rule"] == "OVI003"))

    def test_large_offset_is_overflow_safe_ovi003(self):
        xml = _const({"element_type": "f32", "shape": "2",
                      "offset": str(1 << 63), "size": "10"})
        self.assertIn("OVI003", _rules(ov.scan_bytes(xml, bin_size=100)))

    def test_string_const_out_of_range_notes_runtime_gap(self):
        xml = _const({"element_type": "string", "shape": "2",
                      "offset": "0", "size": "100"})
        findings = ov.scan_bytes(xml, bin_size=50)
        self.assertIn("OVI003", _rules(findings))
        evidence = [f["evidence"] for f in findings
                    if f["rule"] == "OVI003"][0]
        self.assertIn("does not bounds-check", evidence)

    def test_exact_boundary_range_is_valid(self):
        xml = _const({"element_type": "f32", "shape": "3",
                      "offset": "10", "size": "14"})
        self.assertNotIn("OVI003", _rules(ov.scan_bytes(xml, bin_size=24)))

    def test_shape_bitwidth_overflow_is_ovi004(self):
        xml = _const({"element_type": "f32", "shape": str(1 << 64),
                      "offset": "0", "size": "4"})
        findings = ov.scan_bytes(xml, bin_size=1000)
        self.assertIn("OVI004", _rules(findings))

    def test_negative_dimension_is_ovi004(self):
        xml = _const({"element_type": "f32", "shape": "-1,3",
                      "offset": "0", "size": "24"})
        self.assertIn("OVI004", _rules(ov.scan_bytes(xml, bin_size=1000)))

    def test_size_smaller_than_needed_is_ovi005(self):
        xml = _const({"element_type": "f32", "shape": "2,3",
                      "offset": "0", "size": "8"})
        findings = ov.scan_bytes(xml, bin_size=1000)
        rules = _rules(findings)
        self.assertIn("OVI005", rules)
        self.assertNotIn("OVI003", rules)

    def test_subbyte_type_consistency(self):
        # u4: 6 elements * 4 bits = 24 bits -> 3 bytes needed.
        ok = _const({"element_type": "u4", "shape": "2,3",
                     "offset": "0", "size": "3"})
        self.assertEqual(ov.scan_bytes(ok, bin_size=3), [])
        small = _const({"element_type": "u4", "shape": "2,3",
                        "offset": "0", "size": "2"})
        self.assertIn("OVI005", _rules(ov.scan_bytes(small, bin_size=1000)))

    def test_inline_const_without_size_is_skipped(self):
        xml = _const({"element_type": "f32", "shape": "1"})
        self.assertEqual(ov.scan_bytes(xml, bin_size=None), [])

    def test_unparsable_size_is_ovi005(self):
        xml = _const({"element_type": "f32", "shape": "1",
                      "offset": "0", "size": "abc"})
        self.assertIn("OVI005", _rules(ov.scan_bytes(xml, bin_size=10)))

    def test_bin_missing_notes_unchecked_const(self):
        xml = _const({"element_type": "f32", "shape": "2,3",
                      "offset": "0", "size": "24"})
        findings = ov.scan_bytes(xml, bin_size=None)
        self.assertIn("OVI005", _rules(findings))

    def test_python_layer_is_ovi002(self):
        xml = _net('<layer id="0" name="p" type="python"/>')
        findings = ov.scan_bytes(xml)
        self.assertIn("OVI002", _rules(findings))
        self.assertTrue(all(f["severity"] == "high" for f in findings
                            if f["rule"] == "OVI002"))

    def test_custom_layer_is_ovi002(self):
        xml = _net('<layer id="0" name="x" type="custom"/>')
        self.assertIn("OVI002", _rules(ov.scan_bytes(xml)))

    def test_library_so_reference_is_ovi002(self):
        xml = _net('<layer id="0" type="Op" version="e">'
                   '<data library="/opt/evil.so.2"/></layer>')
        self.assertIn("OVI002", _rules(ov.scan_bytes(xml)))

    def test_implementation_path_reference_is_ovi002(self):
        xml = _net('<layer id="0" type="Op" version="e">'
                   '<data implementation="..\\..\\evil.dll"/></layer>')
        self.assertIn("OVI002", _rules(ov.scan_bytes(xml)))

    def test_benign_library_value_not_flagged(self):
        xml = _net('<layer id="0" type="Op" version="opset1">'
                   '<data library="opset1"/></layer>')
        self.assertNotIn("OVI002", _rules(ov.scan_bytes(xml)))

    def test_doctype_is_refused_ovi001(self):
        raw = (b'<?xml version="1.0"?><!DOCTYPE net ['
               b'<!ENTITY x "y">]><net><layers/></net>')
        findings = ov.scan_bytes(raw)
        self.assertEqual(_rules(findings), ["OVI001"])

    def test_entity_is_refused_ovi001(self):
        raw = b'<!ENTITY lol "ha"><net><layers/></net>'
        self.assertIn("OVI001", _rules(ov.scan_bytes(raw)))

    def test_not_xml_is_ovi005(self):
        self.assertIn("OVI005", _rules(ov.scan_bytes(b"this is not xml <<<")))

    def test_wrong_root_is_ovi005(self):
        self.assertIn("OVI005", _rules(ov.scan_bytes(b"<foo><bar/></foo>")))

    def test_empty_and_truncated_never_crash(self):
        for raw in (b"", b"<net", b"<net><layers><layer id='0'",
                    b"\x00\x01\x02\x03", b"<model></model>"):
            self.assertIsInstance(ov.scan_bytes(raw), list)

    def test_clean_multilayer_net(self):
        xml = _net(
            '<layer id="0" name="in" type="Parameter" version="opset1">'
            '<data element_type="f32" shape="1,3"/></layer>'
            '<layer id="1" name="w" type="Const" version="opset1">'
            '<data element_type="f32" shape="3" offset="0" size="12"/></layer>'
            '<layer id="2" name="out" type="Result" version="opset1"/>')
        self.assertEqual(ov.scan_bytes(xml, bin_size=12), [])

    def test_output_is_ascii_with_fixed_keys(self):
        xml = _const({"element_type": "f32", "shape": "2,3",
                      "offset": "0", "size": "100"})
        for f in ov.scan_bytes(xml.replace(b'name="c"',
                                           b'name="c\xc3\xa9"'), bin_size=50):
            self.assertEqual(set(f), {"rule", "severity", "cve", "cwe",
                                      "message", "evidence"})
            self.assertTrue(all(ord(c) < 128 for c in f["message"]))
            self.assertTrue(all(ord(c) < 128 for c in f["evidence"]))

    def test_scan_file_and_main_clean(self):
        root = tempfile.mkdtemp()
        try:
            xml = os.path.join(root, "m.xml")
            with open(xml, "wb") as handle:
                handle.write(_const({"element_type": "f32", "shape": "2,3",
                                     "offset": "0", "size": "24"}))
            with open(os.path.join(root, "m.bin"), "wb") as handle:
                handle.write(b"\x00" * 24)
            self.assertEqual(ov.scan_file(xml), [])
            self.assertEqual(ov.main([xml]), 0)
        finally:
            shutil.rmtree(root)

    def test_scan_file_finds_oob_and_main_returns_one(self):
        root = tempfile.mkdtemp()
        try:
            xml = os.path.join(root, "m.xml")
            with open(xml, "wb") as handle:
                handle.write(_const({"element_type": "f32", "shape": "2,3",
                                     "offset": "0", "size": "999"}))
            with open(os.path.join(root, "m.bin"), "wb") as handle:
                handle.write(b"\x00" * 24)
            self.assertIn("OVI003", _rules(ov.scan_file(xml)))
            self.assertEqual(ov.main([xml]), 1)
        finally:
            shutil.rmtree(root)

    def test_main_usage(self):
        self.assertEqual(ov.main([]), 2)


if __name__ == "__main__":
    unittest.main()
