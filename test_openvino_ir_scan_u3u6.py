# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""openvino_ir_scan: size checks for OpenVINO's u3 and u6 element types.

OpenVINO up to 2026.4 stores u3/u6 in 3-byte units (8 u3 or 4 u6 values per
3 bytes); from PR #37430 (2026.5) it packs them tightly, ceil(n * bits / 8)
bytes. Honest Consts of either layout must pass; a declared size below the
tight size is OVI005; an element count whose bit size reaches 2**64 is OVI004.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import os
import shutil
import tempfile
import unittest

import openvino_ir_scan as oi

XML = """<?xml version="1.0"?>
<net name="t" version="11">
  <layers>
    <layer id="0" name="c" type="Const" version="opset1">
      <data element_type="{et}" shape="{shape}" offset="0" size="{size}"/>
      <output><port id="0" precision="{prec}"><dim>{dim}</dim></port></output>
    </layer>
    <layer id="1" name="r" type="Result" version="opset1">
      <input><port id="0"><dim>{dim}</dim></port></input>
    </layer>
  </layers>
  <edges><edge from-layer="0" from-port="0" to-layer="1" to-port="0"/></edges>
</net>
"""


class U3U6Sizes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rules(self, et, shape, size, bin_bytes=64):
        stem = os.path.join(self.tmp, "%s_%s_%s" % (
            et, shape.replace(",", "x").replace(" ", ""), size))
        with open(stem + ".xml", "w", encoding="utf-8") as fh:
            fh.write(XML.format(et=et, shape=shape, size=size,
                                prec=et.upper(),
                                dim=shape.split(",")[0].strip()))
        with open(stem + ".bin", "wb") as fh:
            fh.write(b"\0" * bin_bytes)
        return sorted({f["rule"] for f in oi.scan_file(stem + ".xml")})

    def test_bit_widths_present(self):
        self.assertEqual(oi._BITWIDTH.get("u3"), 3)
        self.assertEqual(oi._BITWIDTH.get("u6"), 6)

    def test_u3_split_and_tight_layouts_pass(self):
        self.assertEqual(self.rules("u3", "10", 6), [])   # 3 * ceil(10/8)
        self.assertEqual(self.rules("u3", "10", 4), [])   # ceil(30/8)
        self.assertEqual(self.rules("u3", "16", 6), [])   # both layouts

    def test_u6_split_and_tight_layouts_pass(self):
        self.assertEqual(self.rules("u6", "10", 9), [])   # 3 * ceil(10/4)
        self.assertEqual(self.rules("u6", "10", 8), [])   # ceil(60/8)
        self.assertEqual(self.rules("u6", "4", 3), [])    # both layouts

    def test_declared_size_too_small(self):
        self.assertEqual(self.rules("u3", "10", 3), ["OVI005"])
        self.assertEqual(self.rules("u6", "10", 7), ["OVI005"])

    def test_bit_size_overflow(self):
        self.assertEqual(self.rules("u3", "4611686018427387904, 16", 6),
                         ["OVI004"])
        self.assertEqual(self.rules("u6", "4611686018427387904, 16", 6),
                         ["OVI004"])

    def test_version(self):
        parts = tuple(int(p) for p in oi.__version__.split("."))
        self.assertGreaterEqual(parts, (0, 1, 2))


if __name__ == "__main__":
    unittest.main()
