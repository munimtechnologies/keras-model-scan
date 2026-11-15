# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for executorch_pte_scan's dtype table (0.1.1).

The runtime accepts every ScalarType from 0 to 29 (isValid in
runtime/core/exec_aten/util/scalar_type_util.h) and sizes each with sizeof()
over ET_FORALL_SCALAR_TYPES (runtime/core/portable_type/scalar_type.h).
Programs are built by hand with the helpers in test_executorch_pte_scan.py;
nothing is loaded or executed.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import unittest

import executorch_pte_scan as pte
from test_executorch_pte_scan import _pte, _plan, _planned, _rules, _tensor

# sizeof() of each runtime ScalarType: Byte, Char, Short, Int, Long, Half,
# Float, Double, ComplexHalf, ComplexFloat, ComplexDouble, Bool, QInt8,
# QUInt8, QInt32, BFloat16, QUInt4x2, QUInt2x4, Bits1x8, Bits2x4, Bits4x2,
# Bits8, Bits16, Float8_e5m2, Float8_e4m3fn, Float8_e5m2fnuz,
# Float8_e4m3fnuz, UInt16, UInt32, UInt64.
RUNTIME_SIZES = dict(enumerate([1, 1, 2, 4, 8, 2, 4, 8, 4, 8, 16, 1, 1, 1, 4,
                                2, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 4, 8]))


class RuntimeDtypes(unittest.TestCase):

    def test_table_matches_the_runtime_list(self):
        self.assertEqual(len(RUNTIME_SIZES), 30)
        self.assertEqual(pte._ELEMENT_SIZE, RUNTIME_SIZES)

    def test_every_runtime_dtype_is_accepted(self):
        for dtype in sorted(RUNTIME_SIZES):
            values = [_planned(0, dims=(2,), dtype=dtype), _planned(32)]
            findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
            self.assertEqual(findings, [], "dtype %d" % dtype)

    def test_complex_float_is_sized_and_checked(self):
        # ComplexFloat is 8 bytes: a 2x3 tensor takes 48 bytes.
        fits = [_planned(0, dtype=9), _planned(48, dims=(4,))]
        self.assertEqual(pte.scan_bytes(_pte(plan=_plan(values=fits))), [])
        past = [_planned(32, dtype=9), _planned(0, dims=(2,))]
        findings = pte.scan_bytes(_pte(plan=_plan(values=past)))
        self.assertEqual(_rules(findings), ["PTE002"])
        self.assertIn("48 bytes at offset 32", findings[0]["evidence"])

    def test_complex_double_is_sixteen_bytes(self):
        values = [_planned(0, dtype=10), _planned(0, dims=(1,))]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE002"])
        self.assertIn("96 bytes at offset 0", findings[0]["evidence"])

    def test_complex_half_is_four_bytes(self):
        values = [_planned(0, dims=(16,), dtype=8), _planned(0, dims=(1,))]
        self.assertEqual(pte.scan_bytes(_pte(plan=_plan(values=values))), [])
        values = [_planned(4, dims=(16,), dtype=8), _planned(0, dims=(1,))]
        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
        self.assertEqual(_rules(findings), ["PTE002"])

    def test_values_outside_the_runtime_list(self):
        for dtype in (30, 31, 64, 127, -1, -128):
            values = [_tensor(dtype=dtype), _tensor()]
            findings = pte.scan_bytes(_pte(plan=_plan(values=values)))
            self.assertEqual(_rules(findings), ["PTE004"], "dtype %d" % dtype)
            self.assertIn("scalar_type %d" % dtype, findings[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
