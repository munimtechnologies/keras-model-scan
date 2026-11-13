#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PTE005 empty-segment calibration of executorch_pte_scan.

ExecuTorch's writer lists an empty constant segment (offsets [0], size 0)
and writes no eh00 header when a program has no constants. Programs are
hand-built with the helpers in test_executorch_pte_scan.py (honest
structures; nothing is loaded or executed). Version-agnostic: the version
pin lives in test_executorch_pte_scan.py.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import unittest

import executorch_pte_scan as pte
from test_executorch_pte_scan import _call, _delegate, _plan, _pte, _rules


class Pte005EmptySegmentTests(unittest.TestCase):

    def test_writer_layout_without_constants_is_clean(self):
        # serialize_pte_binary output for a program with no constants.
        data = _pte(segments=[(0, 0)], constant=(0, [0]))
        self.assertEqual(pte.scan_bytes(data), [])

    def test_empty_segment_without_constant_table_is_clean(self):
        self.assertEqual(pte.scan_bytes(_pte(segments=[(0, 0)])), [])

    def test_several_empty_segments_are_clean(self):
        self.assertEqual(pte.scan_bytes(_pte(segments=[(0, 0), (0, 0)])), [])

    def test_inline_delegate_with_empty_segment(self):
        # Shape of the census Ethos-U files: inline blob + empty segment.
        data = _pte(segments=[(0, 0)], constant=(0, [0]),
                    inline=[b"\0" * 16],
                    plan=_plan(delegates=[_delegate(b"EthosUBackend")],
                               instructions=[_call(2, 0, [0, 1])]))
        self.assertEqual(_rules(pte.scan_bytes(data)), ["PTE003"])

    def test_non_empty_segment_still_needs_a_header(self):
        findings = pte.scan_bytes(_pte(segments=[(0, 32)]))
        self.assertEqual(_rules(findings), ["PTE005"])
        self.assertIn("1 segments", findings[0]["evidence"])

    def test_one_non_empty_among_empty_still_flagged(self):
        findings = pte.scan_bytes(_pte(segments=[(0, 0), (0, 8)]))
        self.assertEqual(_rules(findings), ["PTE005"])
        self.assertIn("2 segments", findings[0]["evidence"])

    def test_rule_table_unchanged(self):
        self.assertEqual(pte._RULES["PTE005"], ("medium", "CWE-693"))


if __name__ == "__main__":
    unittest.main()
