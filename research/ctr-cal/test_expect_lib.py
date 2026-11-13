# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the ctr-cal-v1 expectation spec (plain config shapes)."""
import unittest

import expect_lib as e


class ExpectLibTest(unittest.TestCase):
    def test_no_key(self):
        self.assertEqual(e.expected_rules({"model_type": "llama"}), [])

    def test_not_lightglue_is_ctr003(self):
        doc = {"model_type": "neobert", "trust_remote_code": True,
               "sub": {"trust_remote_code": False}}
        self.assertEqual(e.expected_rules(doc), ["CTR003", "CTR003"])

    def test_lightglue_truthy_and_not(self):
        doc = {"model_type": "LightGlue", "trust_remote_code": "on",
               "x": [{"trust_remote_code": 0}]}
        self.assertEqual(e.expected_rules(doc), ["CTR001", "CTR002"])

    def test_lightglue_named_only_in_subconfig(self):
        doc = {"model_type": "wrapper", "m": {"model_type": "lightglue"},
               "trust_remote_code": True}
        self.assertEqual(e.expected_rules(doc), ["CTR001"])

    def test_truthy(self):
        for v in (True, "true", " YES ", 1, 2.5):
            self.assertTrue(e.truthy(v), v)
        for v in (False, "no", "", 0, 0.0, None, [], {}):
            self.assertFalse(e.truthy(v), v)

    def test_levels_and_cves(self):
        self.assertEqual(e.EXPECTED_LEVEL["CTR003"], "LOW")
        self.assertEqual(e.EXPECTED_CVE["CTR003"], "")
        self.assertEqual(e.EXPECTED_CVE["CTR001"], "CVE-2026-5241")


if __name__ == "__main__":
    unittest.main()
