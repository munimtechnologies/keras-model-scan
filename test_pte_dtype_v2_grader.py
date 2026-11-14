# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Checks for job pte-dtype-v2's grader, run before it is published.

1. Runs research/pte-dtype-v2/test_vendor_check.py (the corrected grader's
   unit tests). Discovery does not enter research/ (not a package), so this
   root file loads it by path.
2. Re-reads job pte-dtype-v1's recorded output
   (research/pte-dtype/vendor_check.json): the 25 entries it parsed, keyed by
   the header's own /* n */ comment instead of their position, have the same
   sizes as the candidate 0.1.1 table, and the comment numbers it never parsed
   are exactly the five wrapped entries (8, 23-26). This is the diagnosis in
   REALFILE_CHECK_PTE_DTYPE_2026-11.md, pinned. It is not a pass of v1's V1.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import importlib.util
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRADER_TESTS = os.path.join(HERE, "research", "pte-dtype-v2",
                            "test_vendor_check.py")
V1_VENDOR = os.path.join(HERE, "research", "pte-dtype", "vendor_check.json")

# Candidate executorch_pte_scan 0.1.1 table (patch_pte.py NEW_TABLE).
CANDIDATE = {0: 1, 1: 1, 2: 2, 3: 4, 4: 8, 5: 2, 6: 4, 7: 8, 8: 4, 9: 8,
             10: 16, 11: 1, 12: 1, 13: 1, 14: 4, 15: 2, 16: 1, 17: 1,
             18: 1, 19: 1, 20: 1, 21: 1, 22: 2, 23: 1, 24: 1, 25: 1,
             26: 1, 27: 2, 28: 4, 29: 8}


def _load_grader_tests():
    spec = importlib.util.spec_from_file_location(
        "pte_dtype_v2_test_vendor_check", GRADER_TESTS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class V1RecordedOutput(unittest.TestCase):

    def setUp(self):
        with open(V1_VENDOR, encoding="utf-8") as fh:
            self.rep = json.load(fh)
        self.entries = self.rep["entries"]

    def test_v1_row_is_recorded_as_failed(self):
        self.assertEqual(self.rep["V1"]["result"], "failed")

    def test_v1_parsed_25_entries_all_with_comments(self):
        self.assertEqual(len(self.entries), 25)
        self.assertTrue(all(e["comment"] is not None for e in self.entries))

    def test_sizes_keyed_by_comment_equal_the_candidate_table(self):
        for e in self.entries:
            self.assertEqual(CANDIDATE[e["comment"]], e["size"], e["name"])

    def test_unparsed_comments_are_the_wrapped_entries(self):
        seen = {e["comment"] for e in self.entries}
        self.assertEqual(sorted(set(CANDIDATE) - seen), [8, 23, 24, 25, 26])

    def test_the_shift_starts_after_complex_half(self):
        shifted = [e["name"] for e in self.entries
                   if e["comment"] != e["index"]]
        self.assertEqual(shifted[0], "ComplexFloat")
        self.assertEqual(len(shifted), 17)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(V1RecordedOutput))
    suite.addTests(loader.loadTestsFromModule(_load_grader_tests()))
    return suite
