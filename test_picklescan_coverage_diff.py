# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made with AI agents working in MV2's name.
"""Tests for picklescan_coverage_diff: pin the census so a classifier change is caught.

Expected values below are stated independently of the module's data so an error in the
classification logic (top-package split, prefix match) is caught, not silently echoed.
"""
import unittest

import picklescan_coverage_diff as pcd


# Independently-written expected partition (derived by hand from the two source files,
# both fetched 2026-10-23). If the classifier logic drifts, these assertions fail.
EXPECTED_COVERED = {
    "asyncio", "bdb", "commands", "ctypes", "numpy.f2py", "nt", "posix", "os",
    "runpy", "shutil", "socket", "subprocess", "sys", "pdb", "pickle", "pty",
    "timeit", "webbrowser",
}
EXPECTED_GAPS = {
    "aiohttp", "httplib", "numpy.testing._private.utils", "requests.api", "ssl",
    "cProfile", "distutils.file_util", "_pickle", "pip", "profile", "pydoc", "test",
    "urllib.request", "uuid", "venv", "_osx_support", "_aix_support", "_pyrepl",
}


class CensusCounts(unittest.TestCase):
    def test_total_is_36(self):
        self.assertEqual(len(pcd.PICKLESCAN_WILDCARD_UNSAFE), 36)

    def test_partition_matches_hand_derived(self):
        d = pcd.differential()
        self.assertEqual(set(d["covered"]), EXPECTED_COVERED)
        self.assertEqual(set(d["gaps"]), EXPECTED_GAPS)
        self.assertEqual(d["covered_count"], 18)
        self.assertEqual(d["gap_count"], 18)

    def test_covered_and_gaps_are_disjoint_and_complete(self):
        d = pcd.differential()
        self.assertEqual(set(d["covered"]) & set(d["gaps"]), set())
        self.assertEqual(
            set(d["covered"]) | set(d["gaps"]), set(pcd.PICKLESCAN_WILDCARD_UNSAFE)
        )


class ClassifierBehaviour(unittest.TestCase):
    def test_top_package_split(self):
        self.assertEqual(pcd.kms_top_package("asyncio.unix_events"), "asyncio")
        self.assertEqual(pcd.kms_top_package("numpy.testing._private.utils"), "numpy")
        self.assertEqual(pcd.kms_top_package("os"), "os")

    def test_submodule_bypass_resistance(self):
        # The CVE-2025-10157 class: a submodule of a dangerous package is still flagged.
        self.assertTrue(pcd.kms_covers("asyncio.unix_events"))
        self.assertTrue(pcd.kms_covers("os.path"))

    def test_f2py_prefix_exact_and_dotted(self):
        self.assertTrue(pcd.kms_covers("numpy.f2py"))
        self.assertTrue(pcd.kms_covers("numpy.f2py.crackfortran"))
        # A different numpy subpackage is NOT a gadget prefix match -> a real gap.
        self.assertFalse(pcd.kms_covers("numpy.testing._private.utils"))

    def test_known_gaps_are_gaps(self):
        for module in ("pip", "ssl", "aiohttp", "cProfile", "profile", "_pickle"):
            self.assertFalse(pcd.kms_covers(module), module)

    def test_pending_detectors_close_three_gaps(self):
        for module in ("cProfile", "profile", "pip"):
            self.assertFalse(pcd.kms_covers(module))
            self.assertTrue(pcd.kms_covers(module, include_pending=True))
        d = pcd.differential(include_pending=True)
        self.assertEqual(d["covered_count"], 21)
        self.assertEqual(d["gap_count"], 15)


class MarkdownRendering(unittest.TestCase):
    def test_table_mentions_gap_and_covered(self):
        table = pcd.markdown_table()
        self.assertIn("| `pip` | GAP |", table)
        self.assertIn("| `asyncio` | covered |", table)
        self.assertIn("18 of 36 covered, 18 gaps", table)


if __name__ == "__main__":
    unittest.main()
