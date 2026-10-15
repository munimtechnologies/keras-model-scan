#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Part of model-file-scan (munimtechnologies/keras-model-scan).
# Made with AI by MV2 of Munim, Inc.
"""Self-contained tests for archive_bomb_scan.py + archive_bomb_corpus.py.

Imports only the two new modules and the standard library. The corpus files are
tiny, so the scanner is run with LOW thresholds (a few KiB / a thousand entries)
that the demonstrators trip exactly as a production-scale bomb would trip the
realistic defaults.
"""
import os
import tempfile
import unittest

import archive_bomb_corpus
import archive_bomb_scan

# Low thresholds so the harmless corpus exercises each detection path.
TEST_CONFIG = {
    "per_entry_ratio": 50.0,
    "min_entry_bytes": 4096,
    "total_uncompressed": 100_000,
    "max_entries": 400,
    "flag_nested": True,
}


class ArchiveBombCorpusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abomb-")
        self.manifest = archive_bomb_corpus.write_corpus(self.tmp)

    def _codes(self, filename):
        path = os.path.join(self.tmp, filename)
        findings = archive_bomb_scan.scan_file(path, TEST_CONFIG)
        return {f["code"] for f in findings}

    def test_corpus_is_small_and_safe(self):
        # Nothing in the corpus should be large on disk.
        for name, meta in self.manifest.items():
            self.assertLess(meta["bytes"], 100 * 1024, name)

    def test_each_file_trips_its_expected_codes(self):
        for name, (_data, expected) in archive_bomb_corpus.build_corpus().items():
            found = self._codes(name)
            for code in expected:
                self.assertIn(code, found, f"{name} missing {code} (found {found})")

    def test_clean_control_has_no_findings(self):
        self.assertEqual(self._codes("clean_model.zip"), set())

    def test_high_ratio_is_high_severity(self):
        path = os.path.join(self.tmp, "abomb_high_ratio.zip")
        findings = archive_bomb_scan.scan_file(path, TEST_CONFIG)
        abz001 = [f for f in findings if f["code"] == "ABZ001"]
        self.assertTrue(abz001)
        self.assertEqual(abz001[0]["severity"], "HIGH")
        self.assertEqual(abz001[0]["cwe"], "CWE-409")

    def test_many_entries_is_abz003_only(self):
        self.assertEqual(self._codes("abomb_many_entries.zip"), {"ABZ003"})

    def test_nested_archive_flagged(self):
        self.assertIn("ABZ004", self._codes("abomb_nested.zip"))


class ScannerBehaviourTest(unittest.TestCase):
    def test_non_zip_file_is_skipped(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".pt", delete=False) as fh:
            fh.write(b"not a zip at all")
            path = fh.name
        try:
            self.assertEqual(archive_bomb_scan.scan_file(path), [])
        finally:
            os.unlink(path)

    def test_default_thresholds_ignore_tiny_files(self):
        # With realistic defaults the tiny corpus must not raise ABZ001/ABZ002
        # (a 64 KiB demonstrator is far below the 1 MiB / 1 GiB production gates).
        tmp = tempfile.mkdtemp(prefix="abomb-def-")
        archive_bomb_corpus.write_corpus(tmp)
        path = os.path.join(tmp, "abomb_high_ratio.zip")
        codes = {f["code"] for f in archive_bomb_scan.scan_file(path)}
        self.assertNotIn("ABZ001", codes)
        self.assertNotIn("ABZ002", codes)

    def test_fail_on_exit_codes(self):
        tmp = tempfile.mkdtemp(prefix="abomb-cli-")
        archive_bomb_corpus.write_corpus(tmp)
        bomb = os.path.join(tmp, "abomb_high_ratio.zip")
        clean = os.path.join(tmp, "clean_model.zip")
        # Low per-entry ratio so the demonstrator trips HIGH; clean stays quiet.
        rc_bomb = archive_bomb_scan.main(
            [bomb, "--per-entry-ratio", "50", "--min-entry-bytes", "4096",
             "--fail-on", "HIGH"])
        rc_clean = archive_bomb_scan.main(
            [clean, "--per-entry-ratio", "50", "--min-entry-bytes", "4096",
             "--fail-on", "HIGH"])
        self.assertEqual(rc_bomb, 1)
        self.assertEqual(rc_clean, 0)


if __name__ == "__main__":
    unittest.main()
