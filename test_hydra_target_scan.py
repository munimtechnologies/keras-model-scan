# SPDX-License-Identifier: Apache-2.0
# Part of munimtechnologies/keras-model-scan by MV2, Munim, Inc.
# This file was made with AI.
"""Regression tests for hydra_target_scan.py against the generated corpus."""
import os
import tempfile
import unittest

import hydra_target_corpus as corpus
import hydra_target_scan as scan


def ids(findings):
    return {f.id for f in findings}


def severities(findings):
    return {f.severity for f in findings}


class TestHydraTargetScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="hydra_corpus_")
        corpus.write_corpus(cls.tmp)

    def _scan(self, name):
        return scan.scan_file(os.path.join(self.tmp, name))

    def test_clean_has_no_findings(self):
        self.assertEqual(self._scan("clean_config.json"), [])

    def test_exec_target_is_high(self):
        f = self._scan("exec_config.json")
        self.assertIn("HYD001", ids(f))
        self.assertIn("HIGH", severities(f))

    def test_subprocess_target_is_high(self):
        self.assertIn("HYD001", ids(self._scan("subprocess_config.json")))

    def test_os_system_nested_is_high(self):
        # tests the recursive walk reaches a _target_ inside a list
        f = self._scan("ossystem_nested_config.json")
        self.assertIn("HYD001", ids(f))

    def test_generic_target_is_medium_not_high(self):
        f = self._scan("generic_target_config.json")
        self.assertIn("HYD002", ids(f))
        self.assertNotIn("HIGH", severities(f))
        self.assertIn("MEDIUM", severities(f))

    def test_safe_optimizer_is_low(self):
        f = self._scan("safe_optim_config.json")
        self.assertIn("HYD002", ids(f))
        self.assertNotIn("HIGH", severities(f))
        self.assertNotIn("MEDIUM", severities(f))
        self.assertIn("LOW", severities(f))

    def test_helper_only_is_info(self):
        f = self._scan("helper_only_config.json")
        self.assertEqual(ids(f), {"HYD003"})

    def test_yaml_os_system_is_high(self):
        f = self._scan("train.yaml")
        self.assertIn("HYD001", ids(f))

    def test_yaml_generic_is_medium(self):
        f = self._scan("model.yaml")
        self.assertIn("HYD002", ids(f))
        self.assertNotIn("HIGH", severities(f))

    def test_exit_code_high_trips_fail_on_high(self):
        path = os.path.join(self.tmp, "exec_config.json")
        self.assertEqual(scan.main([path, "--fail-on", "HIGH"]), 1)

    def test_exit_code_clean_is_zero(self):
        path = os.path.join(self.tmp, "clean_config.json")
        self.assertEqual(scan.main([path, "--fail-on", "HIGH"]), 0)

    def test_exit_code_medium_below_default_threshold(self):
        path = os.path.join(self.tmp, "generic_target_config.json")
        self.assertEqual(scan.main([path, "--fail-on", "HIGH"]), 0)
        self.assertEqual(scan.main([path, "--fail-on", "MEDIUM"]), 1)

    def test_malformed_json_is_error(self):
        p = os.path.join(self.tmp, "broken_config.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")
        f = scan.scan_file(p)
        self.assertIn("HYD000", ids(f))
        self.assertEqual(scan.main([p]), 1)  # ERROR trips non-zero exit


if __name__ == "__main__":
    unittest.main()
