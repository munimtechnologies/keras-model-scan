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

    def _scan_modules(self, subdir):
        return scan.scan_file(corpus.modules_fixture_path(self.tmp, subdir))

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

    # ---- pyannote-style pipeline/preprocessor class references (HYD004) ----

    def test_pyannote_clean_is_low_only(self):
        f = self._scan("pyannote_clean.yaml")
        self.assertEqual(ids(f), {"HYD004"})
        self.assertEqual(severities(f), {"LOW"})
        path = os.path.join(self.tmp, "pyannote_clean.yaml")
        self.assertEqual(scan.main([path]), 0)

    def test_pyannote_popen_is_high(self):
        f = self._scan("pyannote_popen.yaml")
        self.assertEqual(ids(f), {"HYD004"})
        self.assertEqual(severities(f), {"HIGH"})
        self.assertIn("'subprocess.Popen'", f[0].message)  # quotes and comment stripped
        self.assertNotIn("#", f[0].message)

    def test_pyannote_foreign_is_medium(self):
        # name follows a deeper params block, so the indent stack must pop back
        f = self._scan("pyannote_foreign.yaml")
        self.assertEqual(ids(f), {"HYD004"})
        self.assertEqual(severities(f), {"MEDIUM"})

    def test_pyannote_preprocessor_is_high(self):
        f = self._scan("pyannote_preprocessor.yaml")
        self.assertEqual(ids(f), {"HYD004"})
        self.assertEqual(severities(f), {"LOW", "HIGH"})
        self.assertTrue(any("preprocessors.audio.name" in x.path for x in f))

    def test_unrelated_name_keys_are_ignored(self):
        self.assertEqual(self._scan("dataset.yaml"), [])

    def test_pipeline_name_in_json_is_high(self):
        f = self._scan("pipeline_json_config.json")
        self.assertEqual(ids(f), {"HYD004"})
        self.assertEqual(severities(f), {"HIGH"})

    # ---- sentence-transformers modules.json type (HYD005, CVE-2026-68770) ----

    def test_modules_clean_is_low_only(self):
        f = self._scan_modules("st_clean")
        self.assertEqual(ids(f), {"HYD005"})
        self.assertEqual(severities(f), {"LOW"})
        self.assertEqual(scan.main([corpus.modules_fixture_path(self.tmp, "st_clean")]), 0)

    def test_modules_foreign_is_medium(self):
        f = self._scan_modules("st_foreign")
        self.assertEqual(ids(f), {"HYD005"})
        self.assertIn("MEDIUM", severities(f))
        self.assertNotIn("HIGH", severities(f))
        self.assertTrue(any("CVE-2026-68770" in x.message for x in f))

    def test_modules_exec_is_high(self):
        f = self._scan_modules("st_exec")
        self.assertEqual(ids(f), {"HYD005"})
        self.assertEqual(severities(f), {"HIGH"})
        self.assertIn("'subprocess.Popen'", f[0].message)
        self.assertEqual(
            scan.main([corpus.modules_fixture_path(self.tmp, "st_exec"), "--fail-on", "HIGH"]), 1)

    def test_type_key_outside_modules_json_is_ignored(self):
        # a 'type' key in a normal config file must not raise HYD005
        f = self._scan("type_key_config.json")
        self.assertEqual(f, [])

    def test_every_fixture_matches_its_expected_id(self):
        fixtures = dict(corpus.JSON_FIXTURES)
        fixtures.update(corpus.YAML_FIXTURES)
        for name, (_content, expect, _note) in fixtures.items():
            got = ids(self._scan(name))
            if expect is None:
                self.assertEqual(got, set(), name)
            else:
                self.assertIn(expect, got, name)
        for subdir, (_content, expect, _note) in corpus.MODULES_FIXTURES.items():
            got = ids(self._scan_modules(subdir))
            self.assertIn(expect, got, subdir)


if __name__ == "__main__":
    unittest.main()
