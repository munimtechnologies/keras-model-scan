# Copyright 2026 MV2, Munim, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
"""Tests for jsonargparse_config_scan. Stdlib only; no network, no pip."""
import json
import os
import tempfile
import unittest

import jsonargparse_config_scan as jcs


class TestImportPath(unittest.TestCase):
    def test_dotted_paths_are_import_paths(self):
        for good in ("os.system", "my.pkg.Model", "a.b.c.D", "pickle.loads"):
            self.assertTrue(jcs.is_import_path(good), good)

    def test_non_paths_rejected(self):
        for bad in ("resnet50", "", "ViT-B-32", "plain", 3, None, "a.", ".b"):
            self.assertFalse(jcs.is_import_path(bad), repr(bad))


class TestSeverity(unittest.TestCase):
    def test_dangerous_root_is_critical(self):
        self.assertEqual(jcs._severity_for_value("subprocess.Popen"), "CRITICAL")
        self.assertEqual(jcs._severity_for_value("os.system"), "CRITICAL")
        self.assertEqual(jcs._severity_for_value("importlib.import_module"), "CRITICAL")

    def test_ordinary_class_is_high(self):
        self.assertEqual(jcs._severity_for_value("my.models.Net"), "HIGH")


class TestScanJson(unittest.TestCase):
    def test_class_path_flagged_jac001(self):
        blob = json.dumps(
            {"model": {"class_path": "my.models.Classifier", "init_args": {"lr": 1}}}
        )
        findings = jcs.scan_text(blob, "config.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "JAC001")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("/model/class_path", findings[0].location)

    def test_dangerous_class_path_is_critical(self):
        blob = json.dumps({"model": {"class_path": "os.system"}})
        findings = jcs.scan_text(blob, "config.json")
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].rule, "JAC001")

    def test_checkpoint_class_path_and_instantiator(self):
        blob = json.dumps(
            {
                "_class_path": "attacker.payload.Evil",
                "_instantiator": "builtins.exec",
            }
        )
        findings = jcs.scan_text(blob, "hparams.json")
        rules = {f.rule for f in findings}
        self.assertEqual(rules, {"JAC002", "JAC003"})
        inst = next(f for f in findings if f.rule == "JAC003")
        self.assertEqual(inst.severity, "CRITICAL")  # builtins is dangerous

    def test_nested_list_walked(self):
        blob = json.dumps(
            {"callbacks": [{"class_path": "lightning.Cb"}, {"class_path": "os.getcwd"}]}
        )
        findings = jcs.scan_text(blob, "config.json")
        self.assertEqual(len(findings), 2)
        sev = sorted(f.severity for f in findings)
        self.assertEqual(sev, ["CRITICAL", "HIGH"])

    def test_benign_config_no_findings(self):
        blob = json.dumps(
            {"model": "resnet50", "data": {"batch_size": 32}, "optimizer": "adam"}
        )
        self.assertEqual(jcs.scan_text(blob, "config.json"), [])


class TestScanYaml(unittest.TestCase):
    def test_yaml_class_path(self):
        text = "model:\n  class_path: my.pkg.Model\n  init_args:\n    lr: 0.1\n"
        findings = jcs.scan_text(text, "config.yaml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "JAC001")
        self.assertIn("line 2", findings[0].location)

    def test_yaml_quoted_and_comment(self):
        text = 'model:\n  class_path: "subprocess.run"  # nefarious\n'
        findings = jcs.scan_text(text, "config.yaml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_yaml_instantiator(self):
        text = "_instantiator: lightning.pytorch.cli.instantiate_module\n"
        findings = jcs.scan_text(text, "hparams.yaml")
        self.assertEqual(findings[0].rule, "JAC003")
        self.assertEqual(findings[0].severity, "HIGH")  # lightning root not dangerous

    def test_yaml_benign(self):
        text = "model: resnet50\nbatch_size: 32\nname: my-run\n"
        self.assertEqual(jcs.scan_text(text, "config.yaml"), [])

    def test_yaml_plain_string_not_path(self):
        text = "class_path: notadottedpath\n"
        self.assertEqual(jcs.scan_text(text, "config.yaml"), [])


class TestScanPathsAndCli(unittest.TestCase):
    def test_directory_walk_and_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bad.yaml"), "w", encoding="utf-8") as fh:
                fh.write("model:\n  class_path: os.system\n")
            with open(os.path.join(d, "ok.json"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"model": "resnet"}))
            result = jcs.scan_paths([d])
            self.assertEqual(len(result.scanned_files), 2)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].severity, "CRITICAL")

            # CLI exit code gating.
            rc = jcs.main([d, "--fail-on", "HIGH"])
            self.assertEqual(rc, 1)
            rc_json = jcs.main([d, "--json"])
            self.assertEqual(rc_json, 0)  # default fail-on NONE

    def test_clean_dir_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "ok.yaml"), "w", encoding="utf-8") as fh:
                fh.write("model: resnet50\n")
            self.assertEqual(jcs.main([d, "--fail-on", "LOW"]), 0)


if __name__ == "__main__":
    unittest.main()
