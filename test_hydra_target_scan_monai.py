# Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""Tests for HYD006: the MONAI bundle ``$`` Python-eval expression detector in
hydra_target_scan (CVE-2026-100840 / GHSA-873f-pvrv-4x83).

Self-contained: imports only hydra_target_scan and unittest, and asserts on the
detector's behaviour, not on any security fact of the underlying CVE. All payload
strings here are inert and are only ever read as data; nothing is evaluated.
"""

import unittest

import hydra_target_scan as h


def ids(findings):
    return [f.id for f in findings]


def sev_of(findings, fid):
    return [f.severity for f in findings if f.id == fid]


class TestMonaiExprJson(unittest.TestCase):

    def test_high_dangerous_dollar_expr(self):
        obj = {"evil": "$__import__('os').system('id')", "_target_": "x.Y"}
        fs = h.scan_json_obj(obj, "inference.json")
        self.assertIn("HYD006", ids(fs))
        self.assertIn("HIGH", sev_of(fs, "HYD006"))

    def test_medium_dollar_expr_with_target_marker(self):
        obj = {"net": {"_target_": "monai.networks.nets.UNet"}, "lr": "$print(42)"}
        fs = h.scan_json_obj(obj, "train.json")
        self.assertIn("MEDIUM", sev_of(fs, "HYD006"))
        self.assertNotIn("HIGH", sev_of(fs, "HYD006"))

    def test_medium_dollar_expr_with_monai_underscore_marker(self):
        # No _target_, but a MONAI underscore key marks this as a bundle config.
        obj = {"step": {"_requires_": "@setup", "value": "$1 + 2"}}
        fs = h.scan_json_obj(obj, "metadata.json")
        self.assertIn("MEDIUM", sev_of(fs, "HYD006"))

    def test_benign_dollar_without_marker_is_skipped(self):
        obj = {"price": "$5.00", "label": "$total"}
        fs = h.scan_json_obj(obj, "config.json")
        self.assertNotIn("HYD006", ids(fs))

    def test_omegaconf_interpolation_is_ignored(self):
        obj = {"_target_": "x.Y", "dir": "${hydra:runtime.cwd}", "e": "${env:HOME}"}
        fs = h.scan_json_obj(obj, "config.json")
        self.assertNotIn("HYD006", ids(fs))

    def test_dollar_expr_in_list_element(self):
        obj = {"_requires_": ["$__import__('subprocess').Popen('x')"],
               "_target_": "x.Y"}
        fs = h.scan_json_obj(obj, "inference.json")
        self.assertIn("HYD006", ids(fs))
        self.assertIn("HIGH", sev_of(fs, "HYD006"))

    def test_plain_import_is_medium_not_high(self):
        obj = {"_target_": "x.Y", "m": "$from torchvision.models import resnet18"}
        fs = h.scan_json_obj(obj, "train.json")
        self.assertIn("MEDIUM", sev_of(fs, "HYD006"))
        self.assertNotIn("HIGH", sev_of(fs, "HYD006"))

    def test_existing_target_rule_still_fires(self):
        obj = {"a": {"_target_": "os.system"}}
        fs = h.scan_json_obj(obj, "config.json")
        self.assertIn("HYD001", ids(fs))


class TestMonaiExprYaml(unittest.TestCase):

    def test_yaml_high_dangerous(self):
        text = "_target_: x.Y\ncmd: \"$os.system('id')\"\n"
        fs = h.scan_yaml_text(text, "bundle.yaml")
        self.assertIn("HYD006", ids(fs))
        self.assertIn("HIGH", sev_of(fs, "HYD006"))

    def test_yaml_medium_needs_marker(self):
        text = "net:\n  _target_: monai.nets.UNet\nval: \"$print(1)\"\n"
        fs = h.scan_yaml_text(text, "bundle.yaml")
        self.assertIn("MEDIUM", sev_of(fs, "HYD006"))

    def test_yaml_benign_dollar_no_marker_skipped(self):
        text = "amount: \"$5.00\"\nname: foo\n"
        fs = h.scan_yaml_text(text, "data.yaml")
        self.assertNotIn("HYD006", ids(fs))

    def test_yaml_list_item_dollar(self):
        text = "_requires_:\n  - \"$exec('x')\"\n_target_: x.Y\n"
        fs = h.scan_yaml_text(text, "bundle.yaml")
        self.assertIn("HIGH", sev_of(fs, "HYD006"))


if __name__ == "__main__":
    unittest.main()
