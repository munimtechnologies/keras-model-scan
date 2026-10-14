"""Tests for keras-model-scan.

These build small, benign, synthetic .keras-shaped zip archives whose config.json
contains only the *marker strings* of the known CVE patterns (e.g. the class_name
value "__lambda__", or a module string "subprocess"). No archive here contains real
marshalled bytecode, a real payload, or anything executable: the tests never load a
model and the scanner never executes anything. They only check that the static
pattern detection fires and does not false-positive on a clean model.
"""

import io
import json
import os
import tempfile
import zipfile
import unittest

import keras_model_scan as kms


def _make_keras(config: dict, extra_members=None) -> str:
    """Write a throwaway .keras-shaped zip to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".keras")
    os.close(fd)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.x"}))
        for name, data in (extra_members or {}).items():
            zf.writestr(name, data)
    return path


def _rules(findings):
    return {f.rule for f in findings}


CLEAN_MODEL = {
    "class_name": "Sequential",
    "module": "keras.models",
    "config": {
        "layers": [
            {"class_name": "Dense", "module": "keras.layers",
             "config": {"units": 8, "activation": "relu"}},
            {"class_name": "function", "module": "keras.activations",
             "config": "softmax"},
        ]
    },
}


class ScanConfigTests(unittest.TestCase):
    def test_clean_model_has_no_findings(self):
        self.assertEqual(kms.scan_config(json.dumps(CLEAN_MODEL)), [])

    def test_subprocess_gadget_flagged_high(self):
        # The CVE-2025-1550 shape: a function node resolving a non-keras callable.
        cfg = {"class_name": "function", "config": "Popen", "module": "subprocess",
               "inbound_nodes": [{"args": [["touch", "/tmp/1337"]], "kwargs": {}}]}
        findings = kms.scan_config(json.dumps(cfg))
        self.assertIn("KMS001", _rules(findings))
        hit = next(f for f in findings if f.rule == "KMS001")
        self.assertEqual(hit.severity, "HIGH")
        self.assertIn("subprocess", hit.detail)
        self.assertIn("inbound_nodes args", hit.detail)

    def test_os_system_gadget_flagged(self):
        cfg = {"class_name": "function", "config": "system", "module": "os"}
        self.assertIn("KMS001", _rules(kms.scan_config(json.dumps(cfg))))

    def test_allowlisted_module_not_flagged(self):
        cfg = {"class_name": "function", "config": "relu", "module": "keras.activations"}
        self.assertNotIn("KMS001", _rules(kms.scan_config(json.dumps(cfg))))

    def test_lambda_marker_flagged(self):
        cfg = {"class_name": "__lambda__", "config": {"code": "<marshalled>"}}
        findings = kms.scan_config(json.dumps(cfg))
        self.assertIn("KMS002", _rules(findings))

    def test_enable_unsafe_deserialization_critical(self):
        cfg = {"class_name": "Sequential", "note": "enable_unsafe_deserialization"}
        findings = kms.scan_config(json.dumps(cfg))
        hit = next(f for f in findings if f.rule == "KMS003")
        self.assertEqual(hit.severity, "CRITICAL")

    def test_tfsmlayer_flagged(self):
        cfg = {"class_name": "TFSMLayer", "module": "keras.layers",
               "config": {"filepath": "./saved_model"}}
        self.assertIn("KMS004", _rules(kms.scan_config(json.dumps(cfg))))

    def test_invalid_json_reported(self):
        self.assertIn("KMS000", _rules(kms.scan_config("{not valid")))


class ScanFileTests(unittest.TestCase):
    def test_clean_archive(self):
        path = _make_keras(CLEAN_MODEL)
        try:
            self.assertEqual(kms.scan_file(path), [])
        finally:
            os.remove(path)

    def test_malicious_marker_archive(self):
        cfg = {"class_name": "function", "config": "Popen", "module": "subprocess"}
        path = _make_keras(cfg)
        try:
            findings = kms.scan_file(path)
            self.assertIn("KMS001", _rules(findings))
        finally:
            os.remove(path)

    def test_zip_slip_member_flagged(self):
        path = _make_keras(CLEAN_MODEL, extra_members={"../evil.txt": "x"})
        try:
            findings = kms.scan_file(path)
            self.assertIn("KMS005", _rules(findings))
            self.assertEqual(
                next(f for f in findings if f.rule == "KMS005").severity, "HIGH")
        finally:
            os.remove(path)

    def test_absolute_path_member_flagged(self):
        path = _make_keras(CLEAN_MODEL, extra_members={"/etc/evil": "x"})
        try:
            self.assertIn("KMS005", _rules(kms.scan_file(path)))
        finally:
            os.remove(path)

    def test_raw_config_json_file(self):
        cfg = {"class_name": "function", "config": "Popen", "module": "subprocess"}
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        try:
            self.assertIn("KMS001", _rules(kms.scan_file(path)))
        finally:
            os.remove(path)


class CliTests(unittest.TestCase):
    def test_exit_code_clean(self):
        path = _make_keras(CLEAN_MODEL)
        try:
            self.assertEqual(kms.main([path]), 0)
        finally:
            os.remove(path)

    def test_exit_code_flagged(self):
        cfg = {"class_name": "function", "config": "Popen", "module": "subprocess"}
        path = _make_keras(cfg)
        try:
            self.assertEqual(kms.main([path]), 1)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
