"""Tests for hdf5_keras_lambda_scan. Fixtures are built from bytes so the suite
runs with the standard library only (no h5py, no Keras). They mimic the way a
legacy .h5 file stores the Keras config as contiguous UTF-8 text inside the
HDF5 container, which is what the static detector keys on.

Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""

import json
import unittest

import hdf5_keras_lambda_scan as h5s

SIG = b"\x89HDF\r\n\x1a\n"


def h5_blob(config, attr=b"model_config", sig_offset=0):
    """Build a minimal HDF5-looking blob: signature + attribute name + config."""
    cfg = config if isinstance(config, (bytes, bytearray)) else json.dumps(config).encode()
    return (b"\x00" * sig_offset) + SIG + (b"\x00" * 16) + attr + (b"\x00" * 4) + cfg


LAMBDA_CFG = {
    "class_name": "Functional",
    "config": {
        "layers": [
            {"class_name": "InputLayer", "config": {"name": "in"}},
            {
                "class_name": "Lambda",
                "config": {
                    "name": "lambda",
                    "function": ["4wEAAAAAAAAA", None, None],
                    "function_type": "lambda",
                },
            },
        ]
    },
}

DENSE_CFG = {
    "class_name": "Sequential",
    "config": {"layers": [{"class_name": "Dense", "config": {"units": 10}}]},
}

CUSTOM_CFG = {
    "class_name": "MyModel",
    "registered_name": "Custom>MyModel",
    "module": "my_pkg.models",
    "config": {},
}


def rules(findings):
    return {f["rule"] for f in findings}


class SignatureTests(unittest.TestCase):
    def test_detects_signature_at_zero(self):
        self.assertTrue(h5s.looks_like_hdf5(SIG + b"\x00" * 64))

    def test_detects_signature_at_512(self):
        self.assertTrue(h5s.looks_like_hdf5(b"\x00" * 512 + SIG + b"\x00" * 8))

    def test_rejects_zip_and_noise(self):
        self.assertFalse(h5s.looks_like_hdf5(b"PK\x03\x04" + b"random zip bytes"))
        self.assertFalse(h5s.looks_like_hdf5(b"\x89HDF not quite"))


class ScanTests(unittest.TestCase):
    def test_lambda_with_function_is_high(self):
        findings = h5s.scan_bytes(h5_blob(LAMBDA_CFG))
        self.assertIn("HKL001", rules(findings))
        hkl001 = [f for f in findings if f["rule"] == "HKL001"][0]
        self.assertEqual(hkl001["severity"], "high")
        self.assertEqual(hkl001["cve"], "CVE-2025-9905")
        self.assertEqual(hkl001["cwe"], "CWE-913")

    def test_lambda_at_offset_512_still_detected(self):
        findings = h5s.scan_bytes(h5_blob(LAMBDA_CFG, sig_offset=512))
        self.assertIn("HKL001", rules(findings))

    def test_benign_dense_model_has_no_high(self):
        findings = h5s.scan_bytes(h5_blob(DENSE_CFG))
        self.assertNotIn("HKL001", rules(findings))
        self.assertNotIn("HKL002", rules(findings))
        # It is still a legacy HDF5 Keras model, so the format advisory fires.
        self.assertIn("HKL003", rules(findings))
        self.assertTrue(all(f["severity"] == "info" for f in findings))

    def test_custom_registered_object_is_medium(self):
        findings = h5s.scan_bytes(h5_blob(CUSTOM_CFG))
        self.assertIn("HKL002", rules(findings))
        hkl002 = [f for f in findings if f["rule"] == "HKL002"][0]
        self.assertEqual(hkl002["severity"], "medium")
        self.assertEqual(hkl002["cwe"], "CWE-502")

    def test_training_config_counts_as_keras_model(self):
        findings = h5s.scan_bytes(h5_blob(DENSE_CFG, attr=b"training_config"))
        self.assertIn("HKL003", rules(findings))

    def test_non_keras_hdf5_is_silent(self):
        # HDF5 container with no Keras config at all -> no findings.
        self.assertEqual(h5s.scan_bytes(SIG + b"\x00" * 128), [])

    def test_not_hdf5_is_silent(self):
        self.assertEqual(h5s.scan_bytes(b"PK\x03\x04" + json.dumps(LAMBDA_CFG).encode()), [])

    def test_null_registered_name_not_flagged(self):
        cfg = {"class_name": "Sequential", "registered_name": None,
               "config": {"layers": [{"class_name": "Dense", "config": {}}]}}
        findings = h5s.scan_bytes(h5_blob(cfg))
        self.assertNotIn("HKL002", rules(findings))

    def test_core_keras_module_not_flagged(self):
        cfg = {"class_name": "Sequential", "module": "keras.layers",
               "config": {"layers": [{"class_name": "Dense", "config": {}}]}}
        findings = h5s.scan_bytes(h5_blob(cfg))
        self.assertNotIn("HKL002", rules(findings))


class FormatTests(unittest.TestCase):
    def test_main_usage_without_args(self):
        self.assertEqual(h5s.main([]), 2)


if __name__ == "__main__":
    unittest.main()
