# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Regression tests for advisory identifiers cited by the scanners and docs.
# v0.5.0 corrected two mistakes: the picklescan STACK_GLOBAL bypass advisory
# GHSA-9gvj-pp9x-gcfr is CVE-2025-71325 (it was cited as CVE-2025-71345), and
# PKL001 (generic pickle RCE) is tagged CWE-502 instead of CVE-2025-1550, which
# is a Keras Lambda-deserialization CVE. v0.6.0 added the fp8/C64/sub-byte
# safetensors dtypes to DTYPE_SIZES/SUBBYTE_BITS. v0.7.0 added the sharded-index
# path-safety scanner (safetensors_index_scan). Made with AI by MV2 of Munim, Inc.

import os
import unittest

import model_file_scan
import pickle_model_scan
import safetensors_index_scan
import safetensors_scan

HERE = os.path.dirname(os.path.abspath(__file__))


def _read(name):
    path = os.path.join(HERE, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class AdvisoryIds(unittest.TestCase):
    def test_wrong_bypass_cve_is_gone(self):
        for name in ("pickle_model_scan.py", "PICKLE_SCAN.md",
                     "MODEL_FILE_SCAN.md"):
            text = _read(name)
            if text is None:
                continue
            self.assertNotIn("CVE-2025-71345", text, name)

    def test_bypass_cve_is_correct(self):
        self.assertIn("CVE-2025-71325", pickle_model_scan.__doc__)
        self.assertIn("GHSA-9gvj-pp9x-gcfr", pickle_model_scan.__doc__)

    def test_pickle_scanner_does_not_cite_keras_cve(self):
        self.assertNotIn("CVE-2025-1550", _read("pickle_model_scan.py"))

    def test_pkl001_is_tagged_cwe_502(self):
        # Opcode stream: PROTO 2, GLOBAL 'os system', EMPTY_TUPLE, REDUCE, STOP.
        # Only pickletools.genops reads it; it is never unpickled.
        data = b"\x80\x02cos\nsystem\n)R."
        findings = pickle_model_scan.scan_pickle_bytes(data, "fixture")
        pkl001 = [f for f in findings if f.rule == "PKL001"]
        self.assertEqual(len(pkl001), 1)
        self.assertEqual(pkl001[0].cve, "CWE-502")


class Licence(unittest.TestCase):
    def test_sources_say_apache(self):
        for mod in (model_file_scan, pickle_model_scan):
            self.assertIn("Apache-2.0", mod.__doc__)
            self.assertNotIn("MIT", mod.__doc__)
        self.assertIn("Apache-2.0", _read("safetensors_scan.py"))
        self.assertIn("Apache-2.0", _read("safetensors_index_scan.py"))

    def test_versions(self):
        self.assertEqual(model_file_scan.__version__, "0.7.0")
        self.assertEqual(safetensors_scan.__version__, "0.3.0")
        self.assertEqual(safetensors_index_scan.__version__, "0.1.0")


class SafetensorsDtypes(unittest.TestCase):
    def test_fp8_and_complex_are_whole_byte_known(self):
        for dt, size in (("F8_E4M3", 1), ("F8_E5M2", 1), ("F8_E8M0", 1),
                         ("F8_E4M3FNUZ", 1), ("F8_E5M2FNUZ", 1), ("C64", 8)):
            self.assertIn(dt, safetensors_scan.DTYPE_SIZES)
            self.assertEqual(safetensors_scan.DTYPE_SIZES[dt], size)

    def test_subbyte_dtypes_recognised(self):
        for dt in ("F4", "F6_E2M3", "F6_E3M2"):
            self.assertTrue(safetensors_scan._is_known_dtype(dt))
            self.assertNotIn(dt, safetensors_scan.DTYPE_SIZES)


class IndexScannerRouting(unittest.TestCase):
    def test_index_json_routes_to_sti(self):
        self.assertEqual(
            model_file_scan.route("model.safetensors.index.json"), "sti")
        self.assertEqual(
            model_file_scan.route("pytorch_model.bin.index.json"), "sti")

    def test_plain_json_still_routes_to_keras(self):
        self.assertEqual(model_file_scan.route("config.json"), "keras")
        self.assertEqual(model_file_scan.route("arch.json"), "keras")


if __name__ == "__main__":
    unittest.main()
