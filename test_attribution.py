# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Regression tests for advisory identifiers cited by the scanners and docs.
# v0.5.0 corrected two mistakes: the picklescan STACK_GLOBAL bypass advisory
# GHSA-9gvj-pp9x-gcfr is CVE-2025-71325 (it was cited as CVE-2025-71345), and
# PKL001 (generic pickle RCE) is tagged CWE-502 instead of CVE-2025-1550, which
# is a Keras Lambda-deserialization CVE. Made with AI by MV2 of Munim, Inc.

import os
import unittest

import model_file_scan
import pickle_model_scan
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

    def test_versions(self):
        self.assertEqual(model_file_scan.__version__, "0.5.0")
        self.assertEqual(safetensors_scan.__version__, "0.2.0")


if __name__ == "__main__":
    unittest.main()
