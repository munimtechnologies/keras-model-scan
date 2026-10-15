# SPDX-License-Identifier: Apache-2.0
# Made with AI by MV2 of Munim, Inc.
"""Tests for hf_config_injection_corpus.py.

These verify the corpus itself (structure, field placement, manifest) without
importing the scanner, so each crafted file is proven to carry exactly the
field its expected finding code depends on, the clean control carries none, and
the malformed file is genuinely unparseable.
"""
import json
import os
import tempfile
import unittest

import hf_config_injection_corpus as corpus


class TestCorpusGeneration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hfci_corpus_")
        self.manifest = corpus.write_corpus(self.tmp)

    def _load(self, filename):
        with open(os.path.join(self.tmp, filename), "r", encoding="utf-8") as fh:
            return fh.read()

    def test_all_files_plus_manifest_written(self):
        written = set(os.listdir(self.tmp))
        expected = {spec["filename"] for spec in corpus.CORPUS} | {"manifest.json"}
        self.assertEqual(written, expected)

    def test_manifest_matches_corpus_spec(self):
        self.assertEqual(self.manifest["version"], corpus.__version__)
        self.assertEqual(self.manifest["cve"], "CVE-2026-4372")
        man_names = [f["filename"] for f in self.manifest["files"]]
        spec_names = [spec["filename"] for spec in corpus.CORPUS]
        self.assertEqual(man_names, spec_names)
        for man, spec in zip(self.manifest["files"], corpus.CORPUS):
            self.assertEqual(man["expected_code"], spec["expected_code"])
            self.assertEqual(man["expected_severity"], spec["expected_severity"])
            self.assertEqual(man["trigger_fields"], spec["trigger_fields"])

    def test_counts(self):
        sev = [f["expected_severity"] for f in self.manifest["files"]]
        self.assertEqual(sev.count("HIGH"), 6)
        self.assertEqual(sev.count("INFO"), 3)
        self.assertEqual(sev.count("ERROR"), 1)
        self.assertEqual(sev.count("CLEAN"), 1)

    def test_each_trigger_field_is_actually_present(self):
        # Every HIGH/INFO file must carry exactly the fields the manifest claims,
        # located anywhere in the structure (top-level or nested).
        all_indicators = corpus.HIGH_FIELDS + corpus.INFO_FIELDS
        for spec in corpus.CORPUS:
            if not spec["trigger_fields"]:
                continue
            raw = self._load(spec["filename"])
            data = json.loads(raw)
            present = corpus.find_fields(data, all_indicators)
            self.assertEqual(
                present, sorted(spec["trigger_fields"]),
                f"{spec['filename']} should carry exactly {spec['trigger_fields']}",
            )

    def test_clean_control_has_no_indicator(self):
        data = json.loads(self._load("clean_control.json"))
        present = corpus.find_fields(data, corpus.HIGH_FIELDS + corpus.INFO_FIELDS)
        self.assertEqual(present, [])

    def test_nested_cases_are_not_top_level(self):
        # The recursion cases must hide the field below the top level, otherwise
        # they would not exercise recursion.
        for filename, field in (
            ("nested_attn_internal.json", "_attn_implementation_internal"),
            ("nested_list_experts.json", "_experts_implementation_internal"),
        ):
            data = json.loads(self._load(filename))
            self.assertNotIn(field, data, f"{filename} should hide {field} below top level")
            self.assertIn(field, corpus.find_fields(
                data, corpus.HIGH_FIELDS + corpus.INFO_FIELDS))

    def test_hubid_value_shape(self):
        data = json.loads(self._load("hubid_value.json"))
        value = data["_attn_implementation_internal"]
        self.assertEqual(value.count("/"), 1)
        owner, repo = value.split("/")
        self.assertTrue(owner and repo)

    def test_malformed_is_unparseable(self):
        raw = self._load("malformed.json")
        with self.assertRaises(json.JSONDecodeError):
            json.loads(raw)

    def test_valid_files_parse(self):
        for spec in corpus.CORPUS:
            if spec["expected_code"] == "HCI000":
                continue
            json.loads(self._load(spec["filename"]))  # must not raise

    def test_no_executable_payload(self):
        # Safety guarantee: the corpus contains only JSON data, no code.
        for spec in corpus.CORPUS:
            raw = self._load(spec["filename"])
            self.assertNotIn("import ", raw)
            self.assertNotIn("__reduce__", raw)
            self.assertNotIn("os.system", raw)


if __name__ == "__main__":
    unittest.main()
