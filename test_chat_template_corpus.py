#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Made with AI by MV2 of Munim, Inc.
"""Tests for chat_template_corpus.py.

These verify the corpus WITHOUT importing the scanner: every check here is
independent of chat_template_scan.py, so the corpus stands on its own as a
labelled regression dataset. jinja2 is never imported and nothing is rendered.
"""
import json
import os
import tempfile
import unittest

import chat_template_corpus as corpus

ALL_CODES = {"CT000", "CT001", "CT002", "CT003", "CT004", "CT005", "CT006"}


class TestCorpusGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.manifest = corpus.write_corpus(self.tmp)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _read(self, name: str) -> str:
        with open(os.path.join(self.tmp, name), encoding="utf-8") as fh:
            return fh.read()

    def test_all_files_plus_manifest_written(self) -> None:
        for entry in corpus.CORPUS:
            self.assertTrue(
                os.path.exists(os.path.join(self.tmp, entry["filename"])),
                entry["filename"])
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "manifest.json")))

    def test_manifest_matches_corpus_spec(self) -> None:
        self.assertEqual(self.manifest["version"], corpus.__version__)
        self.assertEqual(self.manifest["cve"], "CVE-2024-34359")
        by_name = {f["filename"]: f for f in self.manifest["files"]}
        for entry in corpus.CORPUS:
            m = by_name[entry["filename"]]
            self.assertEqual(m["expected_code"], entry["expected_code"])
            self.assertEqual(m["expected_severity"], entry["expected_severity"])
            self.assertEqual(m["trigger"], entry["trigger"])

    def test_counts(self) -> None:
        sev = [e["expected_severity"] for e in corpus.CORPUS]
        self.assertEqual(sev.count("HIGH"), 3)
        self.assertEqual(sev.count("MEDIUM"), 3)
        self.assertEqual(sev.count("LOW"), 1)
        self.assertEqual(sev.count("CLEAN"), 2)

    def test_every_finding_code_has_a_fixture(self) -> None:
        codes = {e["expected_code"] for e in corpus.CORPUS if e["expected_code"]}
        self.assertEqual(codes, ALL_CODES)

    def test_trigger_present_in_flagged_fixtures(self) -> None:
        # Independent substring check: the token the manifest claims is really
        # in the written file (no scanner involved).
        for entry in corpus.CORPUS:
            if entry["trigger"]:
                self.assertIn(entry["trigger"], self._read(entry["filename"]),
                              entry["filename"])

    def test_clean_controls_have_no_gadget(self) -> None:
        for entry in corpus.CORPUS:
            if entry["expected_severity"] != "CLEAN":
                continue
            text = self._read(entry["filename"])
            for token in corpus.GADGET_SUBSTRS:
                self.assertNotIn(token, text, "{} in {}".format(
                    token, entry["filename"]))

    def test_no_destructive_payload_anywhere(self) -> None:
        # Risky fixtures carry detector tokens but must never be a real exploit
        # or a destructive command.
        for entry in corpus.CORPUS:
            text = self._read(entry["filename"])
            for token in corpus.DESTRUCTIVE_SUBSTRS:
                self.assertNotIn(token, text, "{} in {}".format(
                    token, entry["filename"]))

    def test_malformed_is_unparseable(self) -> None:
        with self.assertRaises(json.JSONDecodeError):
            json.loads(self._read("malformed_tokenizer_config.json"))

    def test_valid_json_files_parse(self) -> None:
        for entry in corpus.CORPUS:
            name = entry["filename"]
            if not name.endswith(".json") or name.startswith("malformed"):
                continue
            json.loads(self._read(name))  # must not raise

    def test_jinja_sidecars_are_nonempty_text(self) -> None:
        for entry in corpus.CORPUS:
            if entry["filename"].endswith(".jinja"):
                self.assertTrue(self._read(entry["filename"]).strip())

    def test_named_template_list_carrier_shape(self) -> None:
        # The two list-carrier fixtures must deserialize to a list of
        # {name, template} objects.
        for name in ("ssti_global_tokenizer_config.json",
                     "web_global_tokenizer_config.json"):
            obj = json.loads(self._read(name))
            self.assertIsInstance(obj["chat_template"], list)
            for item in obj["chat_template"]:
                self.assertIn("name", item)
                self.assertIn("template", item)


if __name__ == "__main__":
    unittest.main()
