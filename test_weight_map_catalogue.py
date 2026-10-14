# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# test_weight_map_catalogue.py -- integrity checks for weight_map_traversal.json,
# the catalogue of model-loader path-traversal advisories that this project's
# safetensors_index_scan.py detects. Standard library only.
#
# This work was made with AI, by MV2 of Munim, Inc.

from __future__ import annotations

import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "weight_map_traversal.json")

# The rule IDs the scanner actually emits for the weight_map class, plus the
# sentinel "related" for sibling sinks (ONNX external-data, chat-template) that
# share the root cause but are not a weight_map *.index.json file.
KNOWN_RULES = {
    "STI001", "STI002", "STI003", "STI004", "STI005", "STI006",
    "STI007", "STI008", "STI009", "STI010", "related",
}

IDENTIFIER_TYPES = {"CVE", "GHSA", "PR", "issue"}
STATUSES = {"fixed", "open", "declined", "reported"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$")


class CatalogueStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DATA, "r", encoding="utf-8") as fh:
            cls.doc = json.load(fh)

    def test_top_level_keys(self):
        for key in ("dataset", "version", "description", "license",
                    "compiled_on", "detector", "verified_advisories",
                    "community_reports"):
            self.assertIn(key, self.doc, f"missing top-level key {key!r}")

    def test_license_is_cc_by(self):
        # Data may be CC BY 4.0; code in this repo is Apache-2.0.
        self.assertEqual(self.doc["license"], "CC-BY-4.0")

    def test_version_is_semver(self):
        self.assertRegex(self.doc["version"], r"^\d+\.\d+\.\d+$")

    def _all_entries(self):
        return list(self.doc["verified_advisories"]) + list(
            self.doc["community_reports"])

    def test_entries_present(self):
        self.assertGreaterEqual(len(self.doc["verified_advisories"]), 3)
        self.assertGreaterEqual(len(self._all_entries()), 6)

    def test_required_fields(self):
        for e in self._all_entries():
            for key in ("project", "identifier", "file_format",
                        "sink_function", "root_cause", "status",
                        "source_url", "maps_to_rules", "verified"):
                self.assertIn(key, e,
                              f"{e.get('project')}: missing field {key!r}")
            self.assertTrue(e["project"])
            self.assertTrue(e["root_cause"])
            self.assertTrue(e["verified"])

    def test_statuses_are_known(self):
        for e in self._all_entries():
            self.assertIn(e["status"], STATUSES,
                          f"{e['project']}: bad status {e['status']!r}")

    def test_rules_are_known(self):
        for e in self._all_entries():
            self.assertTrue(e["maps_to_rules"],
                            f"{e['project']}: empty maps_to_rules")
            for rule in e["maps_to_rules"]:
                self.assertIn(rule, KNOWN_RULES,
                              f"{e['project']}: unknown rule {rule!r}")

    def test_source_urls_are_https(self):
        for e in self._all_entries():
            self.assertTrue(e["source_url"].startswith("https://"),
                            f"{e['project']}: non-https source_url")

    def test_identifier_types_and_formats(self):
        for e in self.doc["verified_advisories"]:
            self.assertIn("identifier_type", e)
            self.assertIn(e["identifier_type"], IDENTIFIER_TYPES,
                          f"{e['project']}: bad identifier_type")
            ident, itype = e["identifier"], e["identifier_type"]
            if itype == "CVE":
                self.assertRegex(ident, CVE_RE,
                                 f"{e['project']}: malformed CVE {ident!r}")
            elif itype == "GHSA":
                self.assertRegex(ident, GHSA_RE,
                                 f"{e['project']}: malformed GHSA {ident!r}")

    def test_declined_entry_is_honest(self):
        # The huggingface_hub case was declined by the maintainer; it must stay
        # labelled 'declined', not presented as a confirmed vulnerability.
        declined = [e for e in self.doc["verified_advisories"]
                    if e["status"] == "declined"]
        self.assertTrue(declined, "expected the honest 'declined' boundary case")
        for e in declined:
            text = (e["fix_ref"] + " " + e["verified"]).lower()
            self.assertTrue("closed" in text or "won't" in text or
                            "declined" in text,
                            f"{e['project']}: declined entry must say so plainly")

    def test_no_duplicate_identifiers(self):
        idents = [e["identifier"] for e in self._all_entries()]
        self.assertEqual(len(idents), len(set(idents)),
                         "duplicate identifier in catalogue")


if __name__ == "__main__":
    unittest.main(verbosity=2)
