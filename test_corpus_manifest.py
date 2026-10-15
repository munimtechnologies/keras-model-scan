# Copyright 2026 Munim, Inc.
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
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file was made with AI by MV2 of Munim, Inc.
"""Self-contained tests for corpus_manifest.

These assert the manifest's *internal* consistency only - they import nothing
but corpus_manifest and the standard library, and never import the corpora or
scanners the manifest indexes. That keeps the suite runnable in isolation (the
publish sandbox copies only the committed files).
"""

import json
import re
import unittest

import corpus_manifest as cm

_SLUG = re.compile(r"^[a-z][a-z0-9_]*$")


class CorpusManifestTest(unittest.TestCase):
    def test_version_string(self):
        self.assertRegex(cm.__version__, r"^\d+\.\d+\.\d+$")

    def test_seven_rows(self):
        # One row per benign / regression corpus currently in the repo.
        self.assertEqual(len(cm.CORPORA), 7)
        self.assertEqual(len(cm.keys()), 7)

    def test_keys_unique_and_slugged(self):
        ks = cm.keys()
        self.assertEqual(len(ks), len(set(ks)), "duplicate corpus keys")
        for k in ks:
            self.assertRegex(k, _SLUG)

    def test_required_fields_present_and_typed(self):
        for row in cm.CORPORA:
            self.assertEqual(set(row.keys()), set(cm._REQUIRED_KEYS))
            for field in ("key", "title", "corpus_module", "scanner_module", "cve_map"):
                self.assertIsInstance(row[field], str)
                self.assertTrue(row[field], "empty required field: %s" % field)
            for field in ("corpus_doc", "scan_doc"):
                self.assertTrue(row[field] is None or isinstance(row[field], str))

    def test_filename_conventions(self):
        for row in cm.CORPORA:
            self.assertTrue(row["corpus_module"].endswith("_corpus.py"))
            self.assertTrue(row["scanner_module"].endswith("_scan.py"))
            if row["corpus_doc"] is not None:
                self.assertTrue(row["corpus_doc"].endswith("_CORPUS.md"))
            self.assertTrue(row["scan_doc"].endswith(".md"))

    def test_corpus_modules_unique(self):
        mods = cm.corpus_modules()
        self.assertEqual(len(mods), len(set(mods)), "a corpus module appears twice")

    def test_cve_map_is_known(self):
        for row in cm.CORPORA:
            self.assertIn(row["cve_map"], cm.CVE_MAPS)
            self.assertTrue(row["cve_map"].endswith(".json"))

    def test_no_reasserted_advisory_ids(self):
        # The manifest must not carry CVE/GHSA identifiers; those stay in the
        # authoritative maps it points to. Guard that invariant.
        blob = json.dumps(cm.as_list())
        self.assertNotRegex(blob, r"CVE-\d{4}-\d+")
        self.assertNotRegex(blob, r"GHSA-[0-9a-z]{4}")

    def test_get_roundtrip(self):
        for k in cm.keys():
            self.assertEqual(cm.get(k)["key"], k)
        with self.assertRaises(KeyError):
            cm.get("does_not_exist")

    def test_get_returns_copy(self):
        row = cm.get("gguf_cve")
        row["title"] = "mutated"
        self.assertNotEqual(cm.get("gguf_cve")["title"], "mutated")

    def test_by_cve_map_partitions(self):
        total = 0
        for name in cm.CVE_MAPS:
            total += len(cm.by_cve_map(name))
        self.assertEqual(total, len(cm.CORPORA))
        # The GGUF memory-safety family uses its own map.
        gguf_rows = cm.by_cve_map("gguf_cve_map.json")
        self.assertIn("gguf_cve", [r["key"] for r in gguf_rows])
        with self.assertRaises(KeyError):
            cm.by_cve_map("not_a_map.json")

    def test_scanner_modules_cover_every_corpus(self):
        self.assertEqual(len(cm.scanner_modules()), len(cm.CORPORA))

    def test_docs_deduped_and_sorted(self):
        d = cm.docs()
        self.assertEqual(d, sorted(d))
        self.assertEqual(len(d), len(set(d)))
        self.assertTrue(all(p.endswith(".md") for p in d))

    def test_to_json_roundtrips(self):
        parsed = json.loads(cm.to_json())
        self.assertEqual(parsed["version"], cm.__version__)
        self.assertEqual(len(parsed["corpora"]), len(cm.CORPORA))
        self.assertEqual(parsed["cve_maps"], list(cm.CVE_MAPS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
