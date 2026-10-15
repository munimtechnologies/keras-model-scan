# SPDX-License-Identifier: Apache-2.0
"""Tests for onnx_external_data_key_corpus.py (CVE-2026-34445 key corpus).

Self-contained: imports only the corpus module and the standard library. The
corpus is verified by re-parsing the generated protobuf files with the module's
own parse_external_data_keys helper - it does not depend on the scanner.

Made with AI by MV2 of Munim, Inc.
"""
import json
import os
import tempfile
import unittest

import onnx_external_data_key_corpus as corpus


class TestKeyCorpus(unittest.TestCase):
    def test_build_corpus_matches_cases(self):
        built = corpus.build_corpus()
        self.assertEqual(set(built), {c.filename for c in corpus.CASES})
        for fn, data in built.items():
            self.assertIsInstance(data, bytes)
            self.assertGreater(len(data), 0, f"{fn} is empty")

    def test_every_file_is_parseable(self):
        # parse_external_data_keys must not raise on any generated file.
        for fn, data in corpus.build_corpus().items():
            entries = corpus.parse_external_data_keys(data)
            self.assertIsInstance(entries, list)
            self.assertGreaterEqual(len(entries), 1,
                                    f"{fn}: no external_data entry found")

    def test_malicious_files_carry_an_unexpected_key(self):
        built = corpus.build_corpus()
        for case in corpus.CASES:
            if not case.malicious:
                continue
            entries = corpus.parse_external_data_keys(built[case.filename])
            keys = [e["key"] for e in entries]
            unexpected = [k for k in keys if k not in corpus.ALLOWED_KEYS]
            self.assertTrue(
                unexpected,
                f"{case.filename}: expected an unexpected key, got {keys}")
            # Every key the Case declared unexpected must actually be present.
            for k in case.unexpected_keys:
                self.assertIn(k, keys, f"{case.filename}: missing key {k!r}")

    def test_clean_control_has_only_recognised_keys(self):
        built = corpus.build_corpus()
        clean = [c for c in corpus.CASES if not c.malicious]
        self.assertTrue(clean, "corpus must include a clean control")
        for case in clean:
            entries = corpus.parse_external_data_keys(built[case.filename])
            keys = [e["key"] for e in entries]
            self.assertTrue(keys, f"{case.filename}: no keys parsed")
            for k in keys:
                self.assertIn(
                    k, corpus.ALLOWED_KEYS,
                    f"{case.filename}: unexpected key {k!r} in clean control")

    def test_nested_case_is_found_under_a_node_attribute(self):
        built = corpus.build_corpus()
        nested = built["nested_node_attr.onnx"]
        entries = corpus.parse_external_data_keys(nested)
        paths = [e["path"] for e in entries]
        self.assertTrue(
            any("node[" in p and ".t" in p for p in paths),
            f"nested case not found under a node attribute: {paths}")
        keys = [e["key"] for e in entries]
        self.assertIn("__class__", keys)

    def test_case_variant_is_not_the_allowed_key(self):
        # 'Location' must be treated as distinct from 'location'.
        self.assertNotIn("Location", corpus.ALLOWED_KEYS)
        entries = corpus.parse_external_data_keys(
            corpus.build_corpus()["case_variant.onnx"])
        self.assertIn("Location", [e["key"] for e in entries])

    def test_manifest_is_consistent(self):
        man = corpus.manifest()
        self.assertEqual(len(man), len(corpus.CASES))
        for row, case in zip(man, corpus.CASES):
            self.assertEqual(row["file"], case.filename)
            self.assertEqual(row["malicious"], case.malicious)
            self.assertEqual(row["unexpected_keys"], case.unexpected_keys)
            if case.malicious:
                self.assertEqual(row["rules"], ["OEK001"])
            else:
                self.assertEqual(row["rules"], [])

    def test_allowed_keys_match_the_spec(self):
        self.assertEqual(
            corpus.ALLOWED_KEYS,
            frozenset({"location", "offset", "length", "checksum", "basepath"}))

    def test_write_corpus_round_trips_to_disk(self):
        with tempfile.TemporaryDirectory() as d:
            written = corpus.write_corpus(d)
            self.assertIn("manifest.json", written)
            for case in corpus.CASES:
                path = os.path.join(d, case.filename)
                self.assertTrue(os.path.exists(path), f"missing {case.filename}")
                with open(path, "rb") as fh:
                    self.assertGreater(len(fh.read()), 0)
            with open(os.path.join(d, "manifest.json"), encoding="utf-8") as fh:
                meta = json.load(fh)
            self.assertEqual(meta["cve"], "CVE-2026-34445")
            self.assertEqual(len(meta["cases"]), len(corpus.CASES))


if __name__ == "__main__":
    unittest.main(verbosity=2)
