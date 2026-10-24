# Copyright 2026 Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working in the name of MV2 of Munim, Inc.
"""Invariant tests for the `.keras` deserialization-time I/O blind spot demonstrator.

These pin the difference between the current allowlist-only rule (KMS001) and the
proposed version-aware rule (KMS006): KMS006 must flag the in-namespace get_file-class
gadget, the CVE-2025-12058 vocabulary-path layer, and the keras_hub tokenizers that read
a vocabulary/proto/merges file at deserialization, while leaving genuinely benign
`keras.*`/`keras_hub.*` nodes - including inline-vocabulary and saved (None) configs -
untouched. The test imports only the standalone module, so it runs with no repository
dependencies.
"""

import unittest

import keras_deserialization_io_blindspot as m


class TestCurrentRuleHasTheBlindSpot(unittest.TestCase):
    def test_get_file_function_node_scans_clean_today(self):
        node = {"class_name": "function", "module": "keras.utils",
                "config": "keras.utils.get_file"}
        self.assertFalse(m.classify_current(node).flagged)

    def test_vocabulary_path_layer_scans_clean_today(self):
        node = {"class_name": "StringLookup", "module": "keras.layers",
                "config": {"vocabulary": "/etc/passwd"}}
        self.assertFalse(m.classify_current(node).flagged)

    def test_keras_hub_tokenizer_path_scans_clean_today(self):
        node = {"class_name": "WordPieceTokenizer",
                "module": "keras_hub.src.tokenizers.word_piece_tokenizer",
                "config": {"vocabulary": "/etc/passwd"}}
        self.assertFalse(m.classify_current(node).flagged)


class TestProposedRuleClosesIt(unittest.TestCase):
    def test_flags_get_file_as_kms006(self):
        node = {"class_name": "function", "module": "keras.utils",
                "config": "keras.utils.get_file"}
        v = m.classify_proposed(node)
        self.assertTrue(v.flagged)
        self.assertEqual(v.rule, "KMS006")

    def test_flags_stringlookup_vocabulary_path_as_kms006(self):
        node = {"class_name": "StringLookup", "module": "keras.layers",
                "config": {"vocabulary": "http://169.254.169.254/latest/meta-data/"}}
        v = m.classify_proposed(node)
        self.assertTrue(v.flagged)
        self.assertEqual(v.rule, "KMS006")

    def test_flags_integerlookup_vocabulary_path(self):
        node = {"class_name": "IntegerLookup", "module": "keras.layers",
                "config": {"vocabulary": "/home/user/.ssh/id_rsa"}}
        self.assertTrue(m.classify_proposed(node).flagged)

    def test_every_loading_api_is_flagged(self):
        for api in m.LOADING_APIS:
            module, name = api.rsplit(".", 1)
            node = {"class_name": "function", "module": module, "config": api}
            self.assertTrue(m.classify_proposed(node).flagged, api)


class TestKerasHubTokenizerFamily(unittest.TestCase):
    def test_wordpiece_vocabulary_path_flagged_as_kms006(self):
        node = {"class_name": "WordPieceTokenizer",
                "module": "keras_hub.src.tokenizers.word_piece_tokenizer",
                "config": {"vocabulary": "/etc/passwd"}}
        v = m.classify_proposed(node)
        self.assertTrue(v.flagged)
        self.assertEqual(v.rule, "KMS006")

    def test_sentencepiece_proto_path_flagged(self):
        node = {"class_name": "SentencePieceTokenizer",
                "module": "keras_hub.src.tokenizers.sentence_piece_tokenizer",
                "config": {"proto": "http://169.254.169.254/latest/meta-data/"}}
        self.assertTrue(m.classify_proposed(node).flagged)

    def test_bytepair_merges_path_flagged_even_when_vocab_none(self):
        node = {"class_name": "BytePairTokenizer",
                "module": "keras_hub.src.tokenizers.byte_pair_tokenizer",
                "config": {"vocabulary": None, "merges": "/etc/shadow"}}
        v = m.classify_proposed(node)
        self.assertTrue(v.flagged)
        self.assertEqual(v.rule, "KMS006")

    def test_bytepair_vocabulary_path_flagged(self):
        node = {"class_name": "BytePairTokenizer",
                "module": "keras_hub.src.tokenizers.byte_pair_tokenizer",
                "config": {"vocabulary": "/etc/passwd", "merges": None}}
        self.assertTrue(m.classify_proposed(node).flagged)

    def test_every_hub_tokenizer_with_a_string_file_arg_is_flagged(self):
        for cls, keys in m.HUB_IO_TOKENIZER_FILE_KEYS.items():
            for key in keys:
                node = {"class_name": cls, "module": "keras_hub.tokenizers",
                        "config": {key: "/tmp/evil"}}
                self.assertTrue(m.classify_proposed(node).flagged, f"{cls}.{key}")


class TestNoFalsePositives(unittest.TestCase):
    def test_benign_dense_layer(self):
        node = {"class_name": "Dense", "module": "keras.layers",
                "config": {"units": 64}}
        self.assertFalse(m.classify_proposed(node).flagged)

    def test_stringlookup_with_inline_vocabulary_list(self):
        node = {"class_name": "StringLookup", "module": "keras.layers",
                "config": {"vocabulary": ["a", "b", "c"]}}
        self.assertFalse(m.classify_proposed(node).flagged)

    def test_stringlookup_with_null_vocabulary(self):
        node = {"class_name": "StringLookup", "module": "keras.layers",
                "config": {"vocabulary": None}}
        self.assertFalse(m.classify_proposed(node).flagged)

    def test_empty_string_vocabulary_not_flagged(self):
        node = {"class_name": "StringLookup", "module": "keras.layers",
                "config": {"vocabulary": "   "}}
        self.assertFalse(m.classify_proposed(node).flagged)

    def test_saved_hub_tokenizer_with_none_fields_not_flagged(self):
        # A legitimately saved keras_hub tokenizer stores None (asset on disk).
        node = {"class_name": "WordPieceTokenizer",
                "module": "keras_hub.src.tokenizers.word_piece_tokenizer",
                "config": {"vocabulary": None}}
        self.assertFalse(m.classify_proposed(node).flagged)

    def test_bytepair_with_both_fields_none_not_flagged(self):
        node = {"class_name": "BytePairTokenizer",
                "module": "keras_hub.src.tokenizers.byte_pair_tokenizer",
                "config": {"vocabulary": None, "merges": None}}
        self.assertFalse(m.classify_proposed(node).flagged)


class TestKMS001StillFires(unittest.TestCase):
    def test_non_keras_namespace_still_high(self):
        node = {"class_name": "function", "module": "os", "config": "os.system"}
        v = m.classify_proposed(node)
        self.assertTrue(v.flagged)
        self.assertEqual(v.rule, "KMS001")


class TestDenylistProvenance(unittest.TestCase):
    def test_loading_apis_subset_of_union(self):
        self.assertTrue(m.LOADING_APIS <= m.KERAS_NONMODELING_DENYLIST)
        self.assertTrue(m.NON_MODELING_APIS <= m.KERAS_NONMODELING_DENYLIST)

    def test_get_file_present_in_both_denylists(self):
        self.assertIn("keras.utils.get_file", m.LOADING_APIS)
        self.assertIn("keras.utils.get_file", m.NON_MODELING_APIS)

    def test_denylist_sizes_are_sane(self):
        # LOADING_APIS was quoted verbatim from upstream v3.11.0 (7 entries).
        # NON_MODELING_APIS was transcribed from master on 2026-10-24; we assert a
        # lower bound and key membership rather than a brittle exact count, since the
        # set is read, not executed, here.
        self.assertEqual(len(m.LOADING_APIS), 7)
        self.assertGreaterEqual(len(m.NON_MODELING_APIS), 28)
        for critical in (
            "keras.utils.get_file",
            "keras.models.load_model",
            "keras.config.enable_unsafe_deserialization",
            "keras.utils.save_img",
        ):
            self.assertIn(critical, m.NON_MODELING_APIS, critical)

    def test_hub_tokenizer_map_matches_source_review(self):
        # Verified live on keras-team/keras-hub master, 2026-10-24: these are the file
        # arguments each tokenizer reads from a string path at construction time.
        self.assertEqual(
            m.HUB_IO_TOKENIZER_FILE_KEYS["WordPieceTokenizer"], ("vocabulary",))
        self.assertEqual(
            m.HUB_IO_TOKENIZER_FILE_KEYS["SentencePieceTokenizer"], ("proto",))
        self.assertEqual(
            m.HUB_IO_TOKENIZER_FILE_KEYS["BytePairTokenizer"], ("vocabulary", "merges"))


if __name__ == "__main__":
    unittest.main()
