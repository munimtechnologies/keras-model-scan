# SPDX-License-Identifier: Apache-2.0
# Part of keras-model-scan. Made with AI by MV2 of Munim, Inc.
"""Self-contained tests for gguf_chat_template_corpus.

Imports ONLY the new corpus module plus the standard library. It never renders a
template, never imports jinja2, and never imports the scanner under test, so it
runs in a sandbox holding only the committed files.
"""

import json
import os
import tempfile
import unittest

import gguf_chat_template_corpus as corpus

# Representative triggers the scanner family keys on, per finding code. A flagged
# fixture's chat-template text must contain at least one trigger for its code.
_TRIGGERS = {
    "CT001": ("__class__", "__globals__", "__subclasses__"),
    "CT002": ("cycler", "lipsum", "joiner"),
    "CT003": ("os.", "subprocess", "popen", "system(", "eval(", "exec("),
    "CT004": ("|attr(", "getattr("),
    "CT005": ("request", "config", "session"),
    "CT006": ("import", "include", "extends"),
}

# Any benign-trigger token that must NOT appear in a CLEAN fixture's templates.
_ALL_TRIGGERS = tuple(t for toks in _TRIGGERS.values() for t in toks)


class GgufChatTemplateCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.out = cls._tmp.name
        cls.manifest = corpus.build_corpus(cls.out)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_manifest_shape(self):
        m = self.manifest
        self.assertEqual(m["license"], "CC BY 4.0")
        self.assertEqual(m["version"], "0.21.0")
        self.assertIn("CVE-2024-34359", m["cve_reference"])
        self.assertEqual(m["counts"]["total"], len(m["fixtures"]))
        self.assertGreaterEqual(m["counts"]["benign"], 2)
        self.assertGreaterEqual(m["counts"]["flagged"], 6)
        self.assertEqual(m["counts"]["malformed"], 1)
        # manifest.json is on disk and matches
        with open(os.path.join(self.out, "manifest.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["counts"], m["counts"])

    def test_files_exist_and_hash(self):
        import hashlib
        for e in self.manifest["fixtures"]:
            path = os.path.join(self.out, e["filename"])
            self.assertTrue(os.path.isfile(path), e["filename"])
            with open(path, "rb") as f:
                data = f.read()
            self.assertEqual(len(data), e["bytes"], e["filename"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), e["sha256"], e["filename"])

    def test_severity_mapping(self):
        for e in self.manifest["fixtures"]:
            self.assertEqual(e["severity"], corpus._SEVERITY[e["code"]], e["filename"])

    def test_no_unsafe_tokens_anywhere(self):
        """No fixture may contain an exploit-completing or destructive token."""
        for e in self.manifest["fixtures"]:
            with open(os.path.join(self.out, e["filename"]), "rb") as f:
                blob = f.read().decode("utf-8", "replace")
            for tok in corpus.UNSAFE_TOKENS:
                self.assertNotIn(tok, blob, "%s in %s" % (tok, e["filename"]))

    def test_oscall_uses_only_harmless_id(self):
        md = corpus.read_gguf_metadata(os.path.join(self.out, "oscall.gguf"))
        tmpl = md["tokenizer.chat_template"]
        self.assertIn("popen('id')", tmpl)
        for cmd in ("rm", "cat", "wget", "curl", "nc ", "bash"):
            self.assertNotIn(cmd, tmpl)

    def test_benign_fixtures_have_no_triggers(self):
        for e in self.manifest["fixtures"]:
            if e["status"] != "benign":
                continue
            md = corpus.read_gguf_metadata(os.path.join(self.out, e["filename"]))
            for key in corpus.template_keys(md):
                tmpl = md[key]
                for tok in _ALL_TRIGGERS:
                    self.assertNotIn(tok, tmpl, "%s in benign %s/%s" % (tok, e["filename"], key))

    def test_flagged_fixtures_carry_their_trigger(self):
        for e in self.manifest["fixtures"]:
            if e["status"] != "flagged":
                continue
            md = corpus.read_gguf_metadata(os.path.join(self.out, e["filename"]))
            joined = "".join(md[k] for k in corpus.template_keys(md))
            triggers = _TRIGGERS[e["code"]]
            self.assertTrue(
                any(t in joined for t in triggers),
                "no %s trigger in %s" % (e["code"], e["filename"]),
            )

    def test_benign_namespace_control(self):
        """A legitimate namespace(...) call must appear in a benign fixture."""
        md = corpus.read_gguf_metadata(os.path.join(self.out, "clean_namespace_multi.gguf"))
        self.assertIn("namespace(", md["tokenizer.chat_template"])

    def test_malformed_is_unreadable(self):
        path = os.path.join(self.out, "malformed_truncated.gguf")
        with open(path, "rb") as f:
            head = f.read(4)
        self.assertEqual(head, corpus.GGUF_MAGIC)  # still looks like a .gguf
        with self.assertRaises(corpus.GGUFReadError):
            corpus.read_gguf_metadata(path)

    def test_round_trip_reader_writer(self):
        meta = {
            "general.architecture": "llama",
            "tokenizer.chat_template": "{{ messages }}",
            "tokenizer.chat_template.tool_use": "{{ tools }}",
        }
        path = os.path.join(self.out, "_roundtrip.gguf")
        corpus.write_gguf(path, meta)
        self.assertEqual(corpus.read_gguf_metadata(path), meta)
        self.assertEqual(
            corpus.template_keys(meta),
            ["tokenizer.chat_template", "tokenizer.chat_template.tool_use"],
        )

    def test_named_template_path(self):
        md = corpus.read_gguf_metadata(os.path.join(self.out, "named_template_ssti.gguf"))
        self.assertIn("tokenizer.chat_template.tool_use", md)
        self.assertIn("__class__", md["tokenizer.chat_template.tool_use"])
        self.assertNotIn("__class__", md["tokenizer.chat_template"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
