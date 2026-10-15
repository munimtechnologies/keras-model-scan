"""Tests for chat_template_scan.

Self-contained: imports only chat_template_scan and the standard library. No
Jinja2 and no model framework are installed or imported; the scanner is static,
so the "malicious" templates below are inert strings that are never rendered.
"""

import json
import os
import tempfile
import unittest

import chat_template_scan as cts


# A realistic benign chat template in the style of current Llama / Qwen / Mistral
# tokenizer_config.json files: a system-role check, a namespace accumulator, a
# message loop and a generation-prompt guard. None of this must be flagged.
BENIGN_TEMPLATE = (
    "{{- bos_token }}"
    "{%- set ns = namespace(found=false) %}"
    "{%- for message in messages %}"
    "{%- if message['role'] == 'system' %}"
    "{{- '<<SYS>>\\n' + message['content'] + '\\n<</SYS>>\\n\\n' }}"
    "{%- elif message['role'] == 'user' %}"
    "{{- '[INST] ' + message['content'] + ' [/INST]' }}"
    "{%- else %}"
    "{{- ' ' + message['content'] + ' ' + eos_token }}"
    "{%- endif %}"
    "{%- endfor %}"
    "{%- if add_generation_prompt %}{{- '' }}{%- endif %}"
)

# Classic Jinja SSTI payloads documented in the public advisories, as inert text.
PAYLOAD_DUNDER = (
    "{{ ''.__class__.__mro__[1].__subclasses__() }}"
)
PAYLOAD_CYCLER = (
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}"
)
PAYLOAD_OS_SYSTEM = (
    "{% set x = namespace() %}{{ x.update({'a': 1}) }} os.system('id')"
)
PAYLOAD_ATTR = (
    "{{ ().__class__|attr('foo') }}"
)
PAYLOAD_GETATTR = (
    "{{ getattr(obj, 'bar') }}"
)
PAYLOAD_REQUEST = (
    "{{ request.application.__globals__ }}"
)
PAYLOAD_IMPORT = (
    "{% import 'evil.jinja' as evil %}{{ evil.run() }}"
)


class ScanStringTests(unittest.TestCase):
    def _codes(self, template):
        return {f.code for f in cts.scan_template_string(template, "test", "t")}

    def test_benign_template_is_clean(self):
        findings = cts.scan_template_string(BENIGN_TEMPLATE, "test", "t")
        self.assertEqual(findings, [], msg=[f.as_dict() for f in findings])

    def test_namespace_alone_is_not_flagged(self):
        # ``namespace`` is a legitimate Jinja builtin used by real templates and
        # must not trip CT002.
        self.assertEqual(
            self._codes("{% set n = namespace(x=0) %}{{ n.x }}"), set())

    def test_system_role_word_is_not_flagged(self):
        # The word "system" as a role must not match the os.system() rule.
        self.assertNotIn(
            "CT003", self._codes("{% if role == 'system' %}hi{% endif %}"))

    def test_dunder_payload(self):
        self.assertIn("CT001", self._codes(PAYLOAD_DUNDER))

    def test_cycler_payload_flags_global_and_dunder(self):
        codes = self._codes(PAYLOAD_CYCLER)
        self.assertIn("CT002", codes)
        self.assertIn("CT001", codes)
        self.assertIn("CT003", codes)  # popen(

    def test_os_system_payload(self):
        self.assertIn("CT003", self._codes(PAYLOAD_OS_SYSTEM))

    def test_attr_filter_payload(self):
        self.assertIn("CT004", self._codes(PAYLOAD_ATTR))

    def test_getattr_payload(self):
        self.assertIn("CT004", self._codes(PAYLOAD_GETATTR))

    def test_request_global_payload(self):
        self.assertIn("CT005", self._codes(PAYLOAD_REQUEST))

    def test_import_tag_payload(self):
        self.assertIn("CT006", self._codes(PAYLOAD_IMPORT))

    def test_empty_and_non_string(self):
        self.assertEqual(cts.scan_template_string("", "c", "s"), [])
        self.assertEqual(cts.scan_template_string(None, "c", "s"), [])


class TokenizerConfigTests(unittest.TestCase):
    def _write(self, obj):
        fd, path = tempfile.mkstemp(suffix="tokenizer_config.json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    def test_string_chat_template(self):
        path = self._write({"chat_template": PAYLOAD_DUNDER})
        try:
            # scan_tokenizer_config reads the field regardless of file name
            findings = cts.scan_tokenizer_config(path)
        finally:
            os.remove(path)
        self.assertTrue(any(f.code == "CT001" for f in findings))

    def test_named_template_list(self):
        path = self._write({"chat_template": [
            {"name": "default", "template": BENIGN_TEMPLATE},
            {"name": "tool_use", "template": PAYLOAD_CYCLER},
        ]})
        try:
            findings = cts.scan_tokenizer_config(path)
        finally:
            os.remove(path)
        self.assertTrue(any(f.code == "CT002" for f in findings))

    def test_benign_config_is_clean(self):
        path = self._write({"chat_template": BENIGN_TEMPLATE,
                            "model_max_length": 4096})
        try:
            findings = cts.scan_tokenizer_config(path)
        finally:
            os.remove(path)
        self.assertEqual(findings, [])

    def test_no_chat_template_key(self):
        path = self._write({"model_max_length": 4096})
        try:
            self.assertEqual(cts.scan_tokenizer_config(path), [])
        finally:
            os.remove(path)


class PathAndSidecarTests(unittest.TestCase):
    def test_directory_walk_and_sidecar(self):
        d = tempfile.mkdtemp()
        try:
            cfg = os.path.join(d, "tokenizer_config.json")
            with open(cfg, "w", encoding="utf-8") as fh:
                json.dump({"chat_template": BENIGN_TEMPLATE}, fh)
            sidecar = os.path.join(d, "chat_template.jinja")
            with open(sidecar, "w", encoding="utf-8") as fh:
                fh.write(PAYLOAD_OS_SYSTEM)
            findings = cts.scan_path(d)
        finally:
            for name in os.listdir(d):
                os.remove(os.path.join(d, name))
            os.rmdir(d)
        self.assertTrue(any(f.code == "CT003" for f in findings))
        self.assertTrue(any(f.carrier == "jinja-sidecar" for f in findings))

    def test_unrelated_file_ignored(self):
        fd, path = tempfile.mkstemp(suffix="model.safetensors")
        os.close(fd)
        try:
            self.assertEqual(cts.scan_path(path), [])
        finally:
            os.remove(path)


class CliTests(unittest.TestCase):
    def test_fail_on_high_returns_one(self):
        d = tempfile.mkdtemp()
        try:
            cfg = os.path.join(d, "tokenizer_config.json")
            with open(cfg, "w", encoding="utf-8") as fh:
                json.dump({"chat_template": PAYLOAD_DUNDER}, fh)
            rc = cts.main([d, "--fail-on", "HIGH", "--json"])
        finally:
            for name in os.listdir(d):
                os.remove(os.path.join(d, name))
            os.rmdir(d)
        self.assertEqual(rc, 1)

    def test_clean_returns_zero(self):
        d = tempfile.mkdtemp()
        try:
            cfg = os.path.join(d, "tokenizer_config.json")
            with open(cfg, "w", encoding="utf-8") as fh:
                json.dump({"chat_template": BENIGN_TEMPLATE}, fh)
            rc = cts.main([d, "--fail-on", "LOW"])
        finally:
            for name in os.listdir(d):
                os.remove(os.path.join(d, name))
            os.rmdir(d)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
