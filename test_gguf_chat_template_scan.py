"""Tests for gguf_chat_template_scan.

Self-contained: imports only gguf_chat_template_scan and the standard library.
No jinja2 and no model framework are installed or imported; the scanner is
static, so the "malicious" templates below are inert strings that are never
rendered. A small in-memory GGUF writer builds spec-compliant v3 metadata so
the reader is exercised against real GGUF byte layout, not a mock.

Made with AI by MV2 of Munim, Inc. SPDX-License-Identifier: Apache-2.0
"""

import os
import struct
import tempfile
import unittest

import gguf_chat_template_scan as g


# --- A realistic benign chat template (Llama / Qwen / Mistral style). ---------
BENIGN_TEMPLATE = (
    "{{- bos_token }}"
    "{% for message in messages %}"
    "{{ '<|' + message['role'] + '|>\n' + message['content'] + eos_token }}"
    "{% endfor %}"
    "{% if add_generation_prompt %}{{ '<|assistant|>\n' }}{% endif %}"
)

# A second benign template that checks the system role and uses a namespace -
# none of this must be flagged (role == 'system' must NOT trip the os/system rule).
BENIGN_TEMPLATE_2 = (
    "{%- set ns = namespace(found=false) %}"
    "{%- for m in messages %}"
    "{%- if m['role'] == 'system' %}{{ m['content'] }}{%- endif %}"
    "{%- endfor %}"
)

# --- Inert, never-rendered malicious markers, one per finding code. -----------
# None is a complete working exploit: the OS-call marker uses the harmless,
# read-only placeholder 'id' and omits any __globals__/__subclasses__ walk.
MAL = {
    "dunder": "{{ ''.__class__.__base__ }}",       # CT001
    "builtin_global": "{{ lipsum.__globals__ }}",  # CT002 (+ CT001)
    "os_call": "{{ os.popen('id') }}",             # CT003
    "attr_bypass": "{{ ()|attr('foo') }}",         # CT004
    "web_global": "{{ request }}",                 # CT005
    "include_tag": "{% include 'x' %}",            # CT006
}

# Tokens that would indicate a destructive or exploit-completing payload. The
# corpus must contain none of these - the fixtures demonstrate detection only.
_FORBIDDEN = (
    "rm -rf", "rmtree", "unlink", "shutil", "/etc/passwd", "DROP TABLE",
    ".read()", ".communicate(", "> /dev", "format(",
)


# ---------------------------------------------------------------------------
# Minimal spec-compliant GGUF v3 writer (little-endian) used only by the tests.
# ---------------------------------------------------------------------------
def _s(val):  # gguf_string: uint64 length + utf-8 bytes
    vb = val.encode("utf-8")
    return struct.pack("<Q", len(vb)) + vb


def _kv_string(key, val):
    return _s(key) + struct.pack("<I", 8) + _s(val)


def _kv_u32(key, n):
    return _s(key) + struct.pack("<I", 4) + struct.pack("<I", n)


def _kv_array_string(key, items):
    body = struct.pack("<I", 8) + struct.pack("<Q", len(items))  # elem type STRING, len
    for it in items:
        body += _s(it)
    return _s(key) + struct.pack("<I", 9) + body  # type ARRAY


def build_gguf(kv_blobs, version=3, endian="<"):
    out = bytearray()
    out += g._MAGIC
    out += struct.pack(endian + "I", version)
    cnt = endian + ("I" if version == 1 else "Q")
    out += struct.pack(cnt, 0)              # tensor_count
    out += struct.pack(cnt, len(kv_blobs))  # metadata_kv_count
    for blob in kv_blobs:
        out += blob
    return bytes(out)


class ExtractionTests(unittest.TestCase):
    def test_extracts_chat_template_after_other_keys(self):
        raw = build_gguf([
            _kv_string("general.architecture", "llama"),
            _kv_u32("general.quantization_version", 2),
            _kv_array_string("tokenizer.ggml.tokens", ["a", "b", "c"]),
            _kv_string("tokenizer.chat_template", BENIGN_TEMPLATE),
        ])
        found = g.extract_chat_templates(raw)
        self.assertEqual([k for k, _ in found], ["tokenizer.chat_template"])
        self.assertEqual(found[0][1], BENIGN_TEMPLATE)

    def test_extracts_named_multi_templates(self):
        raw = build_gguf([
            _kv_string("tokenizer.chat_template.default", BENIGN_TEMPLATE),
            _kv_string("tokenizer.chat_template.tool_use", MAL["os_call"]),
        ])
        found = dict(g.extract_chat_templates(raw))
        self.assertIn("tokenizer.chat_template.default", found)
        self.assertIn("tokenizer.chat_template.tool_use", found)

    def test_no_chat_template_key_is_empty(self):
        raw = build_gguf([_kv_string("general.architecture", "llama")])
        self.assertEqual(g.extract_chat_templates(raw), [])


class DetectionTests(unittest.TestCase):
    def _codes_for(self, template):
        raw = build_gguf([_kv_string("tokenizer.chat_template", template)])
        return {f.code for f in g.scan_bytes(raw, "model.gguf")}

    def test_benign_templates_are_clean(self):
        self.assertEqual(self._codes_for(BENIGN_TEMPLATE), set())
        self.assertEqual(self._codes_for(BENIGN_TEMPLATE_2), set())

    def test_each_marker_flags_expected_code(self):
        self.assertIn("CT001", self._codes_for(MAL["dunder"]))
        self.assertIn("CT002", self._codes_for(MAL["builtin_global"]))
        self.assertIn("CT003", self._codes_for(MAL["os_call"]))
        self.assertIn("CT004", self._codes_for(MAL["attr_bypass"]))
        self.assertIn("CT005", self._codes_for(MAL["web_global"]))
        self.assertIn("CT006", self._codes_for(MAL["include_tag"]))

    def test_high_findings_carry_cve_reference(self):
        raw = build_gguf([_kv_string("tokenizer.chat_template", MAL["os_call"])])
        highs = [f for f in g.scan_bytes(raw, "m.gguf") if f.severity == "HIGH"]
        self.assertTrue(highs)
        self.assertTrue(all("CVE-2026-5760" in f.cve for f in highs))

    def test_carrier_is_gguf_metadata(self):
        raw = build_gguf([_kv_string("tokenizer.chat_template", MAL["dunder"])])
        for f in g.scan_bytes(raw, "m.gguf"):
            self.assertEqual(f.carrier, "gguf-metadata")
            self.assertTrue(f.source.endswith("tokenizer.chat_template"))


class RobustnessTests(unittest.TestCase):
    def test_truncated_file_yields_gct000_not_crash(self):
        raw = build_gguf([_kv_string("tokenizer.chat_template", BENIGN_TEMPLATE)])
        findings = g.scan_bytes(raw[:12], "trunc.gguf")
        self.assertEqual([f.code for f in findings], ["GCT000"])

    def test_bad_magic_yields_gct000(self):
        findings = g.scan_bytes(b"NOPE" + b"\x00" * 32, "x.gguf")
        self.assertEqual([f.code for f in findings], ["GCT000"])

    def test_hostile_huge_declared_length_is_bounded(self):
        # magic + version + tensor_count=0 + kv_count=1, then a key length that
        # claims far more bytes than exist. Must not over-read or hang.
        raw = g._MAGIC + struct.pack("<I", 3) + struct.pack("<Q", 0)
        raw += struct.pack("<Q", 1) + struct.pack("<Q", 1 << 40)
        findings = g.scan_bytes(raw, "evil.gguf")
        self.assertEqual([f.code for f in findings], ["GCT000"])

    def test_endian_detection(self):
        # GGUF magic is byte-identical both ways; the version field disambiguates.
        little = g._MAGIC + struct.pack("<I", 3)
        big = g._MAGIC + struct.pack(">I", 3)
        self.assertEqual(g._pick_endian(little + b"\x00" * 16), "<")
        self.assertEqual(g._pick_endian(big + b"\x00" * 16), ">")
        self.assertIsNone(g._pick_endian(b"NOPE" + b"\x00" * 16))


class ScanPathTests(unittest.TestCase):
    def test_scan_file_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.gguf")
            with open(p, "wb") as fh:
                fh.write(build_gguf([_kv_string("tokenizer.chat_template", MAL["os_call"])]))
            self.assertEqual(g.main([p, "--fail-on", "HIGH"]), 1)
            clean = os.path.join(d, "clean.gguf")
            with open(clean, "wb") as fh:
                fh.write(build_gguf([_kv_string("tokenizer.chat_template", BENIGN_TEMPLATE)]))
            self.assertEqual(g.main([clean, "--fail-on", "HIGH"]), 0)

    def test_scan_path_walks_directory(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.gguf"), "wb") as fh:
                fh.write(build_gguf([_kv_string("tokenizer.chat_template", MAL["web_global"])]))
            with open(os.path.join(d, "notes.txt"), "wb") as fh:
                fh.write(b"not a model")
            findings = g.scan_path(d)
            self.assertTrue(any(f.code == "CT005" for f in findings))


class SafetyTests(unittest.TestCase):
    def test_no_fixture_contains_destructive_or_exploit_completing_token(self):
        blob = "\n".join(list(MAL.values()) + [BENIGN_TEMPLATE, BENIGN_TEMPLATE_2])
        for tok in _FORBIDDEN:
            self.assertNotIn(tok, blob, "fixture must not contain %r" % tok)

    def test_scanner_imports_no_template_engine(self):
        import sys
        self.assertNotIn("jinja2", sys.modules)


if __name__ == "__main__":
    unittest.main()
