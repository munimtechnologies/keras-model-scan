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
# This file was written by AI agents working in the name of MV2 of Munim, Inc.
"""Tests for gguf_chat_template_evasion_probe."""

import unittest

from gguf_chat_template_evasion_probe import probe, is_suspicious


def _codes(template):
    return [code for code, _sev, _msg in probe(template)]


class SplitDunderTest(unittest.TestCase):
    def test_split_class_subscript(self):
        # ['__cla''ss__'] folds to ['__class__']; a raw denylist misses it.
        t = "{{ ()['__cla''ss__']['__ba''se__']() }}"
        self.assertEqual(_codes(t), ["EVA001"])

    def test_split_builtins_import_chain(self):
        t = ("{{ x()['__buil''tins__']['__imp''ort__']('os')"
             ".popen('id') }}")
        self.assertEqual(_codes(t), ["EVA001"])

    def test_split_dunder_with_plus(self):
        t = "{{ x['__cla' + 'ss__'] }}"
        self.assertEqual(_codes(t), ["EVA001"])

    def test_split_dunder_with_tilde(self):
        t = "{{ x['__glo' ~ 'bals__'] }}"
        self.assertEqual(_codes(t), ["EVA001"])


class SplitLiteralTest(unittest.TestCase):
    def test_split_popen_no_dunder(self):
        # 'pop''en' has no dunder, so it is the weaker EVA002, not EVA001.
        t = "{{ x['pop''en']('id') }}"
        self.assertEqual(_codes(t), ["EVA002"])

    def test_split_os_token(self):
        t = "{{ x['o''s'] }}"
        self.assertEqual(_codes(t), ["EVA002"])


class NoFalsePositiveTest(unittest.TestCase):
    def test_plain_payload_not_flagged_here(self):
        # The canonical, unobfuscated PoC is caught by the MAIN denylist
        # scanner (CT001/CT003), not by this evasion probe.
        t = "{{ ().__class__.__base__.__subclasses__() }}"
        self.assertEqual(_codes(t), [])

    def test_normal_template(self):
        t = "{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}\n{% endfor %}"
        self.assertEqual(_codes(t), [])

    def test_empty_string_literal(self):
        self.assertEqual(_codes("{{ x or '' }}"), [])
        self.assertEqual(_codes("default is ''"), [])

    def test_empty_and_nonstring(self):
        self.assertEqual(probe(""), [])
        self.assertEqual(probe(None), [])
        self.assertEqual(probe(123), [])

    def test_is_suspicious(self):
        self.assertTrue(is_suspicious("{{ x['__cla''ss__'] }}"))
        self.assertFalse(is_suspicious("{{ messages[0]['content'] }}"))


if __name__ == "__main__":
    unittest.main()
