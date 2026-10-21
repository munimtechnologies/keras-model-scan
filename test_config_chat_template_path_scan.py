import json
import os
import tempfile
import unittest

import config_chat_template_path_scan as m


class ConfigChatTemplatePathScanTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def _write(self, obj):
        path = os.path.join(self.tmp, "tokenizer_config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    def _scan(self, obj):
        return m.scan(self._write(obj))

    def test_clean_dict_template_no_findings(self):
        f = self._scan({"chat_template": {"default": "{{ x }}",
                                          "tool_use": "{{ y }}"}})
        self.assertEqual(f, [])

    def test_string_chat_template_not_flagged(self):
        # A single string template is not written per-key, so no sink.
        f = self._scan({"chat_template": "{{ messages }}"})
        self.assertEqual(f, [])

    def test_parent_traversal_key_is_critical(self):
        f = self._scan({"chat_template": {
            "../../../../etc/cron.d/evil": "{{ x }}"}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP001")
        self.assertEqual(f[0]["level"], "CRITICAL")
        self.assertEqual(f[0]["cve"], "CVE-2026-9856")
        self.assertEqual(f[0]["cwe"], "CWE-22")

    def test_absolute_posix_key_is_critical(self):
        f = self._scan({"chat_template": {"/etc/cron.d/evil": "{{ x }}"}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP001")

    def test_windows_drive_key_is_critical(self):
        f = self._scan({"chat_template": {"C:\\Windows\\Temp\\x": "{{ x }}"}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP001")

    def test_parent_in_middle_is_critical(self):
        f = self._scan({"chat_template": {"sub/../../x": "{{ x }}"}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP001")

    def test_separator_only_key_is_high(self):
        f = self._scan({"chat_template": {"subdir/name": "{{ x }}"}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP002")
        self.assertEqual(f[0]["level"], "HIGH")

    def test_backslash_separator_is_high(self):
        f = self._scan({"chat_template": {"subdir\\name": "{{ x }}"}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP002")

    def test_nested_processor_subconfig_is_scanned(self):
        f = self._scan({"processor_config": {
            "chat_template": {"../x": "{{ x }}"}}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP001")
        self.assertEqual(f[0]["key"], "../x")

    def test_two_bad_keys_two_findings(self):
        f = self._scan({"chat_template": {
            "../a": "{{ x }}", "sub/b": "{{ y }}", "default": "{{ z }}"}})
        self.assertEqual(len(f), 2)
        rules = sorted(x["rule"] for x in f)
        self.assertEqual(rules, ["CTP001", "CTP002"])

    def test_unreadable_is_ctp000(self):
        f = m.scan(os.path.join(self.tmp, "does_not_exist.json"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP000")
        self.assertEqual(f[0]["level"], "ERROR")

    def test_bad_json_is_ctp000(self):
        path = os.path.join(self.tmp, "tokenizer_config.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")
        f = m.scan(path)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTP000")


if __name__ == "__main__":
    unittest.main()
