import json
import os
import tempfile
import unittest

import config_trust_remote_code_scan as m


class ConfigTrustRemoteCodeScanTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def _write(self, obj):
        path = os.path.join(self.tmp, "config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    def _scan(self, obj):
        return m.scan(self._write(obj))

    def test_clean_config_no_findings(self):
        f = self._scan({"model_type": "llama", "hidden_size": 4096})
        self.assertEqual(f, [])

    def test_trust_remote_code_true_is_critical(self):
        f = self._scan({"model_type": "lightglue", "trust_remote_code": True})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR001")
        self.assertEqual(f[0]["level"], "CRITICAL")
        self.assertEqual(f[0]["cve"], "CVE-2026-5241")
        self.assertEqual(f[0]["cwe"], "CWE-829")

    def test_trust_remote_code_string_true_is_critical(self):
        f = self._scan({"trust_remote_code": "true"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR001")

    def test_trust_remote_code_int_truthy_is_critical(self):
        f = self._scan({"trust_remote_code": 1})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR001")

    def test_trust_remote_code_false_is_high(self):
        f = self._scan({"trust_remote_code": False})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR002")
        self.assertEqual(f[0]["level"], "HIGH")

    def test_trust_remote_code_other_string_is_high(self):
        f = self._scan({"trust_remote_code": "no"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR002")

    def test_nested_subconfig_is_scanned(self):
        f = self._scan({"model_type": "lightglue",
                        "keypoint_detector_config": {
                            "trust_remote_code": True}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR001")
        self.assertEqual(f[0]["key"], "trust_remote_code")

    def test_two_keys_two_findings(self):
        f = self._scan({"trust_remote_code": True,
                        "sub": {"trust_remote_code": False}})
        self.assertEqual(len(f), 2)
        rules = sorted(x["rule"] for x in f)
        self.assertEqual(rules, ["CTR001", "CTR002"])

    def test_auto_map_alone_not_flagged(self):
        f = self._scan({"model_type": "custom",
                        "auto_map": {"AutoModel": "modeling_custom.MyModel"}})
        self.assertEqual(f, [])

    def test_auto_map_context_reported_with_trc(self):
        f = self._scan({"trust_remote_code": True,
                        "auto_map": {"AutoModel": "modeling_custom.MyModel"}})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR001")
        self.assertIn("auto_map", f[0]["message"])

    def test_unreadable_is_ctr000(self):
        f = m.scan(os.path.join(self.tmp, "does_not_exist.json"))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR000")
        self.assertEqual(f[0]["level"], "ERROR")

    def test_bad_json_is_ctr000(self):
        path = os.path.join(self.tmp, "config.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")
        f = m.scan(path)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "CTR000")


if __name__ == "__main__":
    unittest.main()
