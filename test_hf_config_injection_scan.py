"""Self-contained tests for hf_config_injection_scan (CVE-2026-4372 detector).

Imports only the module under test and the standard library. No network, no model
loading, no third-party dependency. Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import tempfile
import unittest

import hf_config_injection_scan as scan


def _find(findings, rule):
    return [f for f in findings if f.rule == rule]


class ScanBytesTests(unittest.TestCase):
    def test_clean_config_has_no_findings(self):
        config = {
            "model_type": "llama",
            "hidden_size": 4096,
            "attn_implementation": "sdpa",
            "architectures": ["LlamaForCausalLM"],
        }
        findings = scan.scan_bytes(json.dumps(config).encode("utf-8"), "config.json")
        self.assertEqual(findings, [])

    def test_attn_internal_field_is_high(self):
        config = {
            "model_type": "llama",
            "_attn_implementation_internal": "research-lab-2025/optimized-attn-kernel",
        }
        findings = scan.scan_bytes(json.dumps(config).encode("utf-8"), "config.json")
        hci001 = _find(findings, "HCI001")
        self.assertEqual(len(hci001), 1)
        self.assertEqual(hci001[0].severity, "HIGH")
        self.assertEqual(hci001[0].key, "_attn_implementation_internal")
        self.assertIn("research-lab-2025/optimized-attn-kernel", hci001[0].value)
        self.assertIn("CVE-2026-4372", hci001[0].message)
        self.assertIn("owner/repo", hci001[0].message)

    def test_experts_internal_field_is_high(self):
        config = {"_experts_implementation_internal": "evil/kernel"}
        findings = scan.scan_bytes(json.dumps(config).encode("utf-8"), "config.json")
        hci002 = _find(findings, "HCI002")
        self.assertEqual(len(hci002), 1)
        self.assertEqual(hci002[0].severity, "HIGH")

    def test_nested_subconfig_is_flagged_with_dotted_path(self):
        config = {
            "model_type": "clip",
            "text_config": {
                "hidden_size": 512,
                "_attn_implementation_internal": "attacker/repo",
            },
        }
        findings = scan.scan_bytes(json.dumps(config).encode("utf-8"), "config.json")
        hci001 = _find(findings, "HCI001")
        self.assertEqual(len(hci001), 1)
        self.assertEqual(hci001[0].key, "text_config._attn_implementation_internal")
        self.assertGreater(hci001[0].data_location, 0)

    def test_field_in_list_of_subconfigs_is_flagged(self):
        config = {"sub_configs": [{"ok": 1}, {"_attn_implementation_internal": "a/b"}]}
        findings = scan.scan_bytes(json.dumps(config).encode("utf-8"), "config.json")
        self.assertEqual(len(_find(findings, "HCI001")), 1)

    def test_non_id_value_omits_owner_repo_note(self):
        config = {"_attn_implementation_internal": "flash_attention_2"}
        findings = scan.scan_bytes(json.dumps(config).encode("utf-8"), "config.json")
        hci001 = _find(findings, "HCI001")
        self.assertEqual(len(hci001), 1)
        self.assertNotIn("owner/repo", hci001[0].message)

    def test_auto_map_is_info_only(self):
        config = {
            "auto_map": {"AutoModel": "modeling_custom.MyModel"},
            "model_type": "custom",
        }
        findings = scan.scan_bytes(json.dumps(config).encode("utf-8"), "config.json")
        hci003 = _find(findings, "HCI003")
        self.assertEqual(len(hci003), 1)
        self.assertEqual(hci003[0].severity, "INFO")

    def test_malformed_json_reports_error(self):
        findings = scan.scan_bytes(b"{not valid json", "config.json")
        self.assertEqual(len(_find(findings, "HCI000")), 1)
        self.assertEqual(findings[0].severity, "ERROR")


class ExitCodeTests(unittest.TestCase):
    def _write(self, directory, name, obj):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(obj, handle)
        return path

    def test_main_returns_one_on_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "config.json", {"_attn_implementation_internal": "a/b"}
            )
            self.assertEqual(scan.main([path]), 1)

    def test_main_returns_zero_on_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "config.json", {"model_type": "bert"})
            self.assertEqual(scan.main([path]), 0)

    def test_main_info_does_not_fail_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "config.json", {"auto_map": {"AutoModel": "m.M"}})
            self.assertEqual(scan.main([path]), 0)
            self.assertEqual(scan.main([path, "--fail-on", "INFO"]), 1)

    def test_json_output_is_parseable(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "config.json", {"_attn_implementation_internal": "a/b"}
            )
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                scan.main([path, "--json"])
            parsed = json.loads(buffer.getvalue())
            self.assertEqual(parsed[0]["rule"], "HCI001")


class DirectoryTests(unittest.TestCase):
    def test_directory_scan_filters_by_config_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "config.json"), "w", encoding="utf-8") as fh:
                json.dump({"_attn_implementation_internal": "a/b"}, fh)
            # A non-config .json carrying the key must NOT be scanned in a directory.
            with open(os.path.join(tmp, "notes.json"), "w", encoding="utf-8") as fh:
                json.dump({"_attn_implementation_internal": "a/b"}, fh)
            findings = scan.scan_path(tmp)
            self.assertEqual(len(_find(findings, "HCI001")), 1)

    def test_suffix_config_name_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            name = "preprocessor_config.json"
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                json.dump({"_experts_implementation_internal": "x/y"}, fh)
            self.assertEqual(len(_find(scan.scan_path(tmp), "HCI002")), 1)


class HygieneTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(scan.__version__, "0.1.0")

    def test_license_header(self):
        source = scan.__doc__ or ""
        self.assertIn("Apache-2.0", source)
        self.assertNotIn("MIT", source)


if __name__ == "__main__":
    unittest.main()
