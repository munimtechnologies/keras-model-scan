# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Tests for safetensors_index_scan. The "malicious" fixtures are nothing but
# path strings in a JSON object -- there is no payload, nothing is ever opened,
# resolved on disk, loaded or executed. Made with AI by MV2 of Munim, Inc.

import json
import os
import tempfile
import unittest

import safetensors_index_scan as sis


def _rules(findings):
    return {f.rule for f in findings}


def _index(weight_map, metadata=None):
    doc = {"weight_map": weight_map}
    if metadata is not None:
        doc["metadata"] = metadata
    return json.dumps(doc)


class ScanTextTests(unittest.TestCase):
    def test_clean_index_is_sti000(self):
        text = _index({
            "lm_head.weight": "model-00002-of-00002.safetensors",
            "model.embed.weight": "model-00001-of-00002.safetensors",
        }, metadata={"total_size": 123})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI000"})

    def test_absolute_posix_path(self):
        text = _index({"w": "/etc/passwd"})
        f = sis.scan_text(text, "idx")
        self.assertEqual(_rules(f), {"STI001"})
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cve, "CWE-22")

    def test_absolute_windows_path(self):
        text = _index({"w": "C:\\Windows\\win.ini"})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI001"})

    def test_windows_unc_path(self):
        text = _index({"w": "\\\\server\\share\\x.safetensors"})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI001"})

    def test_drive_relative_path(self):
        text = _index({"w": "C:shard.safetensors"})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI001"})

    def test_posix_traversal(self):
        text = _index({"w": "../../../../etc/shadow"})
        f = sis.scan_text(text, "idx")
        self.assertEqual(_rules(f), {"STI002"})
        self.assertEqual(f[0].severity, "HIGH")

    def test_windows_traversal(self):
        text = _index({"w": "..\\..\\secret.safetensors"})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI002"})

    def test_url_scheme(self):
        text = _index({"w": "https://evil.example/x.safetensors"})
        f = sis.scan_text(text, "idx")
        self.assertEqual(_rules(f), {"STI004"})
        self.assertEqual(f[0].cve, "CWE-918")

    def test_file_url(self):
        text = _index({"w": "file:///etc/passwd"})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI004"})

    def test_backslash_separator(self):
        text = _index({"w": "sub\\shard.safetensors"})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI003"})

    def test_subdirectory_component(self):
        text = _index({"w": "nested/shard.safetensors"})
        f = sis.scan_text(text, "idx")
        self.assertEqual(_rules(f), {"STI005"})
        self.assertEqual(f[0].severity, "LOW")

    def test_nul_byte(self):
        text = _index({"w": "good.safetensors\u0000.txt"})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI006"})

    def test_mixed_entries_flag_each_bad_one(self):
        text = _index({
            "a": "model-00001-of-00003.safetensors",   # clean, no finding
            "b": "/etc/passwd",                          # STI001
            "c": "../../x.safetensors",                  # STI002
            "d": "https://evil/x",                       # STI004
        })
        self.assertEqual(_rules(sis.scan_text(text, "idx")),
                         {"STI001", "STI002", "STI004"})

    def test_value_not_string(self):
        text = _index({"w": 1234})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI007"})

    def test_empty_value(self):
        text = _index({"w": ""})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI007"})

    def test_no_weight_map_is_info(self):
        text = json.dumps({"metadata": {"total_size": 1}})
        f = sis.scan_text(text, "idx")
        self.assertEqual(_rules(f), {"STI000"})
        self.assertEqual(f[0].severity, "INFO")

    def test_weight_map_not_object(self):
        text = json.dumps({"weight_map": ["a", "b"]})
        self.assertEqual(_rules(sis.scan_text(text, "idx")), {"STI007"})

    def test_malformed_json(self):
        f = sis.scan_text('{"weight_map": {', "idx")
        self.assertEqual(_rules(f), {"STI009"})
        self.assertEqual(f[0].severity, "HIGH")

    def test_top_level_not_object(self):
        self.assertEqual(_rules(sis.scan_text("[1,2,3]", "idx")), {"STI009"})

    def test_deeply_nested_is_guarded(self):
        # 300 open brackets -> over DEPTH_CAP; must be flagged, never parsed.
        text = "[" * 300 + "]" * 300
        f = sis.scan_text(text, "idx")
        self.assertEqual(_rules(f), {"STI008"})


class ScanFileTests(unittest.TestCase):
    def test_scan_file_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.safetensors.index.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(_index({"w": "/etc/passwd"}))
            self.assertEqual(_rules(sis.scan_file(p)), {"STI001"})

    def test_scan_path_walks_directory(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "model.safetensors.index.json")
            with open(good, "w", encoding="utf-8") as fh:
                fh.write(_index({"w": "model-00001-of-00001.safetensors"}))
            # A non-index .json in the same dir must be ignored by the walk.
            with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as fh:
                fh.write("{}")
            self.assertEqual(_rules(sis.scan_path(d)), {"STI000"})

    def test_cli_fail_on_high(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "pytorch_model.bin.index.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(_index({"w": "../../../../etc/shadow"}))
            self.assertEqual(sis.main([p, "--fail-on", "HIGH"]), 1)
            self.assertEqual(sis.main([p, "--fail-on", "CRITICAL"]), 0)


if __name__ == "__main__":
    unittest.main()
