# Copyright 2026 MV2, Munim, Inc.
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
"""Tests for diffusers_manifest_scan. Stdlib only; no network, no pip."""
import json
import os
import tempfile
import unittest

import diffusers_manifest_scan as dms


class TestKnownLibrary(unittest.TestCase):
    def test_known_libraries(self):
        for good in ("diffusers", "transformers", "onnxruntime", "onnxruntime.training"):
            self.assertTrue(dms.is_known_library(good), good)

    def test_unknown_libraries(self):
        for bad in ("os", "my.evil.pkg", "weird", "", None, 3):
            self.assertFalse(dms.is_known_library(bad), repr(bad))


class TestBenignManifest(unittest.TestCase):
    def test_normal_pipeline_clean(self):
        blob = json.dumps(
            {
                "_class_name": "StableDiffusionPipeline",
                "_diffusers_version": "0.31.0",
                "text_encoder": ["transformers", "CLIPTextModel"],
                "unet": ["diffusers", "UNet2DConditionModel"],
                "safety_checker": [None, None],
            }
        )
        self.assertEqual(dms.scan_text(blob, "model_index.json"), [])

    def test_onnxruntime_training_allowed(self):
        blob = json.dumps({"unet": ["onnxruntime.training", "ORTModule"]})
        self.assertEqual(dms.scan_text(blob, "model_index.json"), [])

    def test_three_element_list_ignored(self):
        blob = json.dumps({"x": ["a", "b", "c"]})
        self.assertEqual(dms.scan_text(blob, "model_index.json"), [])


class TestComponentFindings(unittest.TestCase):
    def test_dangerous_library_is_critical(self):
        blob = json.dumps(
            {"_class_name": "StableDiffusionPipeline", "evil": ["os", "system"]}
        )
        findings = dms.scan_text(blob, "model_index.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "DMS001")
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].key, "evil")
        self.assertEqual(findings[0].location, "/evil")

    def test_unexpected_library_is_high(self):
        blob = json.dumps({"unet": ["my.evil.pkg", "Payload"]})
        findings = dms.scan_text(blob, "model_index.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "DMS001")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_disabled_component_skipped(self):
        blob = json.dumps({"safety_checker": [None, None]})
        self.assertEqual(dms.scan_text(blob, "model_index.json"), [])

    def test_mixed_components(self):
        blob = json.dumps(
            {
                "text_encoder": ["transformers", "CLIPTextModel"],
                "a": ["subprocess", "Popen"],
                "b": ["weird.lib", "X"],
            }
        )
        findings = dms.scan_text(blob, "model_index.json")
        self.assertEqual(len(findings), 2)
        sev = sorted(f.severity for f in findings)
        self.assertEqual(sev, ["CRITICAL", "HIGH"])


class TestClassNameFindings(unittest.TestCase):
    def test_list_class_name_is_dms002(self):
        blob = json.dumps(
            {
                "_class_name": ["my_pipeline", "MyCustomPipeline"],
                "unet": ["diffusers", "UNet2DConditionModel"],
            }
        )
        findings = dms.scan_text(blob, "model_index.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "DMS002")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("my_pipeline", findings[0].message)

    def test_string_class_name_no_dms002(self):
        blob = json.dumps(
            {"_class_name": "StableDiffusionPipeline", "unet": ["diffusers", "U"]}
        )
        self.assertEqual(dms.scan_text(blob, "model_index.json"), [])


class TestMalformed(unittest.TestCase):
    def test_not_json_returns_empty(self):
        self.assertEqual(dms.scan_text("not json {", "model_index.json"), [])

    def test_json_array_returns_empty(self):
        self.assertEqual(dms.scan_text("[1, 2, 3]", "model_index.json"), [])


class TestScanPathsAndCli(unittest.TestCase):
    def test_directory_walk_matches_only_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "model_index.json"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"evil": ["os", "system"]}))
            # Same payload under a different name must be ignored by the walk.
            with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"evil": ["os", "system"]}))
            result = dms.scan_paths([d])
            self.assertEqual(len(result.scanned_files), 1)
            self.assertTrue(result.scanned_files[0].endswith("model_index.json"))
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].severity, "CRITICAL")

            rc = dms.main([d, "--fail-on", "HIGH"])
            self.assertEqual(rc, 1)
            rc_json = dms.main([d, "--json"])
            self.assertEqual(rc_json, 0)  # default fail-on NONE

    def test_explicit_file_scanned_regardless_of_name(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "mi.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"unet": ["evilpkg", "X"]}))
            result = dms.scan_paths([path])
            self.assertEqual(len(result.scanned_files), 1)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.findings[0].severity, "HIGH")

    def test_clean_dir_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "model_index.json"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"unet": ["diffusers", "UNet2DConditionModel"]}))
            self.assertEqual(dms.main([d, "--fail-on", "LOW"]), 0)


if __name__ == "__main__":
    unittest.main()
