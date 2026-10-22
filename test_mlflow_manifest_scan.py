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
"""Tests for mlflow_manifest_scan. Stdlib only; no network, no pip, no execution.

Every manifest below is an inert piece of text written to a temp file; nothing is
imported, unpickled or loaded. The tests assert which rules fire against crafted
``MLmodel`` content and which benign content stays quiet.
"""
import os
import tempfile
import unittest

import mlflow_manifest_scan as mms


# --- crafted, inert MLmodel manifests (plain text, never loaded) -------------

STATSMODELS_BYPASS = """\
artifact_path: model
flavors:
  python_function:
    loader_module: mlflow.statsmodels
    model_path: model.pkl
    python_version: 3.10.12
  statsmodels:
    data: model.statsmodels
    statsmodels_version: 0.14.0
mlflow_version: 2.9.2
model_uuid: 0123456789abcdef
"""

OUTSIDE_NAMESPACE = """\
artifact_path: model
flavors:
  python_function:
    loader_module: evil.payload
    model_path: anything
mlflow_version: 2.9.2
"""

DANGEROUS_ROOT = """\
flavors:
  python_function:
    loader_module: subprocess
    model_path: anything
"""

BENIGN_ONNX = """\
artifact_path: model
flavors:
  onnx:
    data: model.onnx
    onnx_version: 1.14.0
  python_function:
    loader_module: mlflow.onnx
    data: model.onnx
    python_version: 3.10.12
mlflow_version: 2.9.2
"""

BENIGN_SKLEARN_PICKLE = """\
flavors:
  python_function:
    loader_module: mlflow.sklearn
    model_path: model.pkl
    python_version: 3.10.12
  sklearn:
    pickled_model: model.pkl
    serialization_format: cloudpickle
    sklearn_version: 1.3.0
"""

NOT_A_MANIFEST = """\
name: my-config
version: 1.0
description: not an mlflow model manifest
"""

# python_function with a 'code' dir and a non-first-party loader -- the exact
# CVE-2026-79721 shape (sys.path prepend before importlib.import_module).
CODE_INJECTION_HIGH = """\
artifact_path: model
flavors:
  python_function:
    loader_module: payload
    code: "."
    model_path: anything
mlflow_version: 2.9.2
"""

# 'code' dir with a first-party loader -- still a sys.path-prepend risk (MEDIUM).
CODE_FIRST_PARTY = """\
flavors:
  python_function:
    loader_module: mlflow.sklearn
    code: "src"
    python_version: 3.10.12
"""

# First-party loader, no 'code' key -- MLF005 must stay quiet.
NO_CODE_FIRST_PARTY = """\
flavors:
  python_function:
    loader_module: mlflow.sklearn
    python_version: 3.10.12
"""

# No python_function flavor at all -- MLF005 (and MLF004) must stay quiet.
NO_PYFUNC = """\
flavors:
  onnx:
    data: model.onnx
    onnx_version: 1.14.0
"""

# Empty 'code' value parses to a child mapping, not a string -- MLF005 quiet.
EMPTY_CODE = """\
flavors:
  python_function:
    loader_module: mlflow.sklearn
    code: ""
    python_version: 3.10.12
"""


def _rules(findings):
    return {f.rule for f in findings}


def _by_rule(findings, rule):
    matches = [f for f in findings if f.rule == rule]
    return matches[0] if matches else None


class TestYamlSubsetParser(unittest.TestCase):
    def test_nested_block_mapping(self):
        data = mms.parse_yaml_mapping(STATSMODELS_BYPASS)
        self.assertEqual(data["artifact_path"], "model")
        self.assertIn("flavors", data)
        pf = data["flavors"]["python_function"]
        self.assertEqual(pf["loader_module"], "mlflow.statsmodels")
        self.assertEqual(data["flavors"]["statsmodels"]["data"], "model.statsmodels")
        self.assertEqual(data["mlflow_version"], "2.9.2")

    def test_sibling_dedent_is_tracked(self):
        # statsmodels is a sibling of python_function, not a child of it.
        data = mms.parse_yaml_mapping(STATSMODELS_BYPASS)
        self.assertIn("statsmodels", data["flavors"])
        self.assertNotIn("statsmodels", data["flavors"]["python_function"])

    def test_quotes_and_comments_stripped(self):
        data = mms.parse_yaml_mapping(
            'flavors:\n'
            '  python_function:\n'
            "    loader_module: 'mlflow.statsmodels'  # a comment\n")
        self.assertEqual(
            data["flavors"]["python_function"]["loader_module"],
            "mlflow.statsmodels")

    def test_empty_text(self):
        self.assertEqual(mms.parse_yaml_mapping(""), {})


class TestStatsmodelsBypass(unittest.TestCase):
    def test_mlf002_fires(self):
        findings = mms.scan_text(STATSMODELS_BYPASS, "MLmodel")
        self.assertEqual(_rules(findings), {"MLF002", "MLF003", "MLF004"})
        f = _by_rule(findings, "MLF002")
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.value, "mlflow.statsmodels")
        self.assertTrue(f.location.endswith("loader_module"))
        self.assertIn("GHSA-gqvg-gmmx-x4hm", f.message)


class TestLoaderModuleOutsideNamespace(unittest.TestCase):
    def test_mlf001_high(self):
        findings = mms.scan_text(OUTSIDE_NAMESPACE, "MLmodel")
        self.assertEqual(_rules(findings), {"MLF001", "MLF004"})
        f = _by_rule(findings, "MLF001")
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.value, "evil.payload")

    def test_mlf001_critical_for_dangerous_root(self):
        findings = mms.scan_text(DANGEROUS_ROOT, "MLmodel")
        f = _by_rule(findings, "MLF001")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.value, "subprocess")


class TestBenignManifests(unittest.TestCase):
    def test_onnx_first_party_no_loader_finding(self):
        findings = mms.scan_text(BENIGN_ONNX, "MLmodel")
        # First-party loader, no pickle -> only the INFO context finding.
        self.assertEqual(_rules(findings), {"MLF004"})
        self.assertEqual(findings[0].severity, "INFO")

    def test_sklearn_pickle_is_medium_only(self):
        findings = mms.scan_text(BENIGN_SKLEARN_PICKLE, "MLmodel")
        self.assertEqual(_rules(findings), {"MLF003", "MLF004"})
        self.assertIsNone(_by_rule(findings, "MLF001"))
        self.assertIsNone(_by_rule(findings, "MLF002"))
        self.assertEqual(_by_rule(findings, "MLF003").severity, "MEDIUM")


class TestMarkerGating(unittest.TestCase):
    def test_non_manifest_requires_marker(self):
        self.assertEqual(mms.scan_text(NOT_A_MANIFEST, "MLmodel"), [])

    def test_force_scan_without_marker_still_empty_if_no_flavors(self):
        # Even forced, a file with no flavors yields nothing of substance here.
        self.assertEqual(
            mms.scan_text(NOT_A_MANIFEST, "x", require_marker=False), [])

    def test_malformed_text_empty(self):
        self.assertEqual(mms.scan_text("}{ not yaml", "MLmodel"), [])


class TestScanPathsAndCli(unittest.TestCase):
    def test_directory_walk_matches_only_mlmodel(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "MLmodel"), "w", encoding="utf-8") as fh:
                fh.write(STATSMODELS_BYPASS)
            # Same payload under a different name must be ignored by the walk.
            with open(os.path.join(d, "other.yaml"), "w", encoding="utf-8") as fh:
                fh.write(STATSMODELS_BYPASS)
            result = mms.scan_paths([d])
            self.assertEqual(len(result.scanned_files), 1)
            self.assertTrue(result.scanned_files[0].endswith("MLmodel"))
            self.assertIn("MLF002", _rules(result.findings))

            self.assertEqual(mms.main([d, "--fail-on", "HIGH"]), 1)
            self.assertEqual(mms.main([d, "--json"]), 0)  # default fail-on NONE

    def test_explicit_file_scanned_regardless_of_name(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "MLmodel.yaml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(OUTSIDE_NAMESPACE)
            result = mms.scan_paths([path])
            self.assertEqual(len(result.scanned_files), 1)
            self.assertIn("MLF001", _rules(result.findings))

    def test_explicit_non_manifest_file_quiet(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "random.yaml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(NOT_A_MANIFEST)
            result = mms.scan_paths([path])
            self.assertEqual(result.findings, [])

    def test_fail_on_thresholds(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "MLmodel")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(BENIGN_ONNX)
            self.assertEqual(mms.main([path, "--fail-on", "MEDIUM"]), 0)
            self.assertEqual(mms.main([path, "--fail-on", "INFO"]), 1)
            self.assertEqual(mms.main([path]), 0)  # NONE


class TestCodePathSysPathInjection(unittest.TestCase):
    def test_mlf005_high_with_nonfirstparty_loader(self):
        findings = mms.scan_text(CODE_INJECTION_HIGH, "MLmodel")
        self.assertEqual(_rules(findings), {"MLF001", "MLF004", "MLF005"})
        f = _by_rule(findings, "MLF005")
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.value, ".")
        self.assertTrue(f.location.endswith("code"))
        self.assertIn("CVE-2026-79721", f.message)
        self.assertIn("CWE-829", f.message)
        # MLF001 still fires on the non-first-party loader_module.
        self.assertIsNotNone(_by_rule(findings, "MLF001"))

    def test_mlf005_medium_with_first_party_loader(self):
        findings = mms.scan_text(CODE_FIRST_PARTY, "MLmodel")
        self.assertEqual(_rules(findings), {"MLF004", "MLF005"})
        f = _by_rule(findings, "MLF005")
        self.assertEqual(f.severity, "MEDIUM")
        self.assertEqual(f.value, "src")
        self.assertIsNone(_by_rule(findings, "MLF001"))

    def test_no_code_key_no_mlf005(self):
        findings = mms.scan_text(NO_CODE_FIRST_PARTY, "MLmodel")
        self.assertEqual(_rules(findings), {"MLF004"})
        self.assertIsNone(_by_rule(findings, "MLF005"))

    def test_no_pyfunc_flavor_no_mlf005(self):
        findings = mms.scan_text(NO_PYFUNC, "MLmodel")
        self.assertIsNone(_by_rule(findings, "MLF005"))
        self.assertIsNone(_by_rule(findings, "MLF004"))

    def test_empty_code_value_no_mlf005(self):
        findings = mms.scan_text(EMPTY_CODE, "MLmodel")
        self.assertEqual(_rules(findings), {"MLF004"})
        self.assertIsNone(_by_rule(findings, "MLF005"))


if __name__ == "__main__":
    unittest.main()
