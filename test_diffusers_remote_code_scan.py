#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# Licensed under the Apache License, Version 2.0.
"""Tests for diffusers_remote_code_scan (FaceHugger repo-filesystem detector)."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import diffusers_remote_code_scan as drc


def _write(path: str, text: str = "") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class HelperTests(unittest.TestCase):
    def test_severity_order_total(self):
        for s in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            self.assertIn(s, drc.SEVERITY_ORDER)
        self.assertEqual(drc.SEVERITY_ORDER["CRITICAL"], 4)

    def test_is_pipeline_dir(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(drc.is_pipeline_dir(d))
            _write(os.path.join(d, drc.PIPELINE_MARKER), "{}")
            self.assertTrue(drc.is_pipeline_dir(d))


class NonePyTests(unittest.TestCase):
    def test_none_py_in_pipeline_repo_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, drc.PIPELINE_MARKER), '{"_class_name": "X"}')
            _write(os.path.join(d, "None.py"), "import os\n")
            res = drc.scan_paths([d])
            rules = {f.rule: f for f in res.findings}
            self.assertIn("DRC001", rules)
            self.assertEqual(rules["DRC001"].severity, "CRITICAL")
            self.assertIn("CVE-2026-44827", rules["DRC001"].message)

    def test_none_py_without_marker_still_flagged(self):
        # None.py is an exact exploit fingerprint; flag it even without a
        # model_index.json in the same directory.
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, "None.py"), "x = 1\n")
            res = drc.scan_paths([d])
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].rule, "DRC001")

    def test_explicit_none_py_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "None.py")
            _write(p, "x = 1\n")
            res = drc.scan_paths([p])
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].rule, "DRC001")


class CustomModuleTests(unittest.TestCase):
    def test_custom_py_in_pipeline_repo_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, drc.PIPELINE_MARKER), '{"_class_name": "X"}')
            _write(os.path.join(d, "pipeline.py"), "class P: pass\n")
            res = drc.scan_paths([d])
            rules = {f.rule: f for f in res.findings}
            self.assertIn("DRC002", rules)
            self.assertEqual(rules["DRC002"].severity, "HIGH")
            self.assertIn("CVE-2026-44513", rules["DRC002"].message)
            self.assertIn("pipeline.py", rules["DRC002"].message)

    def test_py_without_marker_not_flagged(self):
        # An ordinary Python project (no model_index.json) must not light up.
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, "setup.py"), "x = 1\n")
            _write(os.path.join(d, "mymod.py"), "x = 1\n")
            res = drc.scan_paths([d])
            self.assertEqual(res.findings, [])

    def test_clean_pipeline_repo_has_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, drc.PIPELINE_MARKER), '{"_class_name": "X"}')
            _write(os.path.join(d, "config.json"), "{}")
            _write(os.path.join(d, "model.safetensors"), "weights")
            res = drc.scan_paths([d])
            self.assertEqual(res.findings, [])

    def test_explicit_py_file_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "custom_pipeline.py")
            _write(p, "class P: pass\n")
            res = drc.scan_paths([p])
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].rule, "DRC002")

    def test_nested_non_marker_py_not_flagged_but_none_py_is(self):
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, drc.PIPELINE_MARKER), "{}")
            # a nested sub-dir WITHOUT its own marker
            _write(os.path.join(d, "unet", "helper.py"), "x = 1\n")
            _write(os.path.join(d, "unet", "None.py"), "x = 1\n")
            res = drc.scan_paths([d])
            rules = sorted(f.rule for f in res.findings)
            # repo-root has no loose .py; nested helper.py is NOT flagged;
            # nested None.py IS flagged.
            self.assertEqual(rules, ["DRC001"])


class SeverityAndErrorTests(unittest.TestCase):
    def test_missing_path_is_an_error(self):
        res = drc.scan_paths([os.path.join(tempfile.gettempdir(), "no_such_x")])
        self.assertTrue(res.errors)
        self.assertEqual(res.findings, [])

    def test_max_severity(self):
        f1 = drc.Finding("DRC002", "HIGH", "a.py", "r", "m")
        f2 = drc.Finding("DRC001", "CRITICAL", "None.py", "r", "m")
        self.assertEqual(drc._max_severity([f1, f2]), 4)
        self.assertEqual(drc._max_severity([]), 0)


class CliTests(unittest.TestCase):
    def _run(self, args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = drc.main(args)
        return code, buf.getvalue()

    def test_json_output_and_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, drc.PIPELINE_MARKER), "{}")
            _write(os.path.join(d, "None.py"), "x = 1\n")
            code, out = self._run([d, "--json", "--fail-on", "HIGH"])
            self.assertEqual(code, 1)
            payload = json.loads(out)
            self.assertEqual(payload["version"], drc.__version__)
            self.assertEqual(payload["findings"][0]["rule"], "DRC001")

    def test_text_output_and_clean_repo_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            _write(os.path.join(d, drc.PIPELINE_MARKER), "{}")
            _write(os.path.join(d, "config.json"), "{}")
            code, out = self._run([d, "--fail-on", "HIGH"])
            self.assertEqual(code, 0)
            self.assertIn("0 finding(s)", out)


if __name__ == "__main__":
    unittest.main()
