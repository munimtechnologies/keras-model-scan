#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# Licensed under the Apache License, Version 2.0.
"""Tests for skops_scan (static .skops schema.json type auditor)."""
import io
import json
import os
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout

import skops_scan as sk


def _node(module, cls, loader, **extra):
    d = {"__class__": cls, "__module__": module, "__loader__": loader, "__id__": 0}
    d.update(extra)
    return d


def _write_skops(path, schema):
    """Write a .skops ZIP holding a schema.json with the given tree."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(sk.SCHEMA_MEMBER, json.dumps(schema))
        zf.writestr("data/obj.bin", b"\x00\x01")


def _clean_schema():
    # A plausible sklearn estimator: only sklearn/numpy/builtins nodes.
    return _node(
        "sklearn.preprocessing._data",
        "MinMaxScaler",
        "ObjectNode",
        content={
            "attrs": _node(
                "builtins",
                "dict",
                "DictNode",
                content={
                    "scale_": _node("numpy", "sqrt", "FunctionNode"),
                    "range_": _node(
                        "builtins",
                        "tuple",
                        "TupleNode",
                        content=[1, 2],
                    ),
                },
                key_types=None,
            )
        },
    )


class HelperTests(unittest.TestCase):
    def test_is_node(self):
        self.assertTrue(sk.is_node(_node("os", "system", "FunctionNode")))
        self.assertFalse(sk.is_node({"__class__": "x"}))
        self.assertFalse(sk.is_node([1, 2]))

    def test_iter_nodes_finds_nested(self):
        schema = _clean_schema()
        modules = {n["__module__"] for n in sk.iter_nodes(schema)}
        self.assertIn("sklearn.preprocessing._data", modules)
        self.assertIn("numpy", modules)
        self.assertIn("builtins", modules)

    def test_severity_order_total(self):
        self.assertEqual(sk.SEVERITY_ORDER["CRITICAL"], 4)
        for s in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            self.assertIn(s, sk.SEVERITY_ORDER)


class CleanTests(unittest.TestCase):
    def test_clean_sklearn_model_has_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.skops")
            _write_skops(p, _clean_schema())
            res = sk.scan_paths([p])
            self.assertEqual(res.findings, [])
            self.assertEqual(res.errors, [])
            self.assertIn(p, res.scanned_files)


class DangerousModuleTests(unittest.TestCase):
    def test_os_module_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _node("os", "system", "FunctionNode"))
            res = sk.scan_paths([p])
            rules = {f.rule: f for f in res.findings}
            self.assertIn("SKP001", rules)
            self.assertEqual(rules["SKP001"].severity, "CRITICAL")

    def test_submodule_of_dangerous_module_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _node("importlib.util", "find_spec", "FunctionNode"))
            res = sk.scan_paths([p])
            self.assertTrue(any(f.rule == "SKP001" for f in res.findings))

    def test_dangerous_builtin_is_critical(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _node("builtins", "eval", "FunctionNode"))
            res = sk.scan_paths([p])
            crit = [f for f in res.findings if f.rule == "SKP001"]
            self.assertEqual(len(crit), 1)
            self.assertEqual(crit[0].type_ref, "builtins.eval")

    def test_safe_builtin_container_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _node("builtins", "dict", "DictNode", content={}))
            res = sk.scan_paths([p])
            self.assertEqual(res.findings, [])


class TypeConfusionTests(unittest.TestCase):
    def test_operatorfuncnode_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(
                p,
                _node("operator", "attrgetter", "OperatorFuncNode", attrs=["x"]),
            )
            res = sk.scan_paths([p])
            hi = [f for f in res.findings if f.rule == "SKP002"]
            self.assertEqual(len(hi), 1)
            self.assertEqual(hi[0].severity, "HIGH")
            self.assertIn("CVE-2025-54412", hi[0].message)

    def test_methodnode_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(
                p,
                _node("sklearn.base", "BaseEstimator", "MethodNode", content={}),
            )
            res = sk.scan_paths([p])
            self.assertTrue(any(f.rule == "SKP002" for f in res.findings))


class UntrustedTypeTests(unittest.TestCase):
    def test_outside_allowlist_is_medium(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _node("thirdparty.estimators", "Weird", "ObjectNode"))
            res = sk.scan_paths([p])
            med = [f for f in res.findings if f.rule == "SKP003"]
            self.assertEqual(len(med), 1)
            self.assertEqual(med[0].severity, "MEDIUM")

    def test_trusted_prefix_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _node("xgboost.sklearn", "XGBClassifier", "ObjectNode"))
            res = sk.scan_paths([p])
            self.assertEqual(res.findings, [])


class JoblibFallbackTests(unittest.TestCase):
    def test_non_zip_skops_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.skops")
            with open(p, "wb") as fh:
                fh.write(b"\x80\x04not a zip, looks like a pickle")
            res = sk.scan_paths([p])
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].rule, "SKP010")
            self.assertEqual(res.findings[0].severity, "HIGH")
            self.assertIn("CVE-2025-54886", res.findings[0].message)

    def test_non_zip_non_skops_is_error_not_finding(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "notes.txt")
            with open(p, "wb") as fh:
                fh.write(b"hello")
            res = sk.scan_paths([p])
            self.assertEqual(res.findings, [])
            self.assertTrue(res.errors)

    def test_zip_without_schema_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            with zipfile.ZipFile(p, "w") as zf:
                zf.writestr("random.txt", "x")
            res = sk.scan_paths([p])
            self.assertEqual(res.findings, [])
            self.assertTrue(any("schema.json" in e for e in res.errors))


class DirectoryAndCliTests(unittest.TestCase):
    def test_directory_walk_finds_skops(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "models")
            os.makedirs(sub)
            _write_skops(os.path.join(sub, "a.skops"), _node("os", "system", "FunctionNode"))
            _write_skops(os.path.join(sub, "b.skops"), _clean_schema())
            res = sk.scan_paths([d])
            self.assertEqual(len(res.scanned_files), 2)
            self.assertTrue(any(f.rule == "SKP001" for f in res.findings))

    def test_missing_path_is_an_error(self):
        res = sk.scan_paths([os.path.join(tempfile.gettempdir(), "no_such_skops_x")])
        self.assertTrue(res.errors)
        self.assertEqual(res.findings, [])

    def _run(self, args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sk.main(args)
        return code, buf.getvalue()

    def test_json_output_and_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _node("subprocess", "Popen", "ObjectNode"))
            code, out = self._run([p, "--json", "--fail-on", "HIGH"])
            self.assertEqual(code, 1)
            payload = json.loads(out)
            self.assertEqual(payload["version"], sk.__version__)
            self.assertEqual(payload["findings"][0]["rule"], "SKP001")

    def test_clean_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.skops")
            _write_skops(p, _clean_schema())
            code, out = self._run([p, "--fail-on", "MEDIUM"])
            self.assertEqual(code, 0)
            self.assertIn("0 finding(s)", out)


if __name__ == "__main__":
    unittest.main()
