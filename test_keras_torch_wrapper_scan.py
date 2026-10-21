# test_keras_torch_wrapper_scan.py - local, no-network regression test.
# Builds minimal .keras ZIP archives (and raw config.json) with hand-written
# serialized configs; no keras/torch import needed for a static config scan.
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.
import json
import os
import tempfile
import unittest
import zipfile

import keras_torch_wrapper_scan as m


def _write_keras(path, config, extra=None):
    """Write a minimal .keras ZIP carrying the given config.json (and optional
    extra members). No weights/torch payload is needed for a static scan."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.14.0"}))
        if extra:
            for n, data in extra.items():
                zf.writestr(n, data)


def _dense(name="dense"):
    return {"module": "keras.layers", "class_name": "Dense",
            "config": {"name": name, "units": 8}, "registered_name": None}


def _torch_wrapper(name="torch_module_wrapper"):
    return {"module": "keras.layers", "class_name": "TorchModuleWrapper",
            "config": {"name": name}, "registered_name": None}


class TestKerasTorchWrapperScan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def _p(self, n):
        return os.path.join(self.d, n)

    def _rules(self, path):
        return {f["rule"] for f in m.scan(path)}

    def test_torch_wrapper_in_keras_archive_is_ktw001(self):
        p = self._p("model.keras")
        _write_keras(p, {
            "module": "keras", "class_name": "Sequential",
            "config": {"name": "seq", "layers": [_dense(), _torch_wrapper()]},
            "registered_name": None})
        f = m.scan(p)
        self.assertIn("KTW001", {x["rule"] for x in f})
        hit = [x for x in f if x["rule"] == "KTW001"][0]
        self.assertEqual(hit["cve"], "CVE-2026-12484")
        self.assertEqual(hit["cwe"], "CWE-502")
        self.assertEqual(hit["level"], "HIGH")

    def test_ktw001_cites_both_cves_and_regression(self):
        p = self._p("both.keras")
        _write_keras(p, {"layers": [_torch_wrapper()]})
        hit = [x for x in m.scan(p) if x["rule"] == "KTW001"][0]
        self.assertEqual(hit["related_cve"], "CVE-2025-49655")
        # Message names both advisories and the regression it spans.
        self.assertIn("CVE-2026-12484", hit["message"])
        self.assertIn("CVE-2025-49655", hit["message"])
        self.assertIn("regress", hit["message"])

    def test_registered_name_variant_is_ktw001(self):
        p = self._p("reg.keras")
        _write_keras(p, {"class_name": "CustomObj",
                         "registered_name": "TorchModuleWrapper",
                         "config": {}})
        self.assertIn("KTW001", self._rules(p))

    def test_raw_config_json_is_ktw001(self):
        p = self._p("config.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"layers": [_torch_wrapper()]}))
        self.assertIn("KTW001", self._rules(p))

    def test_nested_deeply_is_detected(self):
        p = self._p("nested.keras")
        _write_keras(p, {"a": {"b": {"c": [_dense(), {"d": _torch_wrapper()}]}}})
        self.assertIn("KTW001", self._rules(p))

    def test_clean_keras_no_findings(self):
        p = self._p("clean.keras")
        _write_keras(p, {
            "module": "keras", "class_name": "Sequential",
            "config": {"name": "seq", "layers": [_dense("d1"), _dense("d2")]},
            "registered_name": None})
        self.assertEqual(m.scan(p), [])

    def test_one_finding_per_wrapper(self):
        p = self._p("two.keras")
        _write_keras(p, {"layers": [_torch_wrapper("a"), _torch_wrapper("b")]})
        ktw = [f for f in m.scan(p) if f["rule"] == "KTW001"]
        self.assertEqual(len(ktw), 2)

    def test_archive_without_config_is_ktw000(self):
        p = self._p("noconfig.keras")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("metadata.json", "{}")
        self.assertIn("KTW000", self._rules(p))

    def test_malformed_config_is_ktw000(self):
        p = self._p("bad.keras")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("config.json", "{not valid json")
        self.assertIn("KTW000", self._rules(p))

    def test_unreadable_is_ktw000(self):
        p = self._p("missing.keras")  # never created
        self.assertIn("KTW000", self._rules(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
