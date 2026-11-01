"""Tests for model_file_scan (the unified ML model-file scanner).

No model is ever loaded, unpickled or executed. Made with AI agents working in
the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import os
import shutil
import struct
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout

import model_file_scan as mfs


def finding(rule, severity, title="t", detail="", location="", cve=""):
    return {"rule": rule, "severity": severity, "title": title,
            "detail": detail, "location": location, "cve": cve}


def standalone(rule, severity, message="m", evidence="e"):
    return {"rule": rule, "severity": severity, "cve": "", "cwe": "CWE-20",
            "message": message, "evidence": evidence}


def _rules(findings):
    return set(mfs._as_dict(f)["rule"] for f in findings)


def _touch(path, data=b"x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _quiet(func, *args):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return func(*args)


# An XDR .rds holding R's NULL: format line, version 3, writer/reader R
# versions, native encoding "UTF-8", then NILVALUE_SXP (254).
_RDS_NULL = (b"X\n" + struct.pack(">iiii", 3, 263425, 197888, 5) + b"UTF-8"
             + struct.pack(">i", 254))

# The shapes the content routing looks at (not complete models).
_XGB_JSON = b'{"learner":{"gradient_booster":{}},"version":[3,0,0]}'
_XGB_UBJ = b"{L\x00\x00\x00\x00\x00\x00\x00\x07learner{}}"
_LGB_TEXT = b"tree\nversion=v4\nnum_class=1\n"
_KERAS_JSON = b'{"class_name":"Sequential","config":{"layers":[]}}'


class RouteTests(unittest.TestCase):
    def test_keras_exts(self):
        for p in ["m.keras", "weights.h5", "x.hdf5", "config.json",
                  os.path.join("sub", "config.json"), "arch.json"]:
            self.assertEqual(mfs.route(p), "keras", p)

    def test_sharded_index(self):
        self.assertEqual(mfs.route("model.safetensors.index.json"), "sti")

    def test_safetensors_and_gguf(self):
        for p in ["w.safetensors", "MODEL.SAFETENSORS",
                  os.path.join("sub", "model-00001-of-00002.safetensors")]:
            self.assertEqual(mfs.route(p), "safetensors", p)
        self.assertEqual(mfs.route("m.gguf"), "gguf")

    def test_pickle_exts(self):
        for p in ["m.pkl", "a.pickle", "sk.joblib", "t.pt", "t.pth",
                  "pytorch_model.bin", "a.npy", "a.npz", "state.ckpt",
                  "x.model", "unknown.xyz"]:
            self.assertEqual(mfs.route(p), "pickle", p)

    def test_standalone_formats(self):
        cases = {
            "m.tflite": "tflite",
            "program.pte": "executorch",
            "Model.mlmodel": "coreml",
            "Model.mlpackage": "coreml",
            "Model.mlpackage" + os.sep: "coreml",
            "inference.pdmodel": "paddle",
            "fit.rds": "r",
            "objects.rda": "r",
            "workspace.RData": "r",
            "flax_model.msgpack": "msgpack",
            "asr.nemo": "nemo",
            "model.onnx": "onnx",
            "openvino_model.xml": "openvino",
            "booster.ubj": "xgboost",
            "BOOSTER.UBJ": "xgboost",
        }
        for path, kind in cases.items():
            self.assertEqual(mfs.route(path), kind, path)

    def test_mlpackage_manifest_beats_json_rule(self):
        self.assertEqual(
            mfs.route(os.path.join("M.mlpackage", "Manifest.json")), "coreml")
        self.assertEqual(
            mfs.route(os.path.join("other", "Manifest.json")), "keras")

    def test_every_route_has_a_scanner_module(self):
        kinds = set(mfs._EXT_ROUTES.values()) | {
            "keras", "sti", "safetensors", "gguf", "pickle", "lightgbm"}
        self.assertEqual(kinds, set(mfs._SCANNERS))
        self.assertEqual(mfs._SCANNERS["xgboost"], "xgboost_model_scan")
        self.assertEqual(mfs._SCANNERS["lightgbm"], "lightgbm_model_scan")


class ContentRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _kinds(self, name, data):
        path = os.path.join(self.tmp, name)
        _touch(path, data)
        return mfs.route_kinds(path)

    def test_xgboost_json(self):
        self.assertEqual(self._kinds("model.json", _XGB_JSON), ["xgboost"])

    def test_pretty_printed_xgboost_json(self):
        data = b'{\n  "version": [3, 0, 0],\n  "learner": {}\n}\n'
        self.assertEqual(self._kinds("pretty.json", data), ["xgboost"])

    def test_keras_json_stays_keras(self):
        self.assertEqual(self._kinds("arch.json", _KERAS_JSON), ["keras"])

    def test_json_with_learner_and_other_keys_gets_both(self):
        data = b'{"learner":{},"class_name":"Sequential","config":{}}'
        self.assertEqual(self._kinds("both.json", data), ["xgboost", "keras"])

    def test_learner_that_is_not_an_object_stays_keras(self):
        self.assertEqual(self._kinds("odd.json", b'{"learner":1}'), ["keras"])

    def test_invalid_or_non_object_json_stays_keras(self):
        self.assertEqual(self._kinds("bad.json", b"{"), ["keras"])
        self.assertEqual(self._kinds("list.json", b"[1, 2]"), ["keras"])
        self.assertEqual(self._kinds("bom.json", b"\xef\xbb\xbf" + _XGB_JSON),
                         ["keras"])

    def test_config_json_is_never_rerouted(self):
        self.assertEqual(self._kinds("config.json", _XGB_JSON), ["keras"])

    def test_index_json_is_never_rerouted(self):
        self.assertEqual(
            self._kinds("model.safetensors.index.json", _XGB_JSON), ["sti"])

    def test_model_and_bst_by_content(self):
        self.assertEqual(self._kinds("a.model", _XGB_UBJ), ["xgboost"])
        self.assertEqual(self._kinds("b.bst", b"  " + _XGB_JSON), ["xgboost"])
        self.assertEqual(self._kinds("c.model", _LGB_TEXT), ["lightgbm"])
        self.assertEqual(self._kinds("d.bst", b"tree\r\nversion=v4\r\n"),
                         ["lightgbm"])
        self.assertEqual(self._kinds("e.model", b"\x80\x04N."), ["pickle"])
        self.assertEqual(self._kinds("f.bst", b"binf\x00\x00"), ["pickle"])

    def test_txt_by_content(self):
        self.assertEqual(self._kinds("model.txt", _LGB_TEXT), ["lightgbm"])
        self.assertEqual(self._kinds("trees.txt", b"trees\n"), ["pickle"])
        self.assertEqual(self._kinds("notes.txt", b"hello"), ["pickle"])
        self.assertEqual(self._kinds("brace.txt", _XGB_JSON), ["pickle"])
        self.assertEqual(self._kinds("m.lgb", _LGB_TEXT), ["lightgbm"])
        self.assertEqual(self._kinds("M.LightGBM", _LGB_TEXT), ["lightgbm"])
        self.assertEqual(self._kinds("other.lgb", b"\x80\x04N."), ["pickle"])

    def test_other_extensions_ignore_content(self):
        self.assertEqual(self._kinds("w.pkl", _XGB_JSON), ["pickle"])
        self.assertEqual(self._kinds("w.bin", _LGB_TEXT), ["pickle"])
        self.assertEqual(self._kinds("w.ubj", b"anything"), ["xgboost"])

    def test_directory_is_not_read(self):
        pkg = os.path.join(self.tmp, "M.mlpackage")
        os.makedirs(pkg)
        self.assertEqual(mfs.route_kinds(pkg), ["coreml"])

    def test_scan_path_runs_every_routed_scanner(self):
        path = os.path.join(self.tmp, "both.json")
        _touch(path, b'{"learner":{},"class_name":"X"}')
        made = []
        for mod, rule in (("_mfs_fake_a", "A1"), ("_mfs_fake_b", "B1")):
            m = types.ModuleType(mod)
            m.scan_file = (lambda r: lambda p: [standalone(r, "high")])(rule)
            sys.modules[mod] = m
            made.append(mod)
        saved = dict(mfs._SCANNERS)
        try:
            mfs._SCANNERS["xgboost"] = "_mfs_fake_a"
            mfs._SCANNERS["keras"] = "_mfs_fake_b"
            self.assertEqual(_rules(mfs.scan_path(path)), {"A1", "B1"})
        finally:
            mfs._SCANNERS.clear()
            mfs._SCANNERS.update(saved)
            for mod in made:
                sys.modules.pop(mod, None)


class ExpandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rel(self, files):
        return set(os.path.relpath(f, self.tmp) for f in files)

    def test_walk_picks_new_formats_and_skips_others(self):
        for name in ["a.tflite", "b.rds", "c.xml", "c.bin", "d.xml",
                     "notes.txt", os.path.join("deep", "p.pte"),
                     os.path.join("M.mlpackage", "Manifest.json"),
                     os.path.join("M.mlpackage", "Data", "w.bin")]:
            _touch(os.path.join(self.tmp, name))
        files, missing = mfs.expand_paths([self.tmp])
        self.assertEqual(missing, [])
        self.assertEqual(self._rel(files), {
            "a.tflite", "b.rds", "c.xml", "c.bin",
            os.path.join("deep", "p.pte"), "M.mlpackage"})

    def test_walk_picks_tree_models_by_content(self):
        files_data = {
            "xgb.json": _XGB_JSON,
            "package.json": b'{"name": "x"}',
            "arch.json": _KERAS_JSON,
            "booster.ubj": _XGB_UBJ,
            "lgb.txt": _LGB_TEXT,
            "readme.txt": b"tree house\n",
            "requirements.txt": b"lightgbm\n",
            "legacy.bst": b"binf",
            "m.lgb": _LGB_TEXT,
            "x.lightgbm": b"hello",
        }
        for name, data in files_data.items():
            _touch(os.path.join(self.tmp, name), data)
        files, missing = mfs.expand_paths([self.tmp])
        self.assertEqual(missing, [])
        self.assertEqual(self._rel(files), {"xgb.json", "booster.ubj",
                                            "lgb.txt", "m.lgb"})

    def test_explicit_mlpackage_is_kept_whole(self):
        pkg = os.path.join(self.tmp, "M.mlpackage")
        _touch(os.path.join(pkg, "Manifest.json"))
        files, missing = mfs.expand_paths([pkg])
        self.assertEqual((files, missing), ([pkg], []))

    def test_explicit_txt_is_kept_as_given(self):
        p = os.path.join(self.tmp, "notes.txt")
        _touch(p, b"hello")
        self.assertEqual(mfs.expand_paths([p]), ([p], []))

    def test_missing(self):
        gone = os.path.join(self.tmp, "nope.rds")
        self.assertEqual(mfs.expand_paths([gone]), ([], [gone]))


class AsDictTests(unittest.TestCase):
    def test_standalone_shape_is_normalized(self):
        d = mfs._as_dict(standalone("RDS002", "high", "calls", "f > g"))
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["title"], "calls")
        self.assertEqual(d["location"], "f > g")
        self.assertEqual(d["cwe"], "CWE-20")

    def test_existing_shape_is_unchanged(self):
        d = mfs._as_dict(finding("SFT009", "MEDIUM", "trailing", "x", "y"))
        self.assertEqual((d["title"], d["detail"], d["location"]),
                         ("trailing", "x", "y"))

    def test_input_is_not_mutated(self):
        f = standalone("CML001", "high")
        mfs._as_dict(f)
        self.assertNotIn("title", f)
        self.assertEqual(f["severity"], "high")

    def test_object_with_as_dict(self):
        class Obj:
            def as_dict(self):
                return finding("OED001", "HIGH")
        self.assertEqual(mfs._as_dict(Obj())["rule"], "OED001")


class SarifTests(unittest.TestCase):
    def test_document_shape(self):
        doc = mfs.to_sarif([("m.pkl", [finding("PKL001", "CRITICAL")])])
        self.assertEqual(doc["version"], "2.1.0")
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "model-file-scan")
        self.assertEqual(driver["version"], mfs.__version__)

    def test_levels_and_security_severity(self):
        results = [("a", [finding("R1", "CRITICAL"), finding("R2", "HIGH"),
                          finding("R3", "MEDIUM"), finding("R4", "LOW"),
                          finding("R5", "INFO")])]
        run = mfs.to_sarif(results)["runs"][0]
        levels = [r["level"] for r in run["results"]]
        self.assertEqual(levels, ["error", "error", "warning", "note", "note"])
        sev = {r["id"]: r["properties"]["security-severity"]
               for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(sev["R1"], "9.0")
        self.assertEqual(sev["R3"], "5.0")

    def test_lowercase_standalone_severity(self):
        run = mfs.to_sarif([("x.rds", [standalone("RDS001", "high")])])["runs"][0]
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertIn("[e]", run["results"][0]["message"]["text"])

    def test_windows_paths_and_rule_dedup(self):
        results = [("dir\\m.pkl", [finding("R1", "HIGH"), finding("R1", "HIGH")])]
        run = mfs.to_sarif(results)["runs"][0]
        uri = run["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"]["uri"]
        self.assertEqual(uri, "dir/m.pkl")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["results"]), 2)

    def test_empty(self):
        run = mfs.to_sarif([])["runs"][0]
        self.assertEqual(run["results"], [])


class ThresholdTests(unittest.TestCase):
    def test_worst_rank(self):
        self.assertEqual(mfs.worst_rank([]), -1)
        self.assertEqual(mfs.worst_rank([("a", [])]), -1)
        self.assertEqual(mfs.worst_rank(
            [("a", [finding("R", "LOW")]), ("b", [finding("R", "HIGH")])]), 3)
        self.assertEqual(mfs.worst_rank([("a", [standalone("R", "medium")])]), 2)


class FormatTests(unittest.TestCase):
    def test_clean(self):
        self.assertIn("no findings", mfs.format_report("m.pkl", []))

    def test_findings(self):
        text = mfs.format_report("m.pkl", [finding(
            "PKL001", "HIGH", "bad import", cve="CVE-2025-0001")])
        self.assertIn("[HIGH] PKL001 CVE-2025-0001: bad import", text)

    def test_standalone_finding(self):
        text = mfs.format_report("x.rds", [standalone(
            "RDS002", "high", "stored code calls", "x.rds > function")])
        self.assertIn("[HIGH] RDS002: stored code calls", text)
        self.assertIn("at x.rds > function", text)


class JsonTests(unittest.TestCase):
    def test_shape(self):
        doc = mfs.to_json([("m.pkl", [finding("R", "LOW")])])
        self.assertEqual(doc["tool"], "model-file-scan")
        self.assertEqual(doc["files"][0]["path"], "m.pkl")
        self.assertEqual(doc["files"][0]["findings"][0]["rule"], "R")


class MainTests(unittest.TestCase):
    def test_missing_file_exit_2(self):
        self.assertEqual(_quiet(mfs.main, ["does-not-exist-xyz.pkl"]), 2)

    def test_empty_dir_exit_0(self):
        d = tempfile.mkdtemp()
        try:
            self.assertEqual(_quiet(mfs.main, [d]), 0)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class IntegrationWiringTests(unittest.TestCase):
    """Verify the unified tool calls the real standalone scanners. Skipped if
    a scanner module is not importable here."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _scan(self, path):
        try:
            return mfs.scan_path(path)
        except ImportError:
            self.skipTest("scanner module not importable in this environment")

    def test_r_null_object_is_clean(self):
        p = os.path.join(self.tmp, "null.rds")
        _touch(p, _RDS_NULL)
        self.assertEqual(self._scan(p), [])
        self.assertEqual(_quiet(mfs.main, [p]), 0)

    def test_r_garbage_is_rds004_and_fails_on_medium(self):
        p = os.path.join(self.tmp, "junk.rds")
        _touch(p, b"not an rds file")
        self.assertEqual(_rules(self._scan(p)), {"RDS004"})
        self.assertEqual(_quiet(mfs.main, [p, "--fail-on", "medium"]), 1)
        self.assertEqual(_quiet(mfs.main, [p, "--fail-on", "high"]), 0)

    def test_coreml_package_without_manifest(self):
        pkg = os.path.join(self.tmp, "Empty.mlpackage")
        os.makedirs(pkg)
        self.assertIn("CML005", _rules(self._scan(pkg)))
        self.assertEqual(_quiet(mfs.main, [self.tmp, "--fail-on", "medium"]), 1)

    def test_paddle_garbage_stays_in_its_rules(self):
        p = os.path.join(self.tmp, "junk.pdmodel")
        _touch(p, b"\xff\xfe\xfd\xfc not a program")
        rules = _rules(self._scan(p))
        self.assertTrue(all(r.startswith("PDL") for r in rules), rules)

    def test_truncated_ubj_reaches_the_xgboost_scanner(self):
        p = os.path.join(self.tmp, "cut.ubj")
        _touch(p, b"{L")
        rules = _rules(self._scan(p))
        self.assertTrue(rules, rules)
        self.assertTrue(all(r.startswith("XGB") for r in rules), rules)

    def test_xgboost_json_reaches_the_xgboost_scanner(self):
        p = os.path.join(self.tmp, "model.json")
        _touch(p, b'{"learner":{"gradient_booster":7},"version":[3,0,0]}')
        rules = _rules(self._scan(p))
        self.assertTrue(all(r.startswith("XGB") for r in rules), rules)

    def test_lightgbm_text_reaches_the_lightgbm_scanner(self):
        p = os.path.join(self.tmp, "model.txt")
        _touch(p, _LGB_TEXT)
        rules = _rules(self._scan(p))
        self.assertTrue(all(r.startswith("LGB") for r in rules), rules)


if __name__ == "__main__":
    unittest.main()
