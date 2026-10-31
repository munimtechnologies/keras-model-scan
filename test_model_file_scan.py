"""Tests for model_file_scan (the unified ML model-file scanner).

No model is ever loaded, unpickled or executed. Made with AI agents working in
the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import os
import shutil
import struct
import tempfile
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
            "keras", "sti", "safetensors", "gguf", "pickle"}
        self.assertEqual(kinds, set(mfs._SCANNERS))


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

    def test_explicit_mlpackage_is_kept_whole(self):
        pkg = os.path.join(self.tmp, "M.mlpackage")
        _touch(os.path.join(pkg, "Manifest.json"))
        files, missing = mfs.expand_paths([pkg])
        self.assertEqual((files, missing), ([pkg], []))

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


if __name__ == "__main__":
    unittest.main()
