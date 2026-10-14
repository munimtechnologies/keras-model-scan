#!/usr/bin/env python3
"""Tests for model_file_scan (the unified ML model-file scanner).

The unit's own logic -- routing, SARIF/JSON output, formatting, exit codes --
is tested hard with synthetic findings. Integration with the real scanner
modules is tested only for wiring (does it import them and get a list back),
and those tests skip cleanly where the scanners are not importable.

No model is ever loaded, unpickled or executed. The one pickle used below is a
benign hand-built opcode stream (a reference to collections.OrderedDict) and is
never passed to pickle.loads -- only the static scanner reads it.
"""
import os
import struct
import tempfile
import unittest

import model_file_scan as mfs


def finding(rule, severity, title="t", detail="d", location=None, cve=None):
    return {"rule": rule, "severity": severity, "title": title,
            "detail": detail, "location": location, "cve": cve}


class RouteTests(unittest.TestCase):
    def test_keras_exts(self):
        for p in ["m.keras", "weights.h5", "x.hdf5", "config.json",
                  os.path.join("sub", "config.json"), "arch.json"]:
            self.assertEqual(mfs.route(p), "keras", p)

    def test_safetensors_ext(self):
        for p in ["w.safetensors", "MODEL.SAFETENSORS",
                  os.path.join("sub", "model-00001-of-00002.safetensors")]:
            self.assertEqual(mfs.route(p), "safetensors", p)

    def test_pickle_exts(self):
        for p in ["m.pkl", "a.pickle", "sk.joblib", "t.pt", "t.pth",
                  "pytorch_model.bin", "a.npy", "a.npz",
                  "m.gguf", "state.ckpt", "x.model", "unknown.xyz"]:
            self.assertEqual(mfs.route(p), "pickle", p)


class SarifTests(unittest.TestCase):
    def test_structure(self):
        results = [("models/a.pkl",
                    [finding("PKL001", "CRITICAL", cve="CWE-502")])]
        doc = mfs.to_sarif(results)
        self.assertEqual(doc["version"], "2.1.0")
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "model-file-scan")
        self.assertEqual(driver["version"], mfs.__version__)
        self.assertIn("munimtechnologies", driver["informationUri"])
        self.assertIn("PKL001", [r["id"] for r in driver["rules"]])
        res = doc["runs"][0]["results"][0]
        self.assertEqual(res["ruleId"], "PKL001")
        self.assertEqual(res["level"], "error")
        loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(loc, "models/a.pkl")
        self.assertIn("CWE-502", res["message"]["text"])

    def test_level_and_security_severity_mapping(self):
        pairs = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                 "LOW": "note", "INFO": "note"}
        for sev, level in pairs.items():
            doc = mfs.to_sarif([("f", [finding("R", sev)])])
            self.assertEqual(doc["runs"][0]["results"][0]["level"], level, sev)
            rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
            self.assertIn("security-severity", rule["properties"])

    def test_windows_path_normalised(self):
        doc = mfs.to_sarif([("models\\a.pkl", [finding("R", "LOW")])])
        uri = doc["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "models/a.pkl")

    def test_rule_deduped(self):
        doc = mfs.to_sarif([("a", [finding("R", "LOW"), finding("R", "LOW")])])
        self.assertEqual(len(doc["runs"][0]["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(doc["runs"][0]["results"]), 2)

    def test_empty(self):
        doc = mfs.to_sarif([])
        self.assertEqual(doc["runs"][0]["results"], [])
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["rules"], [])


class ThresholdTests(unittest.TestCase):
    def test_worst_rank(self):
        results = [("a", [finding("R", "LOW"), finding("R2", "HIGH")])]
        self.assertEqual(mfs.worst_rank(results), mfs._SEVERITY_RANK["HIGH"])

    def test_no_findings(self):
        self.assertEqual(mfs.worst_rank([("a", [])]), -1)


class FormatTests(unittest.TestCase):
    def test_clean(self):
        self.assertIn("no findings", mfs.format_report("a.pkl", []))

    def test_findings(self):
        out = mfs.format_report(
            "a.pkl", [finding("PKL001", "CRITICAL", title="bad", cve="CVE-1")])
        self.assertIn("PKL001", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("bad", out)
        self.assertIn("CVE-1", out)


class JsonTests(unittest.TestCase):
    def test_shape(self):
        doc = mfs.to_json([("a.pkl", [finding("PKL001", "HIGH")])])
        self.assertEqual(doc["tool"], "model-file-scan")
        self.assertEqual(doc["files"][0]["path"], "a.pkl")
        self.assertEqual(doc["files"][0]["findings"][0]["rule"], "PKL001")


class MainTests(unittest.TestCase):
    def test_missing_file_exit_2(self):
        self.assertEqual(mfs.main(["does-not-exist-xyz.pkl"]), 2)

    def test_empty_dir_exit_0(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(mfs.main([d]), 0)


def _write_safetensors(path, trailing=b""):
    header = b'{"w":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}'
    with open(path, "wb") as fh:
        fh.write(struct.pack("<Q", len(header)) + header + b"\x00" * 4
                 + trailing)


def _rules(findings):
    return {mfs._as_dict(f)["rule"] for f in findings}


class IntegrationWiringTests(unittest.TestCase):
    """Verify the unified tool actually calls the real scanners and gets a list
    back. Skipped if the scanner modules are not importable here."""

    def _scan(self, path):
        try:
            return mfs.scan_path(path)
        except ImportError:
            self.skipTest("scanner modules not importable in this environment")

    def test_safetensors_routed_to_integrity_validator(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.safetensors")
            _write_safetensors(p)
            self.assertEqual(_rules(self._scan(p)), {"SFT000"})

    def test_safetensors_trailing_bytes_fail_ci(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.safetensors")
            _write_safetensors(p, trailing=b"hidden")
            self.assertIn("SFT009", _rules(self._scan(p)))
            try:
                code = mfs.main([d, "--fail-on", "medium"])
            except ImportError:
                self.skipTest("scanner modules not importable in this environment")
            self.assertEqual(code, 1)

    def test_pickle_wiring(self):
        # Benign opcode stream: PROTO 2, GLOBAL 'collections OrderedDict', STOP.
        payload = b"\x80\x02ccollections\nOrderedDict\n."
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "benign.pkl")
            with open(p, "wb") as fh:
                fh.write(payload)
            self.assertIsInstance(self._scan(p), list)


if __name__ == "__main__":
    unittest.main()
