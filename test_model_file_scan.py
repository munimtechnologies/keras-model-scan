#!/usr/bin/env python3
"""Tests for model_file_scan (the unified ML model-file scanner).

The unit's own logic -- routing, SARIF/JSON output, formatting, exit codes --
is tested hard with synthetic findings. Integration with the real scanner
modules is tested only for wiring (does it import them and get a list back),
and those tests skip cleanly where the scanners are not importable.

No model is ever loaded, unpickled or executed. The one pickle used below is a
hand-built opcode stream written from byte constants and is never passed to
pickle.loads -- only the static scanner reads it.
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

    def test_pickle_exts(self):
        for p in ["m.pkl", "a.pickle", "sk.joblib", "t.pt", "t.pth",
                  "pytorch_model.bin", "a.npy", "a.npz", "w.safetensors",
                  "m.gguf", "state.ckpt", "x.model", "unknown.xyz"]:
            self.assertEqual(mfs.route(p), "pickle", p)


class SarifTests(unittest.TestCase):
    def test_structure(self):
        results = [("models/a.pkl",
                    [finding("PKL001", "CRITICAL", cve="CVE-2025-1550")])]
        doc = mfs.to_sarif(results)
        self.assertEqual(doc["version"], "2.1.0")
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "model-file-scan")
        self.assertEqual(driver["version"], mfs.__version__)
        self.assertIn("PKL001", [r["id"] for r in driver["rules"]])
        res = doc["runs"][0]["results"][0]
        self.assertEqual(res["ruleId"], "PKL001")
        self.assertEqual(res["level"], "error")
        loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(loc, "models/a.pkl")
        self.assertIn("CVE-2025-1550", res["message"]["text"])

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


def _write_safetensors(path):
    header = b'{"__metadata__":{}}'
    with open(path, "wb") as fh:
        fh.write(struct.pack("<Q", len(header)) + header)


class IntegrationWiringTests(unittest.TestCase):
    """Verify the unified tool actually calls the real scanners and gets a list
    back. Skipped if the scanner modules are not importable here."""

    def _scan(self, path):
        try:
            return mfs.scan_path(path)
        except ImportError:
            self.skipTest("scanner modules not importable in this environment")

    def test_safetensors_wiring(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.safetensors")
            _write_safetensors(p)
            self.assertIsInstance(self._scan(p), list)

    def test_pickle_wiring(self):
        # Hand-built opcode stream equivalent to os.system('id') via
        # STACK_GLOBAL + REDUCE. Built from byte constants; never unpickled.
        payload = (
            b"\x80\x04"            # PROTO 4
            b"\x8c\x02os\x94"      # SHORT_BINUNICODE 'os'; MEMOIZE
            b"\x8c\x06system\x94"  # SHORT_BINUNICODE 'system'; MEMOIZE
            b"\x93"                # STACK_GLOBAL -> os.system
            b"\x8c\x02id\x94"      # SHORT_BINUNICODE 'id'; MEMOIZE
            b"\x85"                # TUPLE1
            b"\x52"                # REDUCE
            b"\x2e"                # STOP
        )
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "evil.pkl")
            with open(p, "wb") as fh:
                fh.write(payload)
            self.assertIsInstance(self._scan(p), list)


if __name__ == "__main__":
    unittest.main()
