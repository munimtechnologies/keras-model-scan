"""Self-contained validation of model_file_cve_map.json.

Made with AI, by MV2 of Munim, Inc. Imports only the standard library and reads
the dataset sitting next to it, so it needs no other module in the repo. Run with:
    python -m unittest -v test_model_file_cve_map
"""
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "model_file_cve_map.json")

ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|[a-z0-9-]+)$")
CWE_RE = re.compile(r"^CWE-\d+$")
ALIAS_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|TALOS-\d{4}-\d+|VDB-\d+)$")

REQUIRED_TOP = {"name", "version", "license", "made_with", "verified_at",
                "description", "coverage_legend", "formats", "entries"}
REQUIRED_ENTRY = {"id", "aliases", "format", "project", "ecosystem", "mechanism",
                  "trigger_field", "cwe", "cvss", "affected", "fixed",
                  "detector", "verified"}
REQUIRED_DETECTOR = {"module", "rule", "coverage"}


class TestModelFileCveMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(DATA_PATH, encoding="utf-8") as fh:
            cls.data = json.load(fh)

    def test_top_level_shape(self):
        self.assertTrue(REQUIRED_TOP.issubset(self.data), REQUIRED_TOP - set(self.data))
        self.assertEqual(self.data["license"], "CC BY 4.0")
        self.assertIn("AI", self.data["made_with"])
        self.assertIsInstance(self.data["entries"], list)
        self.assertGreaterEqual(len(self.data["entries"]), 20)

    def test_formats_block(self):
        fmts = self.data["formats"]
        for name, body in fmts.items():
            self.assertIn("code_execution_surface", body)
            self.assertIsInstance(body["code_execution_surface"], bool)
            self.assertIn("detector_module", body)
            self.assertIn("note", body)

    def test_entries_have_required_fields(self):
        for e in self.data["entries"]:
            missing = REQUIRED_ENTRY - set(e)
            self.assertFalse(missing, f"{e.get('id')} missing {missing}")
            self.assertTrue(ID_RE.match(e["id"]), f"bad id {e['id']}")
            self.assertIn(e["format"], self.data["formats"], e["id"])
            self.assertTrue(e["cwe"], f"{e['id']} has no CWE")
            for cwe in e["cwe"]:
                self.assertTrue(CWE_RE.match(cwe), f"{e['id']} bad cwe {cwe}")
            for alias in e["aliases"]:
                self.assertTrue(ALIAS_RE.match(alias), f"{e['id']} bad alias {alias}")
            self.assertTrue(str(e["mechanism"]).strip(), f"{e['id']} empty mechanism")
            self.assertTrue(str(e["verified"]).strip(), f"{e['id']} empty verified")

    def test_detector_and_coverage(self):
        legend = set(self.data["coverage_legend"])
        for e in self.data["entries"]:
            det = e["detector"]
            self.assertEqual(REQUIRED_DETECTOR, set(det), e["id"])
            self.assertIn(det["coverage"], legend, f"{e['id']} coverage {det['coverage']}")
            # full/partial coverage must name a concrete module and rule
            if det["coverage"] in ("full", "partial"):
                self.assertTrue(det["module"], f"{e['id']} full/partial needs a module")
                self.assertTrue(det["rule"], f"{e['id']} full/partial needs a rule")
            # gap/out-of-scope must NOT claim a detecting rule
            if det["coverage"] == "out-of-scope":
                self.assertIsNone(det["rule"], f"{e['id']} out-of-scope must not name a rule")

    def test_cvss_range(self):
        for e in self.data["entries"]:
            if e["cvss"] is not None:
                self.assertIsInstance(e["cvss"], (int, float), e["id"])
                self.assertGreaterEqual(e["cvss"], 0.0)
                self.assertLessEqual(e["cvss"], 10.0)

    def test_no_duplicate_ids(self):
        ids = [e["id"] for e in self.data["entries"]]
        dupes = {i for i in ids if ids.count(i) > 1}
        self.assertFalse(dupes, f"duplicate ids: {dupes}")

    def test_every_format_represented(self):
        seen = {e["format"] for e in self.data["entries"]}
        self.assertEqual(seen, set(self.data["formats"]),
                         f"formats with no entry: {set(self.data['formats']) - seen}")

    def test_verified_cves_this_run(self):
        # The five identifiers re-checked at source this run must carry
        # the exact facts verified, so a silent edit can't drift them.
        by_id = {e["id"]: e for e in self.data["entries"]}
        checks = {
            "CVE-2024-3660": ("keras", "CWE-94", 9.8),
            "CVE-2025-1550": ("keras", "CWE-94", 7.3),
            "CVE-2025-71325": ("pickle", "CWE-391", 9.3),
            "CVE-2025-71339": ("pickle", "CWE-502", 7.6),
            "CVE-2022-25882": ("onnx", "CWE-22", 7.5),
            "CVE-2024-5187": ("onnx", "CWE-22", 8.8),
        }
        for cve, (fmt, cwe, cvss) in checks.items():
            self.assertIn(cve, by_id, cve)
            self.assertEqual(by_id[cve]["format"], fmt, cve)
            self.assertIn(cwe, by_id[cve]["cwe"], cve)
            self.assertEqual(by_id[cve]["cvss"], cvss, cve)


if __name__ == "__main__":
    unittest.main()
