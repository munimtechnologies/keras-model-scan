# Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""Consistency tests for the shipped coverage matrix (data, not linter rules).

coverage_matrix_lint checks the SHAPE of scanner_coverage.json; these tests check
that the shipped JSON passes it with no findings, and that the human-readable table
in SCANNER_COVERAGE_MATRIX.md says exactly what the JSON says, row for row and cell
for cell. Like the linter, they assert no security facts of their own.
"""

import json
import os
import unittest

from coverage_matrix_lint import lint_matrix

HERE = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(HERE, "scanner_coverage.json")
MD_PATH = os.path.join(HERE, "SCANNER_COVERAGE_MATRIX.md")

SYMBOL = {
    "detects": "✓",
    "partial": "~",
    "no": "✗",
    "out-of-scope": "–",
    "unknown": "?",
}


def load_json():
    with open(JSON_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def table_rows(md_text):
    """Return (header_ids, rows) from the '| Attack vector' table.

    Each row is (title, [symbol, ...]) in column order.
    """
    lines = md_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith("| Attack vector"):
            start = i
            break
    if start is None:
        raise AssertionError("matrix table header not found")

    def split(line):
        return [c.strip() for c in line.strip().strip("|").split("|")]

    header_ids = split(lines[start])[1:]
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        cells = split(line)
        rows.append((cells[0], cells[1:]))
    return header_ids, rows


class TestScannerCoverageData(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = load_json()
        with open(MD_PATH, "r", encoding="utf-8") as fh:
            cls.header_ids, cls.rows = table_rows(fh.read())
        cls.status = {(c["vector"], c["scanner"]): c["status"] for c in cls.data["cells"]}

    def test_json_lints_clean(self):
        findings = lint_matrix(self.data)
        self.assertEqual(findings, [], "shipped matrix should have no ERROR or WARN")

    def test_table_columns_match_scanners(self):
        self.assertEqual(self.header_ids, [s["id"] for s in self.data["scanners"]])

    def test_one_table_row_per_vector(self):
        self.assertEqual(len(self.rows), len(self.data["vectors"]))

    def test_table_cells_match_json(self):
        scanner_ids = [s["id"] for s in self.data["scanners"]]
        for (title, symbols), vector in zip(self.rows, self.data["vectors"]):
            expected = [SYMBOL[self.status[(vector["id"], sid)]] for sid in scanner_ids]
            self.assertEqual(symbols, expected,
                             "row %r does not match vector %s" % (title, vector["id"]))

    def test_sources_are_https(self):
        for c in self.data["cells"]:
            for src in c.get("sources", []):
                self.assertTrue(src.startswith("https://"),
                                "%s/%s source %r" % (c["vector"], c["scanner"], src))

    def test_positive_kms_cells_point_at_this_repository(self):
        repo = "https://github.com/munimtechnologies/keras-model-scan"
        for c in self.data["cells"]:
            if c["scanner"] == "kms" and c["status"] in ("detects", "partial"):
                self.assertTrue(any(s.startswith(repo) for s in c["sources"]),
                                "kms cell for %s cites no detector doc" % c["vector"])

    def test_config_instantiation_rows_present(self):
        ids = {v["id"] for v in self.data["vectors"]}
        for vid in ("cfg-hydra", "cfg-pyannote", "cfg-st-modules",
                    "cfg-jsonargparse", "ckpt-lightning"):
            self.assertIn(vid, ids)


if __name__ == "__main__":
    unittest.main()
