# Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""Self-contained tests for coverage_matrix_lint.lint_matrix.

These use inline fixture dicts only; they do NOT read scanner_coverage.json and do
NOT import any scanner. They verify the linter's structural rules, not security facts.
"""

import unittest

from coverage_matrix_lint import lint_matrix, ALLOWED_STATUS, NEEDS_SOURCE


def base_valid():
    """A minimal, structurally complete, valid matrix (1 vector x 1 scanner)."""
    return {
        "schema": "mv2-scanner-coverage/1",
        "generated": "2026-10-15",
        "methodology": "doc-based review",
        "scanners": [{"id": "a", "name": "Scanner A"}],
        "vectors": [{"id": "x", "title": "Vector X"}],
        "cells": [
            {"vector": "x", "scanner": "a", "status": "detects",
             "note": "ok", "sources": ["https://example.test/a"]},
        ],
    }


def levels(findings):
    return [lvl for lvl, _ in findings]


class TestCoverageMatrixLint(unittest.TestCase):

    def test_valid_matrix_is_clean(self):
        findings = lint_matrix(base_valid())
        self.assertEqual(findings, [], "a complete valid matrix should produce no findings")

    def test_missing_top_level_key_is_error(self):
        data = base_valid()
        del data["methodology"]
        findings = lint_matrix(data)
        self.assertIn("ERROR", levels(findings))
        self.assertTrue(any("methodology" in m for _, m in findings))

    def test_invalid_status_is_error(self):
        data = base_valid()
        data["cells"][0]["status"] = "maybe"
        findings = lint_matrix(data)
        self.assertIn("ERROR", levels(findings))
        self.assertTrue(any("invalid status" in m for _, m in findings))

    def test_unknown_vector_reference_is_error(self):
        data = base_valid()
        data["cells"][0]["vector"] = "zzz"
        findings = lint_matrix(data)
        self.assertIn("ERROR", levels(findings))
        self.assertTrue(any("unknown vector" in m for _, m in findings))

    def test_unknown_scanner_reference_is_error(self):
        data = base_valid()
        data["cells"][0]["scanner"] = "nope"
        findings = lint_matrix(data)
        self.assertTrue(any("unknown scanner" in m for _, m in findings))

    def test_duplicate_cell_is_error(self):
        data = base_valid()
        data["cells"].append(dict(data["cells"][0]))
        findings = lint_matrix(data)
        self.assertTrue(any("duplicate cell" in m for _, m in findings))

    def test_positive_claim_without_source_is_error(self):
        data = base_valid()
        data["cells"][0]["sources"] = []
        findings = lint_matrix(data)
        self.assertIn("ERROR", levels(findings))
        self.assertTrue(any("requires at least one source" in m for _, m in findings))

    def test_non_positive_status_without_source_is_ok(self):
        data = base_valid()
        data["cells"][0]["status"] = "out-of-scope"
        data["cells"][0]["sources"] = []
        findings = lint_matrix(data)
        self.assertEqual(findings, [])

    def test_missing_scanner_name_is_warn_not_error(self):
        data = base_valid()
        data["scanners"][0] = {"id": "a"}
        findings = lint_matrix(data)
        self.assertNotIn("ERROR", levels(findings))
        self.assertIn("WARN", levels(findings))

    def test_incomplete_matrix_warns(self):
        data = base_valid()
        data["scanners"].append({"id": "b", "name": "Scanner B"})
        # no cell for (x, b)
        findings = lint_matrix(data)
        self.assertNotIn("ERROR", levels(findings))
        self.assertTrue(any("no cell for vector/scanner: x/b" in m for _, m in findings))

    def test_status_constants_are_consistent(self):
        # NEEDS_SOURCE must be a subset of the allowed statuses.
        self.assertTrue(NEEDS_SOURCE.issubset(ALLOWED_STATUS))


if __name__ == "__main__":
    unittest.main()
