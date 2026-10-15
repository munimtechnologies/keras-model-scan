# test_cve_map_lint.py
#
# Self-contained tests for cve_map_lint.py. Imports only cve_map_lint and the
# standard library, and builds every fixture inline, so the publish test_first
# sandbox can run it in isolation without the real advisory map files present.
# No CVE/GHSA/CWE fact is asserted here -- only structural behaviour of the linter.
#
# Made with AI by MV2 of Munim, Inc. Licence: Apache-2.0.

import copy
import json
import os
import tempfile
import unittest

import cve_map_lint as lint


def _valid_map():
    """A minimal, structurally-complete advisory map that must lint clean."""
    return {
        "name": "cross-format advisory map",
        "version": "1.0",
        "license": "CC BY 4.0",
        "made_with": "AI agents at MV2 of Munim, Inc.",
        "verified_at": "2026-10-15",
        "description": "structural fixture",
        "coverage_legend": {
            "full": "detected",
            "partial": "partially detected",
            "class": "class-level",
            "gap": "not detected",
            "out-of-scope": "not a static target",
        },
        "formats": {
            "pickle": {
                "code_execution_surface": True,
                "detector_module": "pickle_model_scan",
                "note": "opcode scan",
            },
        },
        "entries": [
            {
                "id": "CVE-2024-3660",
                "aliases": ["GHSA-xxxx-yyyy-zzzz"],
                "format": "pickle",
                "project": "example",
                "ecosystem": "PyPI",
                "mechanism": "deserialization",
                "trigger_field": "opcode",
                "cwe": ["CWE-94"],
                "cvss": 9.8,
                "affected": "<1.0",
                "fixed": "1.0",
                "detector": {
                    "module": "pickle_model_scan",
                    "rule": "PKL001",
                    "coverage": "full",
                },
                "verified": "2026-10-15",
            }
        ],
    }


def _codes(findings):
    return {f.code for f in findings}


def _errors(findings):
    return [f for f in findings if f.severity == lint.ERROR]


class ValidMapTests(unittest.TestCase):
    def test_valid_map_has_no_findings(self):
        self.assertEqual(lint.lint_map(_valid_map()), [])

    def test_root_must_be_object(self):
        findings = lint.lint_map([1, 2, 3])
        self.assertIn("CML001", _codes(findings))
        self.assertTrue(_errors(findings))


class TopLevelTests(unittest.TestCase):
    def test_missing_top_level_key_is_error(self):
        data = _valid_map()
        del data["formats"]
        findings = lint.lint_map(data)
        self.assertIn("CML002", _codes(findings))
        self.assertTrue(_errors(findings))

    def test_wrong_license_is_warning_only(self):
        data = _valid_map()
        data["license"] = "MIT"
        findings = lint.lint_map(data)
        self.assertIn("CML003", _codes(findings))
        self.assertEqual(_errors(findings), [])

    def test_made_with_without_ai_warns(self):
        data = _valid_map()
        data["made_with"] = "a person"
        findings = lint.lint_map(data)
        self.assertIn("CML004", _codes(findings))
        self.assertEqual(_errors(findings), [])

    def test_empty_formats_block_warns(self):
        data = _valid_map()
        data["formats"] = {}
        # entry format "pickle" is no longer declared -> that part is skipped
        findings = lint.lint_map(data)
        self.assertIn("CML007", _codes(findings))


class FormatBlockTests(unittest.TestCase):
    def test_format_record_missing_key_is_error(self):
        data = _valid_map()
        del data["formats"]["pickle"]["note"]
        findings = lint.lint_map(data)
        self.assertIn("CML009", _codes(findings))

    def test_code_execution_surface_must_be_bool(self):
        data = _valid_map()
        data["formats"]["pickle"]["code_execution_surface"] = "yes"
        findings = lint.lint_map(data)
        self.assertIn("CML010", _codes(findings))


class EntryTests(unittest.TestCase):
    def test_missing_entry_field_is_error(self):
        data = _valid_map()
        del data["entries"][0]["mechanism"]
        findings = lint.lint_map(data)
        self.assertIn("CML014", _codes(findings))

    def test_undeclared_format_is_error(self):
        data = _valid_map()
        data["entries"][0]["format"] = "exe"
        findings = lint.lint_map(data)
        self.assertIn("CML018", _codes(findings))

    def test_duplicate_id_is_error(self):
        data = _valid_map()
        data["entries"].append(copy.deepcopy(data["entries"][0]))
        findings = lint.lint_map(data)
        self.assertIn("CML015", _codes(findings))

    def test_unrecognised_id_is_info_not_error(self):
        data = _valid_map()
        data["entries"][0]["id"] = "PICKLE-RCE-CLASS"
        findings = lint.lint_map(data)
        self.assertIn("CML016", _codes(findings))
        self.assertEqual(_errors(findings), [])

    def test_empty_cwe_is_error(self):
        data = _valid_map()
        data["entries"][0]["cwe"] = []
        findings = lint.lint_map(data)
        self.assertIn("CML019", _codes(findings))

    def test_bad_cwe_token_is_error(self):
        data = _valid_map()
        data["entries"][0]["cwe"] = ["CWE-94", "502"]
        findings = lint.lint_map(data)
        self.assertIn("CML020", _codes(findings))

    def test_cvss_out_of_range_is_error(self):
        data = _valid_map()
        data["entries"][0]["cvss"] = 12.0
        findings = lint.lint_map(data)
        self.assertIn("CML023", _codes(findings))

    def test_cvss_bool_rejected(self):
        data = _valid_map()
        data["entries"][0]["cvss"] = True
        findings = lint.lint_map(data)
        self.assertIn("CML022", _codes(findings))

    def test_cvss_null_is_allowed(self):
        data = _valid_map()
        data["entries"][0]["cvss"] = None
        self.assertEqual(lint.lint_map(data), [])

    def test_entries_must_be_list(self):
        data = _valid_map()
        data["entries"] = "nope"
        findings = lint.lint_map(data)
        self.assertIn("CML011", _codes(findings))


class DetectorTests(unittest.TestCase):
    def test_detector_keys_must_match_exactly(self):
        data = _valid_map()
        del data["entries"][0]["detector"]["coverage"]
        findings = lint.lint_map(data)
        self.assertIn("CML026", _codes(findings))

    def test_coverage_not_in_legend_is_error(self):
        data = _valid_map()
        data["entries"][0]["detector"]["coverage"] = "bogus"
        findings = lint.lint_map(data)
        self.assertIn("CML027", _codes(findings))

    def test_full_coverage_requires_module_and_rule(self):
        data = _valid_map()
        data["entries"][0]["detector"]["rule"] = None
        findings = lint.lint_map(data)
        self.assertIn("CML028", _codes(findings))

    def test_out_of_scope_requires_null_rule(self):
        data = _valid_map()
        data["entries"][0]["detector"]["coverage"] = "out-of-scope"
        data["entries"][0]["detector"]["rule"] = "PKL001"
        findings = lint.lint_map(data)
        self.assertIn("CML029", _codes(findings))

    def test_out_of_scope_with_null_rule_is_clean(self):
        data = _valid_map()
        data["entries"][0]["detector"]["coverage"] = "out-of-scope"
        data["entries"][0]["detector"]["rule"] = None
        self.assertEqual(lint.lint_map(data), [])


class FileAndCliTests(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_load_and_lint_missing_file(self):
        findings = lint.load_and_lint(
            os.path.join(tempfile.gettempdir(), "does-not-exist-9z8q.json"))
        self.assertIn("CML000", _codes(findings))

    def test_load_and_lint_bad_json(self):
        path = self._write("{not valid json")
        findings = lint.load_and_lint(path)
        self.assertIn("CML000", _codes(findings))

    def test_load_and_lint_valid_file(self):
        path = self._write(json.dumps(_valid_map()))
        self.assertEqual(lint.load_and_lint(path), [])

    def test_cli_returns_zero_on_valid(self):
        path = self._write(json.dumps(_valid_map()))
        self.assertEqual(lint.main([path]), 0)

    def test_cli_returns_one_on_error(self):
        bad = _valid_map()
        bad["entries"][0]["cwe"] = []
        path = self._write(json.dumps(bad))
        self.assertEqual(lint.main([path]), 1)

    def test_cli_quiet_returns_zero_on_warning_only(self):
        warn_only = _valid_map()
        warn_only["license"] = "MIT"
        path = self._write(json.dumps(warn_only))
        self.assertEqual(lint.main(["--quiet", path]), 0)


class FindingTests(unittest.TestCase):
    def test_finding_str_contains_code_and_location(self):
        f = lint.Finding("CML999", lint.ERROR, "where", "what")
        s = str(f)
        self.assertIn("CML999", s)
        self.assertIn("where", s)
        self.assertIn("ERROR", s)


if __name__ == "__main__":
    unittest.main()
