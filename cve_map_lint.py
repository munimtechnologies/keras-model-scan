# cve_map_lint.py
#
# Structural linter for the cross-format advisory maps shipped in this repo
# (model_file_cve_map.json, gguf_cve_map.json). It validates the *shape* of an
# advisory map -- required keys, field types, value ranges, internal consistency
# -- and deliberately re-asserts NO CVE / GHSA / CWE identifiers or facts. Those
# live, verified, in the map files themselves and in test_model_file_cve_map.py;
# this tool only checks that the structure around them is well formed, so a fork
# or a future edit that adds an entry gets a clear, line-free structural report.
#
# Dependency-free: Python standard library only, no execution of model files.
# Usage:
#   python cve_map_lint.py model_file_cve_map.json [more.json ...]
#   python cve_map_lint.py --quiet model_file_cve_map.json   # errors only
# Exit code is non-zero if any ERROR-severity finding is produced.
#
# Made with AI by MV2 of Munim, Inc. Licence: Apache-2.0.

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

# Identifier families we recognise. An id outside these is only an INFO finding,
# never an error, so this linter cannot spuriously reject a valid, verified map.
_ID_PATTERNS = (
    re.compile(r"^CVE-\d{4}-\d{4,}$"),
    re.compile(r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
               r"-[23456789cfghjmpqrvwx]{4}$"),
    re.compile(r"^CWE-\d+$"),
)
_CWE_PATTERN = re.compile(r"^CWE-\d+$")

_REQUIRED_TOP_LEVEL = (
    "name", "version", "license", "made_with", "verified_at",
    "description", "coverage_legend", "formats", "entries",
)

# Each entry (advisory record) must carry these fields.
_REQUIRED_ENTRY = (
    "id", "aliases", "format", "project", "ecosystem", "mechanism",
    "trigger_field", "cwe", "cvss", "affected", "fixed", "detector", "verified",
)

# A format record under "formats" must carry these fields.
_REQUIRED_FORMAT = ("code_execution_surface", "detector_module", "note")

_DETECTOR_KEYS = frozenset(("module", "rule", "coverage"))

_EXPECTED_LICENSE = "CC BY 4.0"

# Severity ordering so callers can filter.
ERROR = "ERROR"
WARN = "WARN"
INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity:5} {self.code} {self.location}: {self.message}"


def _is_str(v) -> bool:
    return isinstance(v, str)


def lint_map(data) -> list[Finding]:
    """Lint one parsed advisory map. Returns a list of Finding, possibly empty."""
    out: list[Finding] = []

    if not isinstance(data, dict):
        return [Finding("CML001", ERROR, "<root>",
                        "advisory map must be a JSON object")]

    # --- top level -------------------------------------------------------
    for key in _REQUIRED_TOP_LEVEL:
        if key not in data:
            out.append(Finding("CML002", ERROR, "<root>",
                               f"missing required top-level key {key!r}"))

    lic = data.get("license")
    if lic is not None and lic != _EXPECTED_LICENSE:
        out.append(Finding("CML003", WARN, "license",
                           f"license is {lic!r}, expected {_EXPECTED_LICENSE!r} "
                           f"for a data file"))

    made = data.get("made_with")
    if _is_str(made) and "AI" not in made:
        out.append(Finding("CML004", WARN, "made_with",
                           "made_with should disclose the work was made with AI"))

    legend = data.get("coverage_legend")
    legend_keys: set = set()
    if legend is not None:
        if not isinstance(legend, dict):
            out.append(Finding("CML005", ERROR, "coverage_legend",
                               "coverage_legend must be an object"))
        else:
            legend_keys = set(legend)

    # --- formats block ---------------------------------------------------
    formats = data.get("formats")
    declared_formats: set = set()
    if formats is not None:
        if not isinstance(formats, dict):
            out.append(Finding("CML006", ERROR, "formats",
                               "formats must be an object keyed by format name"))
        elif not formats:
            out.append(Finding("CML007", WARN, "formats",
                               "formats block is empty"))
        else:
            declared_formats = set(formats)
            for fmt, rec in formats.items():
                loc = f"formats.{fmt}"
                if not isinstance(rec, dict):
                    out.append(Finding("CML008", ERROR, loc,
                                       "format record must be an object"))
                    continue
                for fk in _REQUIRED_FORMAT:
                    if fk not in rec:
                        out.append(Finding("CML009", ERROR, loc,
                                           f"missing format key {fk!r}"))
                if "code_execution_surface" in rec and not isinstance(
                        rec["code_execution_surface"], bool):
                    out.append(Finding("CML010", ERROR, loc,
                                       "code_execution_surface must be a boolean"))

    # --- entries ---------------------------------------------------------
    entries = data.get("entries")
    if entries is None:
        return out
    if not isinstance(entries, list):
        out.append(Finding("CML011", ERROR, "entries",
                           "entries must be a list"))
        return out
    if not entries:
        out.append(Finding("CML012", WARN, "entries", "entries list is empty"))

    seen_ids: dict[str, int] = {}
    for i, entry in enumerate(entries):
        loc = f"entries[{i}]"
        if not isinstance(entry, dict):
            out.append(Finding("CML013", ERROR, loc, "entry must be an object"))
            continue

        for fk in _REQUIRED_ENTRY:
            if fk not in entry:
                out.append(Finding("CML014", ERROR, loc,
                                   f"missing entry field {fk!r}"))

        eid = entry.get("id")
        if _is_str(eid):
            loc = f"entries[{i}] id={eid}"
            if eid in seen_ids:
                out.append(Finding("CML015", ERROR, loc,
                                   f"duplicate id (first seen at index "
                                   f"{seen_ids[eid]})"))
            else:
                seen_ids[eid] = i
            if not any(p.match(eid) for p in _ID_PATTERNS):
                out.append(Finding("CML016", INFO, loc,
                                   "id is not a recognised CVE/GHSA/CWE form"))
        elif eid is not None:
            out.append(Finding("CML017", ERROR, loc, "id must be a string"))

        fmt = entry.get("format")
        if _is_str(fmt) and declared_formats and fmt not in declared_formats:
            out.append(Finding("CML018", ERROR, loc,
                               f"format {fmt!r} is not declared in the formats "
                               f"block"))

        cwe = entry.get("cwe")
        if cwe is not None:
            if not isinstance(cwe, list) or not cwe:
                out.append(Finding("CML019", ERROR, loc,
                                   "cwe must be a non-empty list"))
            else:
                for c in cwe:
                    if not (_is_str(c) and _CWE_PATTERN.match(c)):
                        out.append(Finding("CML020", ERROR, loc,
                                           f"cwe entry {c!r} must match CWE-<n>"))

        aliases = entry.get("aliases")
        if aliases is not None and not isinstance(aliases, list):
            out.append(Finding("CML021", ERROR, loc, "aliases must be a list"))

        cvss = entry.get("cvss")
        if cvss is not None:
            if not isinstance(cvss, (int, float)) or isinstance(cvss, bool):
                out.append(Finding("CML022", ERROR, loc,
                                   "cvss must be a number or null"))
            elif not (0.0 <= float(cvss) <= 10.0):
                out.append(Finding("CML023", ERROR, loc,
                                   f"cvss {cvss} is outside 0.0-10.0"))

        for sk in ("mechanism", "verified"):
            sv = entry.get(sk)
            if sv is not None and (not _is_str(sv) or not sv.strip()):
                out.append(Finding("CML024", ERROR, loc,
                                   f"{sk} must be a non-empty string"))

        det = entry.get("detector")
        if det is not None:
            if not isinstance(det, dict):
                out.append(Finding("CML025", ERROR, loc,
                                   "detector must be an object"))
            else:
                if set(det) != _DETECTOR_KEYS:
                    out.append(Finding("CML026", ERROR, loc,
                                       f"detector keys must be exactly "
                                       f"{sorted(_DETECTOR_KEYS)}"))
                cov = det.get("coverage")
                if _is_str(cov) and legend_keys and cov not in legend_keys:
                    out.append(Finding("CML027", ERROR, loc,
                                       f"detector coverage {cov!r} is not in "
                                       f"coverage_legend"))
                if cov in ("full", "partial"):
                    if not det.get("module") or not det.get("rule"):
                        out.append(Finding("CML028", ERROR, loc,
                                           f"coverage {cov!r} requires a module "
                                           f"and rule"))
                elif cov == "out-of-scope":
                    if det.get("rule") is not None:
                        out.append(Finding("CML029", ERROR, loc,
                                           "out-of-scope coverage must have "
                                           "rule null"))

    return out


def load_and_lint(path: str) -> list[Finding]:
    """Read a JSON file and lint it. A parse/IO failure is itself a Finding."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return [Finding("CML000", ERROR, path, "file not found")]
    except json.JSONDecodeError as exc:
        return [Finding("CML000", ERROR, path, f"invalid JSON: {exc}")]
    return lint_map(data)


def _run(argv) -> int:
    ap = argparse.ArgumentParser(
        description="Structural linter for repo advisory maps "
                    "(re-asserts no CVE/GHSA/CWE facts).")
    ap.add_argument("paths", nargs="+", help="advisory map JSON file(s)")
    ap.add_argument("--quiet", action="store_true",
                    help="print ERROR findings only")
    args = ap.parse_args(argv)

    had_error = False
    for path in args.paths:
        findings = load_and_lint(path)
        shown = [f for f in findings if not (args.quiet and f.severity != ERROR)]
        errors = sum(1 for f in findings if f.severity == ERROR)
        had_error = had_error or errors > 0
        header = f"== {path}: {errors} error(s), {len(findings)} finding(s) =="
        print(header)
        for f in shown:
            print("  " + str(f))
    return 1 if had_error else 0


def main(argv=None) -> int:
    return _run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
