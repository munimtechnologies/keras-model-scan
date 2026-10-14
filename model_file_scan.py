#!/usr/bin/env python3
"""model-file-scan: one static, no-execution security scan for ML model files.

Unifies the scanners in this repository behind a single command:

  * ``.keras`` / ``.h5`` / ``.hdf5`` / ``config.json``  -> keras_model_scan
  * ``*.index.json`` (sharded-model index)              -> safetensors_index_scan
    (path safety of the weight_map: a shard path that is absolute, uses ``..``,
     or carries a URL scheme escapes the model directory -- CWE-22)
  * ``.safetensors``                                     -> safetensors_scan
    (header / offset integrity: the format has no code-execution surface, but
     malformed headers break hand-written loaders)
  * everything else (pickle & container formats)         -> pickle_model_scan
    (``.pkl`` ``.pickle`` ``.joblib`` ``.pt`` ``.pth`` ``.bin`` ``.npy``
     ``.npz`` ``.gguf`` ``.ckpt`` ``.model``)

It never loads, imports, unpickles or executes a model -- it only reads bytes
and disassembles opcode/JSON structure. Output is human text (default), JSON
(``--json``) or SARIF 2.1.0 (``--sarif``) for GitHub code scanning.

Made with AI by MV2 of Munim, Inc. Standard library only (Python 3.8+). Apache-2.0.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

__version__ = "0.7.0"

REPO_URL = "https://github.com/munimtechnologies/keras-model-scan"

# ---------------------------------------------------------------------------
# Routing -- which scanner owns a given path. Pure, no I/O.
# ---------------------------------------------------------------------------
_KERAS_EXTS = {".keras", ".h5", ".hdf5"}

_MODEL_EXTS = _KERAS_EXTS | {
    ".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin",
    ".npy", ".npz", ".safetensors", ".gguf", ".ckpt", ".model",
}


def route(path):
    """Return 'keras', 'sti', 'safetensors' or 'pickle' -- which scanner handles
    ``path``. A sharded-model index (``*.index.json``) is checked for weight_map
    path safety and must win over the generic ``.json`` -> keras rule."""
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if ext in _KERAS_EXTS:
        return "keras"
    if name.endswith(".index.json"):
        return "sti"
    if name == "config.json" or ext == ".json":
        return "keras"
    if ext == ".safetensors":
        return "safetensors"
    return "pickle"


def scan_path(path):
    """Dispatch one file to the right scanner and return its list of findings.

    Imports are lazy so this module loads even where the scanner modules are
    not importable (the tests rely on that)."""
    kind = route(path)
    if kind == "keras":
        import keras_model_scan as scanner
    elif kind == "sti":
        import safetensors_index_scan as scanner
    elif kind == "safetensors":
        import safetensors_scan as scanner
    else:
        import pickle_model_scan as scanner
    return scanner.scan_file(path)


def expand_paths(paths):
    """Expand files and directories into a (files, missing) pair.

    Directories are walked for files whose extension looks like a model file;
    files are kept as given; anything that does not exist is reported missing."""
    files = []
    missing = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, names in os.walk(p):
                for name in names:
                    low = name.lower()
                    ext = os.path.splitext(low)[1]
                    if (ext in _MODEL_EXTS or low == "config.json"
                            or low.endswith(".index.json")):
                        files.append(os.path.join(root, name))
        elif os.path.exists(p):
            files.append(p)
        else:
            missing.append(p)
    return files, missing


# ---------------------------------------------------------------------------
# Severity handling
# ---------------------------------------------------------------------------
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_FAIL_ON_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _as_dict(finding):
    """Accept either a scanner Finding (with ``as_dict``) or a plain dict."""
    if hasattr(finding, "as_dict"):
        return finding.as_dict()
    return dict(finding)


def _rank(severity):
    return _SEVERITY_RANK.get(str(severity).upper(), 0)


def worst_rank(results):
    """Highest severity rank across all findings, or -1 if there are none."""
    worst = -1
    for _path, findings in results:
        for f in findings:
            worst = max(worst, _rank(_as_dict(f)["severity"]))
    return worst


# ---------------------------------------------------------------------------
# SARIF 2.1.0 output (GitHub code scanning / upload-sarif)
# ---------------------------------------------------------------------------
_SARIF_LEVEL = {
    "CRITICAL": "error", "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note", "INFO": "note",
}
_SECURITY_SEVERITY = {
    "CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.0",
    "LOW": "3.0", "INFO": "0.0",
}


def _sarif_level(severity):
    return _SARIF_LEVEL.get(str(severity).upper(), "note")


def to_sarif(results):
    """Build a SARIF 2.1.0 document from ``[(path, [finding, ...]), ...]``."""
    rules = {}
    rule_order = []
    sarif_results = []
    for path, findings in results:
        uri = str(path).replace("\\", "/")
        for f in findings:
            d = _as_dict(f)
            rule_id = str(d["rule"])
            sev = str(d["severity"]).upper()
            if rule_id not in rules:
                rule_order.append(rule_id)
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": str(d.get("title") or rule_id)},
                    "helpUri": REPO_URL + "#checks",
                    "defaultConfiguration": {"level": _sarif_level(sev)},
                    "properties": {
                        "security-severity": _SECURITY_SEVERITY.get(sev, "0.0"),
                    },
                }
            message = str(d.get("title") or rule_id)
            if d.get("detail"):
                message += ": " + str(d["detail"])
            if d.get("cve"):
                message += " (" + str(d["cve"]) + ")"
            if d.get("location"):
                message += " [" + str(d["location"]) + "]"
            sarif_results.append({
                "ruleId": rule_id,
                "level": _sarif_level(sev),
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1},
                    },
                }],
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "model-file-scan",
                "informationUri": REPO_URL,
                "version": __version__,
                "rules": [rules[r] for r in rule_order],
            }},
            "results": sarif_results,
        }],
    }


def to_json(results):
    """Build a plain JSON summary from ``[(path, [finding, ...]), ...]``."""
    files = []
    for path, findings in results:
        files.append({
            "path": path,
            "findings": [_as_dict(f) for f in findings],
        })
    return {"tool": "model-file-scan", "version": __version__, "files": files}


def format_report(path, findings):
    """Human-readable report for one file."""
    if not findings:
        return "ok   " + str(path) + ": no findings"
    lines = ["scan " + str(path) + ": " + str(len(findings)) + " finding(s)"]
    for f in findings:
        d = _as_dict(f)
        cve = (" " + str(d["cve"])) if d.get("cve") else ""
        lines.append("  [" + str(d["severity"]) + "] " + str(d["rule"]) + cve
                     + ": " + str(d.get("title") or ""))
        if d.get("detail"):
            lines.append("      " + str(d["detail"]))
        if d.get("location"):
            lines.append("      at " + str(d["location"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="model-file-scan",
        description="Static, no-execution security scan for ML model files. "
                    "Never loads, imports, unpickles or executes a model.",
    )
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    out = parser.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="emit JSON")
    out.add_argument("--sarif", action="store_true",
                     help="emit SARIF 2.1.0 for GitHub code scanning")
    parser.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low", "info"],
        default="medium",
        help="minimum severity that sets a non-zero exit (default: medium)")
    parser.add_argument("--version", action="version",
                        version="model-file-scan " + __version__)
    args = parser.parse_args(argv)

    files, missing = expand_paths(args.paths)
    results = []
    errored = False
    for path in files:
        try:
            findings = scan_path(path)
        except Exception as exc:  # a single bad file must not crash the run
            errored = True
            print("error scanning " + str(path) + ": " + str(exc),
                  file=sys.stderr)
            continue
        results.append((path, findings))

    if args.sarif:
        print(json.dumps(to_sarif(results), indent=2))
    elif args.json:
        print(json.dumps(to_json(results), indent=2))
    else:
        if not results and not missing:
            print("no model files found")
        for path, findings in results:
            print(format_report(path, findings))
        for path in missing:
            print("not found: " + str(path), file=sys.stderr)

    if missing or errored:
        return 2
    if worst_rank(results) >= _FAIL_ON_RANK[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
