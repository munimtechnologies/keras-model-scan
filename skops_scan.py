#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Static, no-execution type auditor for skops (.skops) model files.

Background
----------
``skops`` is promoted as a *safe* alternative to pickle for sharing
scikit-learn models. A ``.skops`` file is a ZIP archive whose ``schema.json``
describes the object as a tree of **nodes**; every node carries the exact
keys ``"__class__"``, ``"__module__"`` and ``"__loader__"``. On load, skops
walks this tree and only reconstructs a type if it is *trusted* - trusted by
default, or passed in ``load(..., trusted=[...])``. ``get_untrusted_types``
lets a user review the requested types first.

That trust boundary has been broken three times in 2025, all RCE at load time:

* ``CVE-2025-54412`` (CWE-351, CVSS 8.7, fixed 0.12.0) - an inconsistency in
  the **OperatorFuncNode** lets a file request one (seemingly safe) trusted
  type while a *different* operator method is actually executed: a code-reuse
  attack confirmed by trusting only a few innocent-looking types.
* ``CVE-2025-54413`` (CWE-351, CVSS 8.7, fixed 0.12.0) - the **MethodNode**
  can reach unexpected object fields via dot notation, reaching arbitrary code
  with even fewer trusted-type assumptions.
* ``CVE-2025-54886`` (CWE-502, CVSS ~8.4, fixed 0.13.0) - ``Card.get_model``
  silently falls back to **joblib** (i.e. pickle, arbitrary code execution)
  when the model file is *not* a valid ZIP, bypassing skops' type validation.

This tool reads a ``.skops`` file's ``schema.json`` **only**. It never
imports, reconstructs, unpickles, downloads or executes anything. It lists the
types the file would ask you to trust and flags the code-execution-capable
ones - the same information ``get_untrusted_types`` shows, available before you
ever call ``load``.

Rules
-----
* ``SKP001`` (CRITICAL) - a node whose ``__module__`` is an operating-system /
  process / eval sink (``os``, ``subprocess``, ``importlib`` ...), or a
  dangerous ``builtins`` callable (``eval``, ``exec``, ``getattr`` ...). These
  have no legitimate place in a serialised estimator and are the payload of a
  code-execution attack.
* ``SKP002`` (HIGH) - an ``OperatorFuncNode`` or ``MethodNode`` loader, or any
  node in the ``operator`` module. These are the exact type-confusion /
  code-reuse mechanisms of ``CVE-2025-54412`` and ``CVE-2025-54413``.
* ``SKP003`` (MEDIUM) - any other object/function/type node whose module is
  outside a conservative ML allow-list (``numpy``, ``scipy``, ``sklearn``,
  ``pandas``, ``builtins``, ``collections``). skops will ask you to confirm
  these as trusted; review them before loading.
* ``SKP010`` (HIGH) - a ``*.skops`` path that is **not** a valid ZIP archive.
  ``skops.io.load`` rejects it, but ``Card.get_model`` silently loads it with
  joblib (pickle), which runs arbitrary code (``CVE-2025-54886``).

Honest limits
-------------
* This is a review aid, not an exploit, and claims no new CVE. It documents
  skops' own trust model so an auto-loadable type is visible before load.
* It cannot perfectly reproduce skops' built-in trusted set, which changes
  across versions; SKP003 is a conservative "please review", not a verdict. A
  type outside the allow-list is often perfectly legitimate.
* It reads ``schema.json`` only: it never inspects the actual data blobs, so it
  cannot confirm what a node would do - only which type the file requests.
* The real fix is upgrading to skops ``>= 0.13.0``, loading only from trusted
  sources, and auditing ``get_untrusted_types`` output. A clean scan guarantees
  nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from dataclasses import dataclass, field
from typing import Any, Iterable

__version__ = "0.1.0"

# The manifest member inside every .skops ZIP archive.
SCHEMA_MEMBER = "schema.json"

# The three keys every skops node dict carries (plus "__id__").
NODE_KEYS = ("__class__", "__module__", "__loader__")

# Fixed-in versions for the three load-time RCE CVEs.
FIXED_TYPE_CONFUSION = "0.12.0"  # CVE-2025-54412, CVE-2025-54413
FIXED_JOBLIB_FALLBACK = "0.13.0"  # CVE-2025-54886

# SKP001: modules that are operating-system / process / eval sinks. A trusted
# estimator never serialises a reference into any of these.
DANGEROUS_MODULES = frozenset(
    {
        "os",
        "posix",
        "nt",
        "subprocess",
        "sys",
        "socket",
        "shutil",
        "pty",
        "importlib",
        "runpy",
        "code",
        "codeop",
        "pickle",
        "_pickle",
        "marshal",
        "ctypes",
        "multiprocessing",
        "pdb",
        "webbrowser",
    }
)

# SKP001: builtins callables that execute or reach arbitrary code/attributes.
DANGEROUS_BUILTINS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
        "open",
        "input",
        "breakpoint",
        "exit",
        "quit",
    }
)

# SKP002: loaders that are the documented type-confusion / code-reuse vectors.
RISKY_LOADERS = frozenset({"OperatorFuncNode", "MethodNode"})

# SKP003: top-level packages skops reconstructs as part of ordinary ML models.
# A module outside this set is a "please review", not a verdict.
TRUSTED_PREFIXES = frozenset(
    {
        "numpy",
        "scipy",
        "sklearn",
        "pandas",
        "builtins",
        "collections",
        "skops",
        "xgboost",
        "lightgbm",
    }
)

# Loaders that are purely structural (containers / leaves): never SKP003.
STRUCTURAL_LOADERS = frozenset(
    {
        "DictNode",
        "DefaultDictNode",
        "ListNode",
        "SetNode",
        "TupleNode",
        "JsonNode",
        "BytesNode",
        "BytearrayNode",
        "CachedNode",
        "SliceNode",
    }
)

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    loader: str
    type_ref: str
    message: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "file": self.file,
            "loader": self.loader,
            "type": self.type_ref,
            "message": self.message,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def is_node(obj: Any) -> bool:
    """True if ``obj`` is a skops schema node (has the three node keys)."""
    return isinstance(obj, dict) and all(k in obj for k in NODE_KEYS)


def iter_nodes(obj: Any) -> Iterable[dict]:
    """Yield every skops node dict found anywhere in a parsed schema tree."""
    if isinstance(obj, dict):
        if is_node(obj):
            yield obj
        for value in obj.values():
            yield from iter_nodes(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_nodes(item)


def _top_package(module: str) -> str:
    return module.split(".", 1)[0] if module else ""


def _classify(node: dict, path: str) -> Finding | None:
    """Return the highest-severity Finding for one node, or None if benign."""
    module = str(node.get("__module__", "") or "")
    cls = str(node.get("__class__", "") or "")
    loader = str(node.get("__loader__", "") or "")
    type_ref = f"{module}.{cls}" if module else cls

    # SKP001 - OS / process / eval sink module, or dangerous builtin callable.
    if _top_package(module) in DANGEROUS_MODULES or module in DANGEROUS_MODULES:
        return Finding(
            "SKP001",
            "CRITICAL",
            path,
            loader,
            type_ref,
            (
                f"skops schema requests type '{type_ref}', whose module is an "
                "operating-system / process / code-execution sink. A trusted "
                "scikit-learn model never serialises this. Treat the file as "
                "untrusted and do not load it."
            ),
        )
    if module == "builtins" and cls in DANGEROUS_BUILTINS:
        return Finding(
            "SKP001",
            "CRITICAL",
            path,
            loader,
            type_ref,
            (
                f"skops schema requests the builtin '{cls}', which executes or "
                "reaches arbitrary code/attributes (eval/exec/getattr-class). "
                "This is the payload shape of a load-time code-execution "
                "attack; do not load the file."
            ),
        )

    # SKP002 - the documented OperatorFuncNode / MethodNode type-confusion path.
    if loader in RISKY_LOADERS or module == "operator":
        return Finding(
            "SKP002",
            "HIGH",
            path,
            loader,
            type_ref,
            (
                f"skops node uses loader '{loader}' / module '{module}', the "
                "operator / method code-reuse surface abused by CVE-2025-54412 "
                "and CVE-2025-54413 (type confusion, fixed in skops "
                f"{FIXED_TYPE_CONFUSION}). Review this type and load only with "
                "skops >= "
                f"{FIXED_TYPE_CONFUSION}."
            ),
        )

    # SKP003 - a non-structural type outside the conservative ML allow-list.
    if loader and loader not in STRUCTURAL_LOADERS:
        if _top_package(module) not in TRUSTED_PREFIXES:
            return Finding(
                "SKP003",
                "MEDIUM",
                path,
                loader,
                type_ref,
                (
                    f"skops will ask you to trust type '{type_ref}' "
                    f"(loader '{loader}'), which is outside the common "
                    "numpy/scipy/sklearn/pandas set. Confirm it is expected "
                    "before loading (this is a review signal, not proof of "
                    "malice)."
                ),
            )
    return None


def scan_schema(schema: Any, path: str, result: ScanResult) -> None:
    """Classify every node in a parsed ``schema.json`` tree."""
    for node in iter_nodes(schema):
        finding = _classify(node, path)
        if finding is not None:
            result.findings.append(finding)


def scan_file(path: str, result: ScanResult) -> None:
    """Inspect one ``.skops`` file: read schema.json and audit its types."""
    if not zipfile.is_zipfile(path):
        # A .skops path that is not a ZIP: skops.io.load rejects it, but
        # Card.get_model silently falls back to joblib (pickle) -> RCE.
        if path.lower().endswith(".skops"):
            result.scanned_files.append(path)
            result.findings.append(
                Finding(
                    "SKP010",
                    "HIGH",
                    path,
                    "",
                    "",
                    (
                        "This '.skops' file is not a valid ZIP archive. "
                        "skops.io.load rejects it, but Card.get_model silently "
                        "falls back to joblib (pickle), which executes "
                        "arbitrary code on load (CVE-2025-54886, fixed in "
                        f"skops {FIXED_JOBLIB_FALLBACK}). Do not pass it to "
                        "Card.get_model."
                    ),
                )
            )
        else:
            result.errors.append(f"{path}: not a ZIP archive (not a .skops file?)")
        return

    result.scanned_files.append(path)
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if SCHEMA_MEMBER not in names:
                result.errors.append(
                    f"{path}: ZIP has no {SCHEMA_MEMBER} (not a skops file?)"
                )
                return
            raw = zf.read(SCHEMA_MEMBER)
    except (zipfile.BadZipFile, OSError) as exc:
        result.errors.append(f"{path}: cannot read archive: {exc}")
        return

    try:
        schema = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        result.errors.append(f"{path}: {SCHEMA_MEMBER} is not valid JSON: {exc}")
        return

    scan_schema(schema, path, result)


def scan_paths(paths: Iterable[str]) -> ScanResult:
    """Scan files and directories; directories are walked for ``*.skops``."""
    result = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for name in sorted(files):
                    if name.lower().endswith(".skops"):
                        scan_file(os.path.join(root, name), result)
        elif os.path.isfile(p):
            scan_file(p, result)
        else:
            result.errors.append(f"{p}: not a file or directory")
    return result


def _max_severity(findings: list[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skops_scan",
        description=(
            "Static type auditor for skops (.skops) model files. Reads "
            "schema.json only - no import, no reconstruction, no network, "
            "stdlib only. Lists the types a file asks you to trust and flags "
            "code-execution-capable ones (CVE-2025-54412/54413/54886)."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="directories to walk for *.skops, or individual files to inspect",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="NONE",
        help="exit non-zero if a finding at or above this severity is present",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    result = scan_paths(args.paths)

    if args.json:
        print(
            json.dumps(
                {
                    "version": __version__,
                    "scanned_files": result.scanned_files,
                    "findings": [f.as_dict() for f in result.findings],
                    "errors": result.errors,
                },
                indent=2,
            )
        )
    else:
        for f in result.findings:
            print(f"[{f.severity}] {f.rule} {f.file} ({f.type_ref}): {f.message}")
        for e in result.errors:
            print(f"[ERROR] {e}", file=sys.stderr)
        print(
            f"\nScanned {len(result.scanned_files)} skops file(s); "
            f"{len(result.findings)} finding(s)."
        )

    threshold = SEVERITY_ORDER[args.fail_on]
    if threshold > 0 and _max_severity(result.findings) >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
