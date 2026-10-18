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
#
# This file and the detector it implements were made with AI.
"""Static, no-execution detector for the MLflow ``MLmodel`` manifest
loader-dispatch surface.

Background
----------
Every MLflow model is described by a small YAML manifest named ``MLmodel`` that
sits at the root of the model directory. Its ``flavors`` block records how to
load the model. The generic ``python_function`` flavor carries a
``loader_module`` key -- a dotted Python module path::

    artifact_path: model
    flavors:
      python_function:
        loader_module: mlflow.statsmodels
        model_path: model.pkl
        python_version: 3.10.12
      statsmodels:
        data: model.statsmodels
        statsmodels_version: 0.14.0
    mlflow_version: 2.9.2

When any process calls ``mlflow.pyfunc.load_model()`` on such a directory,
MLflow reads ``loader_module`` from the ``MLmodel`` file and resolves it with
``importlib.import_module(loader_module)`` -- **with no allowlist** -- then calls
that module's ``_load_pyfunc`` entry point. The dotted string in the manifest
therefore selects which code runs at load time.

Public precedent (all already disclosed; this detector documents the class, it
does not introduce a new exploit):

* ``GHSA-gqvg-gmmx-x4hm`` (mlflow, PyPI, introduced 2.1.0, fixed **3.15.0**,
  CWE-502, CVSS 8.8). MLflow offers an ``MLFLOW_ALLOW_PICKLE_DESERIALIZATION``
  control that operators set to ``False`` to block unsafe pickle loading. The
  ``mlflow.statsmodels`` flavor **omits that guard**: its loader calls
  ``statsmodels.iolib.smpickle.load_pickle`` (a thin ``pickle.load`` wrapper)
  unconditionally. A crafted ``MLmodel`` with ``loader_module:
  mlflow.statsmodels`` plus a malicious pickle artifact therefore yields
  arbitrary code execution on ``load_model()`` *even when the control is set to
  False*. Fixed by adding the guard to the statsmodels flavor in 3.15.0.
* CVE-2024-37052 .. CVE-2024-37060 -- the broader MLflow model-loading
  deserialization family: loading an untrusted model (sklearn, pytorch,
  tensorflow, lightgbm, xgboost, pmdarima, and other pickle-backed flavors)
  deserializes attacker-controlled pickle/weight artifacts referenced by the
  ``MLmodel`` manifest.

What it flags
-------------
This tool reads the ``MLmodel`` YAML text only. It never imports, resolves or
executes anything it finds.

* ``MLF001`` (HIGH / CRITICAL) -- a ``loader_module`` that leaves the
  ``mlflow.`` first-party namespace. ``mlflow.pyfunc.load_model`` would import
  that arbitrary module and call its ``_load_pyfunc``. CRITICAL when the
  module's top-level name grants code execution / deserialization / import /
  reflection / process / network access; HIGH otherwise.
* ``MLF002`` (HIGH) -- ``loader_module: mlflow.statsmodels``, the flavor that
  bypasses ``MLFLOW_ALLOW_PICKLE_DESERIALIZATION`` (GHSA-gqvg-gmmx-x4hm). A
  crafted model using this flavor deserializes its pickle even when the operator
  disabled pickle loading.
* ``MLF003`` (MEDIUM) -- an ``MLmodel`` manifest that references a pickle
  artifact (a ``.pkl`` / ``.pickle`` / ``.cloudpickle`` path, a ``pickled_model``
  key, or ``serialization_format: pickle`` / ``cloudpickle``). Loading it
  deserializes that artifact (CVE-2024-37052 family). Review the model's source.
* ``MLF004`` (INFO) -- the ``python_function`` flavor is present; corroborates
  that this model is loaded through the ``loader_module`` dispatch path.

Honest limits
-------------
* This is a detector, not an exploit, and not a claim of a new CVE. It documents
  MLflow's documented loading behaviour so a reviewer can spot an unexpected
  loader target or an ungated pickle flavor in an untrusted model.
* The underlying code-execution primitive for the pickle flavors is pickle
  deserialization, which a dedicated pickle scanner catches when it reads the
  referenced ``.pkl``. The added value here is manifest-level: the ``MLmodel``
  file names the loader and the artifact before anything is unpickled.
* A first-party ``mlflow.`` loader_module is not proof of safety, and a clean
  scan guarantees nothing. The real protection is only loading MLflow models
  from a source you trust and upgrading mlflow to >= 3.15.0.
* This parses one manifest's YAML text with a minimal block-mapping reader (not
  a general YAML parser). It does not download the referenced artifact, unpickle
  anything, or confirm what any import does.

Usage
-----
    python mlflow_manifest_scan.py <file-or-directory> [--fail-on LEVEL] [--json]

Exit code is non-zero when a finding at or above ``--fail-on`` is present.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

__version__ = "0.1.0"

SEVERITY_ORDER = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

# MLflow always names its manifest exactly this (no extension).
MANIFEST_NAME = "MLmodel"

# The first-party flavor namespace. ``mlflow.pyfunc.load_model`` imports the
# ``loader_module`` string with importlib and no allowlist; anything outside this
# namespace is an unexpected import target a reviewer should see.
MLFLOW_PREFIX = "mlflow."

# The one first-party flavor that ignores MLFLOW_ALLOW_PICKLE_DESERIALIZATION
# (GHSA-gqvg-gmmx-x4hm). Kept as a set so a future ungated flavor can be added.
UNGATED_PICKLE_FLAVORS = frozenset({"mlflow.statsmodels"})

# Top-level modules whose import / use grants code execution, deserialization,
# import, reflection, filesystem, process or network access. Matched on the first
# dotted segment. Mirrors the diffusers / jsonargparse detectors' intent.
DANGEROUS_ROOTS = frozenset(
    {
        "os", "nt", "posix", "subprocess", "sys", "shutil", "pathlib",
        "pickle", "pickletools", "cpickle", "_pickle", "dill", "joblib",
        "marshal", "shelve",
        "importlib", "imp", "runpy", "builtins", "__builtin__",
        "code", "codeop", "compileall", "ast", "types", "inspect",
        "functools", "operator", "ctypes", "cffi",
        "socket", "socketserver", "http", "urllib", "ftplib", "smtplib",
        "telnetlib", "asyncio", "requests",
        "multiprocessing", "threading", "concurrent", "pty", "signal",
        "eval", "exec",
    }
)

# A pickle artifact reference anywhere in the manifest text.
_PICKLE_EXT_RE = re.compile(r"\.(?:pkl|pickle|pckl|cloudpickle)\b", re.IGNORECASE)
_PICKLED_KEY_RE = re.compile(r"(?mi)^\s*(?:-\s+)?pickled_model\s*:")
_SER_FORMAT_RE = re.compile(
    r"(?mi)^\s*serialization_format\s*:\s*['\"]?(?:cloud)?pickle\b")


@dataclass
class Finding:
    rule: str
    severity: str
    key: str
    value: str
    file: str
    location: str
    message: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "key": self.key,
            "value": self.value,
            "file": self.file,
            "location": self.location,
            "message": self.message,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _root(dotted: str) -> str:
    return dotted.strip().split(".", 1)[0]


def _clean_scalar(raw: str) -> str:
    """Strip a trailing comment and surrounding quotes from a YAML scalar."""
    value = raw.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()
    return value


def parse_yaml_mapping(text: str) -> dict:
    """Parse the YAML subset an ``MLmodel`` manifest uses into a nested dict.

    Handles nested block mappings with scalar ``key: value`` pairs and ``key:``
    headers that open a child mapping. It is deliberately minimal: list items and
    anything it does not recognise are ignored, and it imports no YAML library and
    executes nothing. Indentation must use spaces (MLflow writes spaces).
    """
    root: dict = {}
    # stack of (indent, container_dict); the container holds keys at that indent.
    stack: list[tuple[int, dict]] = [(-1, root)]
    for raw in text.splitlines():
        if not raw.strip():
            continue
        stripped = raw.strip()
        if stripped.startswith("#") or stripped in ("---", "..."):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        # A line indented with tabs (or otherwise unparseable) is skipped.
        if raw[:indent] != " " * indent:
            continue
        if stripped.startswith("- ") or stripped == "-" or ":" not in stripped:
            continue
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        key, _, val = stripped.partition(":")
        key = key.strip()
        if not key:
            continue
        val = _clean_scalar(val)
        if val == "":
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = val
    return root


def _walk(node: Any, path: str) -> Iterable[tuple]:
    """Yield (key, value, path) for every mapping key in a nested dict."""
    if isinstance(node, dict):
        for k, v in node.items():
            kp = f"{path}.{k}" if path else k
            yield (k, v, kp)
            yield from _walk(v, kp)


def _loader_finding(value: str, path: str, file: str) -> Optional[Finding]:
    """Classify a ``loader_module`` string value into MLF001 / MLF002, or None
    for an ordinary first-party ``mlflow.`` flavor."""
    dotted = value.strip()
    if dotted in UNGATED_PICKLE_FLAVORS:
        msg = (
            f"MLmodel loader_module '{dotted}' is the MLflow flavor that omits the "
            f"MLFLOW_ALLOW_PICKLE_DESERIALIZATION guard: mlflow.pyfunc.load_model "
            f"would unpickle the model artifact even when that control is set to "
            f"False (GHSA-gqvg-gmmx-x4hm, CWE-502, fixed in mlflow 3.15.0). Do not "
            f"load this model from an untrusted source; upgrade mlflow."
        )
        return Finding("MLF002", "HIGH", "loader_module", dotted, file,
                       f"/{path}", msg)
    # An ordinary first-party flavor (mlflow.sklearn, mlflow.onnx, ...) is the
    # expected import target; its pickle surface, if any, is covered by MLF003.
    if dotted.startswith(MLFLOW_PREFIX):
        return None
    # Outside the mlflow. first-party namespace -> arbitrary importlib dispatch.
    if _root(dotted) in DANGEROUS_ROOTS:
        severity = "CRITICAL"
        msg = (
            f"MLmodel loader_module '{dotted}' is outside the mlflow namespace and "
            f"its top-level module grants code execution / deserialization / "
            f"process / network access. mlflow.pyfunc.load_model imports it with "
            f"importlib.import_module and no allowlist and calls its _load_pyfunc, "
            f"so loading this model can run code. Do not load it from an untrusted "
            f"source."
        )
    else:
        severity = "HIGH"
        msg = (
            f"MLmodel loader_module '{dotted}' leaves the mlflow namespace. "
            f"mlflow.pyfunc.load_model resolves it with importlib.import_module and "
            f"no allowlist and calls its _load_pyfunc, so a crafted manifest can "
            f"import an unexpected module at load time. Review the model's source."
        )
    return Finding("MLF001", severity, "loader_module", dotted, file, f"/{path}", msg)


def scan_text(text: str, file: str = "<text>", *, require_marker: bool = True
              ) -> list[Finding]:
    """Scan one ``MLmodel`` manifest blob.

    ``require_marker`` (default True) returns [] unless the manifest looks like an
    MLflow ``MLmodel`` file (it has a ``flavors`` mapping). Set it False to force a
    scan of a file already known to be a manifest.
    """
    data = parse_yaml_mapping(text)
    if not isinstance(data, dict) or not data:
        return []

    flavors = data.get("flavors")
    has_flavors = isinstance(flavors, dict)
    if require_marker and not has_flavors:
        return []

    out: list[Finding] = []

    # MLF001 / MLF002: every loader_module value anywhere in the manifest.
    for key, value, path in _walk(data, ""):
        if key == "loader_module" and isinstance(value, str) and value.strip():
            lf = _loader_finding(value, path, file)
            if lf is not None:
                out.append(lf)

    # MLF003: a pickle artifact reference anywhere in the manifest text.
    pickle_ref = bool(
        _PICKLE_EXT_RE.search(text)
        or _PICKLED_KEY_RE.search(text)
        or _SER_FORMAT_RE.search(text)
    )
    if pickle_ref:
        out.append(Finding(
            "MLF003", "MEDIUM", "flavors", "", file, "/flavors",
            "MLmodel manifest references a pickle artifact (a .pkl/.pickle/"
            ".cloudpickle path, a pickled_model key, or serialization_format: "
            "pickle/cloudpickle); mlflow.pyfunc.load_model deserializes it, so "
            "loading this model from an untrusted source can run code "
            "(CVE-2024-37052 family, CWE-502). Review the model's source."))

    # MLF004: the python_function dispatch flavor is present (context).
    if has_flavors and isinstance(flavors.get("python_function"), dict):
        out.append(Finding(
            "MLF004", "INFO", "flavors.python_function", "", file,
            "/flavors/python_function",
            "MLmodel declares the python_function flavor; mlflow.pyfunc.load_model "
            "dispatches through its loader_module to load this model."))

    return out


def scan_file(path: str, result: ScanResult, *, require_marker: bool) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        result.errors.append(f"{path}: {exc}")
        return
    result.scanned_files.append(path)
    result.findings.extend(scan_text(text, path, require_marker=require_marker))


def _iter_targets(paths: Iterable[str]) -> Iterable[tuple]:
    """Yield (path, require_marker) pairs. Directory walks match only ``MLmodel``
    files (and require no marker since the name is authoritative); an explicit
    file is scanned whatever its name but must look like a manifest."""
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in sorted(files):
                    if name == MANIFEST_NAME:
                        yield (os.path.join(root, name), False)
        else:
            # An explicit file is scanned; require the flavors marker unless its
            # name is exactly MLmodel.
            yield (p, os.path.basename(p) != MANIFEST_NAME)


def scan_paths(paths: Iterable[str]) -> ScanResult:
    result = ScanResult()
    for target, require_marker in _iter_targets(paths):
        scan_file(target, result, require_marker=require_marker)
    return result


def _max_severity(findings: list[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mlflow_manifest_scan",
        description=(
            "Static detector for the MLflow MLmodel manifest loader-dispatch "
            "surface (loader_module import targets, the statsmodels pickle-guard "
            "bypass, and pickle artifact references). No execution, no network, "
            "stdlib only."
        ),
    )
    parser.add_argument(
        "paths", nargs="+",
        help="MLmodel files, or directories to walk for them")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"],
        default="NONE",
        help="exit non-zero if a finding at or above this severity is present")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    result = scan_paths(args.paths)

    if args.json:
        print(json.dumps(
            {
                "version": __version__,
                "scanned_files": result.scanned_files,
                "findings": [f.as_dict() for f in result.findings],
                "errors": result.errors,
            },
            indent=2,
        ))
    else:
        for f in result.findings:
            print(f"[{f.severity}] {f.rule} {f.file} ({f.location}): {f.message}")
        for e in result.errors:
            print(f"[ERROR] {e}", file=sys.stderr)
        print(
            f"\nScanned {len(result.scanned_files)} file(s); "
            f"{len(result.findings)} finding(s).")

    threshold = SEVERITY_ORDER[args.fail_on]
    if threshold > 0 and _max_severity(result.findings) >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
