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
"""Static, no-execution detector for auto-executing Python in a Diffusers
pipeline repository (the "FaceHugger" remote-code surface).

Background
----------
A Hugging Face Diffusers pipeline repository is normally just weights plus
JSON/text configuration. But ``DiffusionPipeline.from_pretrained`` can import
and run a **Python module that lives inside the repository**, and two 2026
advisories (collectively "FaceHugger", both fixed in diffusers ``0.38.0``)
show this happens even when the caller passes ``trust_remote_code=False``:

* ``CVE-2026-44827`` - when ``from_pretrained`` is called with **no**
  ``custom_pipeline`` argument, diffusers builds the literal module filename
  ``None.py`` (because the unset argument stringifies to ``"None"``) and an
  existence check loads it from the target repo without treating it as
  untrusted custom code. A repository that merely *contains a file named
  ``None.py``* therefore runs its code on a plain, default ``from_pretrained``
  call. ``None.py`` is an exact exploit fingerprint: no legitimate repository
  ships a module by that name.

* ``CVE-2026-44513`` - the ``custom_pipeline`` / local-custom-components path
  imports a local ``<name>.py`` from the repo directory; before 0.38.0 the
  trust gate ran at the download call site, not at the module-load site, so
  local Python executed without validation.

This tool walks a directory (or inspects one file) and reads **file names
only**. It never imports, parses, resolves, downloads or executes anything it
finds. It flags:

* ``DRC001`` - a file named exactly ``None.py`` (the ``CVE-2026-44827``
  fingerprint). CRITICAL. Reported wherever it is found, because the name is
  effectively never legitimate.
* ``DRC002`` - any other ``*.py`` module sitting in a Diffusers pipeline
  repository (the same directory as a ``model_index.json``). HIGH. A model
  repo normally has no Python at all; a loose module here is the
  ``custom_pipeline`` / local-custom-components remote-code surface
  (``CVE-2026-44513``) and should be reviewed before the pipeline is loaded.

Honest limits
-------------
* This is a detector, not an exploit, and makes no claim of a new CVE. It
  documents a documented Diffusers loading behaviour so a reviewer can spot an
  unexpected, auto-loadable Python module in an untrusted pipeline.
* A ``*.py`` next to ``model_index.json`` is not proof of malice: some
  legitimate community pipelines genuinely ship a ``pipeline.py``. DRC002 is a
  review signal, not a verdict.
* The real fix is upgrading to diffusers ``>= 0.38.0`` and only loading
  pipelines from a source you trust. A clean scan guarantees nothing.
* It reads file names, not file contents: it does not confirm what any module
  does. DRC002 flags ``*.py`` modules in the repository root (the directory
  holding ``model_index.json``); Python nested in unrelated sub-directories is
  not flagged, while a ``None.py`` is flagged wherever it appears.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Iterable

__version__ = "0.1.0"

# A Diffusers pipeline repository is identified by this manifest at its root.
PIPELINE_MARKER = "model_index.json"

# The literal filename diffusers builds when no custom_pipeline is supplied.
NONE_MODULE = "None.py"

# Fixed-in version for both FaceHugger code-injection CVEs.
FIXED_VERSION = "0.38.0"

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    repo: str
    message: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "file": self.file,
            "repo": self.repo,
            "message": self.message,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def is_pipeline_dir(dirpath: str) -> bool:
    """True if ``dirpath`` holds a Diffusers ``model_index.json`` manifest."""
    return os.path.isfile(os.path.join(dirpath, PIPELINE_MARKER))


def _none_py_finding(path: str, repo: str) -> Finding:
    msg = (
        "A file named 'None.py' is present. When "
        "DiffusionPipeline.from_pretrained is called with no custom_pipeline "
        "argument, diffusers builds the literal module filename 'None.py' and "
        "loads it from the repository, running its code even when "
        "trust_remote_code=False (CVE-2026-44827, fixed in diffusers "
        f"{FIXED_VERSION}). No legitimate repository ships a 'None.py'. Treat "
        "this repository as untrusted and do not load it with diffusers < "
        f"{FIXED_VERSION}."
    )
    return Finding("DRC001", "CRITICAL", path, repo, msg)


def _custom_module_finding(path: str, repo: str) -> Finding:
    name = os.path.basename(path)
    msg = (
        f"Python module '{name}' sits in a Diffusers pipeline repository (the "
        "directory holding model_index.json). diffusers can import such a "
        "local module through the custom_pipeline / local-custom-components "
        "path, which executed code without validation before diffusers "
        f"{FIXED_VERSION} (CVE-2026-44513). Model repositories normally "
        "contain only weights and JSON/text config; review why this .py is "
        "here before loading the pipeline."
    )
    return Finding("DRC002", "HIGH", path, repo, msg)


def scan_dir(dirpath: str, result: ScanResult) -> None:
    """Walk ``dirpath``; flag None.py anywhere and other .py in pipeline dirs."""
    for root, dirs, files in os.walk(dirpath):
        dirs.sort()
        pipeline = PIPELINE_MARKER in files
        repo = root if pipeline else ""
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            full = os.path.join(root, name)
            if name == NONE_MODULE:
                result.scanned_files.append(full)
                result.findings.append(_none_py_finding(full, repo or root))
            elif pipeline:
                result.scanned_files.append(full)
                result.findings.append(_custom_module_finding(full, root))


def scan_file(path: str, result: ScanResult) -> None:
    """Inspect a single explicit path. None.py -> DRC001; other .py -> DRC002."""
    name = os.path.basename(path)
    repo = os.path.dirname(path)
    if name == NONE_MODULE:
        result.scanned_files.append(path)
        result.findings.append(_none_py_finding(path, repo))
    elif name.endswith(".py"):
        result.scanned_files.append(path)
        result.findings.append(_custom_module_finding(path, repo))


def scan_paths(paths: Iterable[str]) -> ScanResult:
    result = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            scan_dir(p, result)
        elif os.path.isfile(p):
            scan_file(p, result)
        else:
            result.errors.append(f"{p}: not a file or directory")
    return result


def _max_severity(findings: list[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="diffusers_remote_code_scan",
        description=(
            "Static detector for auto-executing Python in a Diffusers pipeline "
            "repository (the FaceHugger surface: None.py / local custom "
            "pipeline modules). Reads file names only - no execution, no "
            "network, stdlib only."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="pipeline directories to walk, or individual files to inspect",
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
            print(f"[{f.severity}] {f.rule} {f.file}: {f.message}")
        for e in result.errors:
            print(f"[ERROR] {e}", file=sys.stderr)
        print(
            f"\nScanned {len(result.scanned_files)} Python file(s); "
            f"{len(result.findings)} finding(s)."
        )

    threshold = SEVERITY_ORDER[args.fail_on]
    if threshold > 0 and _max_severity(result.findings) >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
