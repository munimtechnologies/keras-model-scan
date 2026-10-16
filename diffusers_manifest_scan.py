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
"""Static, no-execution detector for the Diffusers ``model_index.json``
class-instantiation surface.

Background
----------
A Diffusers pipeline repository is described by a flat JSON manifest,
``model_index.json``. Besides the pipeline class (``_class_name``) and the
library version (``_diffusers_version``), every sub-model is recorded as a
two-element ``[library_name, class_name]`` list, e.g.::

    {
      "_class_name": "StableDiffusionPipeline",
      "_diffusers_version": "0.31.0",
      "text_encoder": ["transformers", "CLIPTextModel"],
      "unet": ["diffusers", "UNet2DConditionModel"]
    }

When ``DiffusionPipeline.from_pretrained`` loads such a repo, it resolves each
component's class with ``get_class_obj_and_candidates`` in
``diffusers/pipelines/pipeline_loading_utils.py``. In the fallback branch that
function calls ``importlib.import_module(library_name)`` on the first element of
the list **with no allowlist** - the ``LOADABLE_CLASSES`` /
``ALL_IMPORTABLE_CLASSES`` tables are used only to enumerate candidate parent
classes, not to gate which module is imported. Real manifests only ever name
the three libraries Diffusers knows how to load (``diffusers``,
``transformers``, ``onnxruntime.training``), so a component pointing anywhere
else is an unexpected import target a reader should see.

Separately, when ``_class_name`` is a two-element list rather than a plain
string, Diffusers treats element 0 as a local ``<file>.py`` and imports the
class named by element 1 from it - the custom-pipeline / remote-code path,
analogous to ``trust_remote_code``.

This tool reads the ``model_index.json`` text only. It never imports, resolves
or executes anything it finds. It flags:

* ``DMS001`` - a component ``[library, class]`` whose library is outside the
  known-safe set; CRITICAL when the library's top-level module grants code
  execution / deserialization / import / reflection / filesystem / process /
  network access, HIGH otherwise.
* ``DMS002`` - a list-form ``_class_name`` (custom pipeline loaded from a local
  ``.py``).

Honest limits
-------------
* This is a detector, not an exploit, and not a claim of a new CVE. It
  documents a Diffusers loading behaviour so a reviewer can spot an unexpected
  import target in an untrusted pipeline.
* Naming an unusual library is not proof of malice - a legitimate pipeline may
  occasionally reference an uncommon helper. A finding is a review signal.
* The real protection is only loading pipelines from a source you trust; a
  clean scan guarantees nothing.
* This parses one manifest's JSON text. It does not download the referenced
  weights, follow the custom-pipeline ``.py``, or confirm what any import does.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable

__version__ = "0.1.0"

# Libraries Diffusers knows how to load a component from (LOADABLE_CLASSES keys
# in pipeline_loading_utils.py). Matched on the first dotted segment, so
# "onnxruntime.training" is covered by "onnxruntime".
KNOWN_LIBRARIES = frozenset({"diffusers", "transformers", "onnxruntime"})

# Top-level modules whose import or use grants code execution / deserialization
# / import / reflection / filesystem / process / network access. Matched on the
# first dotted segment. Mirrors the jsonargparse detector's intent.
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

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

MANIFEST_NAME = "model_index.json"


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


def is_known_library(library: str) -> bool:
    """True if ``library`` is one Diffusers loads components from."""
    return isinstance(library, str) and _root(library) in KNOWN_LIBRARIES


def _component_finding(key: str, library: str, class_name: Any, file: str) -> Finding:
    value = f"[{library}, {class_name}]"
    if _root(library) in DANGEROUS_ROOTS:
        severity = "CRITICAL"
        msg = (
            f"model_index.json component '{key}' names library '{library}', "
            f"whose top-level module grants code execution / deserialization / "
            f"process / network access. DiffusionPipeline.from_pretrained "
            f"imports it with importlib.import_module and no allowlist, so "
            f"loading this pipeline can run code. Do not load it from an "
            f"untrusted source."
        )
    else:
        severity = "HIGH"
        msg = (
            f"model_index.json component '{key}' names library '{library}', "
            f"outside the known-safe set (diffusers, transformers, "
            f"onnxruntime). Diffusers resolves it with importlib.import_module "
            f"and no allowlist, so a crafted manifest can import an unexpected "
            f"module. Review the source of this pipeline."
        )
    return Finding("DMS001", severity, key, value, file, f"/{key}", msg)


def _class_name_finding(value: Any, file: str) -> Finding:
    rendered = json.dumps(value)
    msg = (
        f"model_index.json '_class_name' is a custom-pipeline reference "
        f"{rendered}: Diffusers imports the class from the local "
        f"'{value[0]}.py' module (the custom_pipeline / remote-code path). "
        f"Only load this pipeline from a source you trust."
    )
    return Finding("DMS002", "HIGH", "_class_name", rendered, file, "/_class_name", msg)


def scan_text(text: str, file: str = "<text>") -> list[Finding]:
    """Scan one ``model_index.json`` blob. Returns [] if it is not a JSON object."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[Finding] = []

    class_name = data.get("_class_name")
    if isinstance(class_name, list) and len(class_name) == 2 and isinstance(
        class_name[0], str
    ):
        out.append(_class_name_finding(class_name, file))

    for key, value in data.items():
        if key == "_class_name":
            continue
        if not isinstance(value, list) or len(value) != 2:
            continue
        library, cls = value[0], value[1]
        # A disabled component is recorded as [null, null]; skip those.
        if not isinstance(library, str) or not library:
            continue
        if is_known_library(library):
            continue
        out.append(_component_finding(key, library, cls, file))

    return out


def scan_file(path: str, result: ScanResult) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        result.errors.append(f"{path}: {exc}")
        return
    result.scanned_files.append(path)
    result.findings.extend(scan_text(text, path))


def _iter_targets(paths: Iterable[str]) -> Iterable[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in sorted(files):
                    if name == MANIFEST_NAME:
                        yield os.path.join(root, name)
        else:
            # An explicit file is scanned whatever its name.
            yield p


def scan_paths(paths: Iterable[str]) -> ScanResult:
    result = ScanResult()
    for target in _iter_targets(paths):
        scan_file(target, result)
    return result


def _max_severity(findings: list[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="diffusers_manifest_scan",
        description=(
            "Static detector for the Diffusers model_index.json "
            "class-instantiation surface (component [library, class] import "
            "targets and custom-pipeline _class_name). No execution, no "
            "network, stdlib only."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="model_index.json files, or directories to walk for them",
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
            print(f"[{f.severity}] {f.rule} {f.file} ({f.location}): {f.message}")
        for e in result.errors:
            print(f"[ERROR] {e}", file=sys.stderr)
        print(
            f"\nScanned {len(result.scanned_files)} file(s); "
            f"{len(result.findings)} finding(s)."
        )

    threshold = SEVERITY_ORDER[args.fail_on]
    if threshold > 0 and _max_severity(result.findings) >= threshold:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
