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
"""Static, no-execution detector for Python object tags in YAML model metadata.

Background
----------
PyYAML's unsafe loaders build Python objects from tags such as
``!!python/object/apply:os.system``. HyperPyYAML, the format of SpeechBrain's
``hyperparams.yaml``, has shorthand tags (``!new:``, ``!apply:``, ``!name:``,
``!module:``) that construct or call any importable callable while the file
loads; its README and SpeechBrain's ``from_hparams`` docs say this is by design
and that only trusted files should be loaded.

* CVE-2026-10036 (SpeechBrain < 1.1.1, CVSS 8.8, CWE-502): ``CKPT.yaml``
  checkpoint metadata was parsed with PyYAML's unsafe loader during candidate
  enumeration in ``Checkpointer.recover_if_possible()``, so a
  ``!!python/object/apply`` tag in any ``CKPT.yaml`` under the checkpoint
  directory ran code even if that checkpoint was never selected. Fixed in 1.1.1.

This tool reads YAML text only. It never parses with a YAML library, imports,
resolves or calls anything it finds.

Honest limits
-------------
* Everything named here is already public; this is a detector, not an exploit.
* A clean scan guarantees nothing. The real fixes are upgrading SpeechBrain to
  1.1.1+, using ``yaml.safe_load`` for metadata, and loading hyperparams files
  only from trusted sources.
* Line-based: tags inside quoted scalars are ignored, block scalars are not
  modelled, and ``%TAG`` aliases are reported (YPT003) but not followed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable

__version__ = "0.1.0"

# PyYAML python tags that import, reference or call code. Primitive tags such as
# !!python/tuple, !!python/str or !!python/bytes build plain data and are ignored.
_PYYAML_TAG_RE = re.compile(
    r"(?<![^\s\[\{,:-])"
    r"(?:!!|!<tag:yaml\.org,2002:)"
    r"python/(?P<kind>object/apply|object/new|object|name|module)"
    r":(?P<target>[A-Za-z_][\w.]*)?"
)

# HyperPyYAML shorthand tags (SpeechBrain hyperparams.yaml).
_HYPER_TAG_RE = re.compile(
    r"(?<![^\s\[\{,:-])"
    r"!(?P<kind>apply|new|name|module):(?P<target>[A-Za-z_][\w.]*)"
)

# A %TAG directive that maps a handle onto the python tag namespace.
_TAG_DIRECTIVE_RE = re.compile(r"^%TAG\s+(?P<handle>!\S*!)\s+tag:yaml\.org,2002:python/")

_QUOTED_RE = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"")

# Tag kinds that call or construct something (as opposed to only referencing it).
CALLING_KINDS = frozenset({"object/apply", "object/new", "object", "apply", "new"})

# Top-level modules that grant code execution, deserialization, imports,
# reflection, filesystem, process or network access.
DANGEROUS_ROOTS = frozenset(
    {
        "os", "nt", "posix", "subprocess", "sys", "shutil", "pathlib",
        "pickle", "pickletools", "cpickle", "_pickle", "dill", "joblib",
        "marshal", "shelve",
        "importlib", "imp", "runpy", "builtins", "__builtin__",
        "code", "codeop", "compileall", "ast", "types", "inspect",
        "functools", "operator", "ctypes", "cffi", "pydoc",
        "socket", "socketserver", "http", "urllib", "ftplib", "smtplib",
        "telnetlib", "asyncio", "requests",
        "multiprocessing", "threading", "concurrent", "pty", "signal",
        "webbrowser",
    }
)

# Bare names resolve to builtins in both PyYAML and HyperPyYAML (pydoc.locate).
DANGEROUS_BARE = frozenset(
    {"eval", "exec", "compile", "__import__", "open", "getattr", "setattr",
     "delattr", "input", "breakpoint", "globals", "locals", "vars"}
)

# Namespaces ordinary SpeechBrain recipes construct from hyperparams.yaml.
BENIGN_PREFIXES = (
    "speechbrain.", "torch.", "torchaudio.", "transformers.", "sentencepiece.",
    "numpy.",
)

CKPT_NAME = "ckpt.yaml"

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    tag: str
    target: str
    file: str
    location: str
    message: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "tag": self.tag,
            "target": self.target,
            "file": self.file,
            "location": self.location,
            "message": self.message,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def is_dangerous(target: str) -> bool:
    """True if a dotted or bare name points into a code-execution family."""
    target = target.strip()
    if not target:
        return False
    if "." not in target:
        return target in DANGEROUS_BARE or target in DANGEROUS_ROOTS
    return target.split(".", 1)[0] in DANGEROUS_ROOTS


def _strip_line(line: str) -> str:
    """Drop quoted scalars and a trailing comment so tags in strings are ignored."""
    line = _QUOTED_RE.sub('""', line)
    if line.lstrip().startswith("#"):
        return ""
    cut = line.find(" #")
    return line if cut < 0 else line[:cut]


def _pyyaml_severity(kind: str, target: str) -> str:
    if kind in CALLING_KINDS and is_dangerous(target):
        return "CRITICAL"
    return "HIGH"


def _hyper_severity(kind: str, target: str) -> str:
    if is_dangerous(target):
        return "CRITICAL" if kind in CALLING_KINDS else "HIGH"
    if target.startswith(BENIGN_PREFIXES):
        return "LOW"
    return "MEDIUM"


def scan_text(text: str, file: str = "<text>") -> list[Finding]:
    """Scan one YAML blob for Python object tags."""
    in_ckpt = os.path.basename(file).lower() == CKPT_NAME
    out: list[Finding] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        where = f"line {lineno}"
        directive = _TAG_DIRECTIVE_RE.match(raw.strip())
        if directive:
            out.append(Finding(
                "YPT003", "HIGH", "%TAG " + directive.group("handle"), "", file, where,
                "%TAG directive aliases the python tag namespace; tags using this "
                "handle are not followed by this scanner. Review the file by hand."))
            continue
        line = _strip_line(raw)
        if not line:
            continue
        for m in _PYYAML_TAG_RE.finditer(line):
            kind, target = m.group("kind"), m.group("target") or ""
            tag = "!!python/" + kind
            if in_ckpt:
                out.append(Finding(
                    "YPT004", "CRITICAL", tag, target, file, where,
                    f"{tag} in checkpoint metadata CKPT.yaml. SpeechBrain < 1.1.1 "
                    f"parsed every CKPT.yaml with an unsafe loader during candidate "
                    f"enumeration (CVE-2026-10036), so this runs on recovery."))
                continue
            sev = _pyyaml_severity(kind, target)
            out.append(Finding(
                "YPT001", sev, tag, target, file, where,
                f"PyYAML python tag {tag}:{target} builds a Python object; it "
                f"runs code under yaml.unsafe_load / yaml.Loader."))
        for m in _HYPER_TAG_RE.finditer(line):
            kind, target = m.group("kind"), m.group("target")
            tag = "!" + kind
            if in_ckpt:
                out.append(Finding(
                    "YPT004", "CRITICAL", tag, target, file, where,
                    f"HyperPyYAML tag {tag}:{target} in checkpoint metadata "
                    f"CKPT.yaml, which should hold plain data only (CVE-2026-10036)."))
                continue
            sev = _hyper_severity(kind, target)
            out.append(Finding(
                "YPT002", sev, tag, target, file, where,
                f"HyperPyYAML tag {tag}:{target} is resolved and "
                f"{'called' if kind in CALLING_KINDS else 'imported'} when the "
                f"file loads (SpeechBrain from_hparams). Load only trusted files."))
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


_YAML_EXTS = (".yaml", ".yml")


def _iter_targets(paths: Iterable[str]) -> Iterable[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in sorted(files):
                    if name.lower().endswith(_YAML_EXTS):
                        yield os.path.join(root, name)
        else:
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
        prog="yaml_python_tag_scan",
        description=(
            "Static detector for Python object tags in YAML model metadata "
            "(PyYAML !!python/*, HyperPyYAML !new/!apply/!name/!module, "
            "SpeechBrain CKPT.yaml CVE-2026-10036). No execution, stdlib only."
        ),
    )
    parser.add_argument("paths", nargs="+", help="YAML files or directories")
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
