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
"""Static, no-execution detector for jsonargparse / LightningCLI config-driven
class instantiation (the CVE-2026-58659 class).

Background
----------
jsonargparse resolves a ``class_path`` by importing the named module and
instantiating the class with config-supplied ``init_args`` - so "a config
effectively decides what code runs" (mauvilsa/jsonargparse PR #959). When the
config comes from an untrusted source, a dotted import path can reach
module-level code that runs on import.

PyTorch Lightning's ``LightningModule.load_from_checkpoint`` stores two such
values inside a checkpoint's hyper-parameters and resolves them on load,
bypassing ``weights_only=True``:

* ``_instantiator`` - a dotted path Lightning imports and calls
  (CVE-2026-58659 / GHSA-qqmf-gpg7-g8gw / PYSEC-2026-3624, CVSS 8.4,
  affects pytorch-lightning <= 2.6.5, fixed 2.6.6).
* ``_class_path`` - passed to jsonargparse ``import_object``, which calls
  ``__import__`` on the named module *before* the subclass check (the second
  vector closed by Lightning PR #21914).

This tool reads YAML/JSON config text only. It never imports, evaluates or
executes anything it finds. It flags any ``class_path`` / ``_class_path`` /
``_instantiator`` key whose value is a dotted import path, and escalates to
CRITICAL when that path points into a module family that grants code
execution, deserialization, imports, reflection, filesystem, process or
network access (the same families jsonargparse's own denylist targets).

Honest limits
-------------
* Everything named here is already public and fixed upstream; this is a
  detector, not an exploit, and not a zero-day.
* The real fix is upgrading (pytorch-lightning >= 2.6.6, jsonargparse with the
  import-path denylist) and never loading configs/checkpoints from untrusted
  sources. A clean scan guarantees nothing.
* This parses config *text*. Checkpoint ``.ckpt`` files embed hparams inside a
  zip/pickle container; extract the hparams YAML/JSON first, then scan it.
* A dotted path in a config is not proof of a vulnerability - it is only
  dangerous if the consuming CLI/loader resolves it without an allowlist.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable

__version__ = "0.1.0"

# Keys whose value jsonargparse / LightningCLI will resolve as an import path.
CLASS_PATH_KEYS = ("class_path", "_class_path")
INSTANTIATOR_KEY = "_instantiator"

# A dotted import path: at least two dotted identifier segments (module.name).
_IMPORT_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")

# Line-based YAML match: `key: value` with optional quotes/inline comment.
_YAML_LINE_RE = re.compile(
    r"""^\s*['"]?(?P<key>_?class_path|_instantiator)['"]?\s*:\s*"""
    r"""['"]?(?P<val>[A-Za-z_][\w.]*)['"]?\s*(?:\#.*)?$"""
)

# Module families that grant code execution / deserialization / import /
# reflection / filesystem / process / network access. Matched on the first
# dotted segment (top-level module). Mirrors jsonargparse's denylist intent.
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


def is_import_path(value: Any) -> bool:
    """True if ``value`` is a string that looks like a dotted import path."""
    return isinstance(value, str) and bool(_IMPORT_PATH_RE.match(value.strip()))


def _rule_for_key(key: str) -> tuple[str, str]:
    """Return (rule_id, base_message_subject) for an instantiation key."""
    if key == "class_path":
        return "JAC001", "jsonargparse/LightningCLI config `class_path`"
    if key == "_class_path":
        return "JAC002", "checkpoint hparam `_class_path` (CVE-2026-58659)"
    if key == INSTANTIATOR_KEY:
        return "JAC003", "checkpoint hparam `_instantiator` (CVE-2026-58659)"
    return "JAC000", key


def _severity_for_value(value: str) -> str:
    root = value.strip().split(".", 1)[0]
    return "CRITICAL" if root in DANGEROUS_ROOTS else "HIGH"


def _make_finding(key: str, value: str, file: str, location: str) -> Finding:
    rule, subject = _rule_for_key(key)
    severity = _severity_for_value(value)
    if severity == "CRITICAL":
        msg = (
            f"{subject} resolves import path '{value}', whose top-level module "
            f"grants code execution / deserialization / process / network "
            f"access. A crafted config or checkpoint hparam can run this on load."
        )
    else:
        msg = (
            f"{subject} resolves import path '{value}'. Config decides what code "
            f"runs; unsafe if the loader resolves it without an allowlist."
        )
    return Finding(rule, severity, key, value, file, location, msg)


def _walk_json(node: Any, file: str, pointer: str, out: list[Finding]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            child = f"{pointer}/{k}"
            if k in CLASS_PATH_KEYS or k == INSTANTIATOR_KEY:
                if is_import_path(v):
                    out.append(_make_finding(k, v.strip(), file, child or "/"))
            _walk_json(v, file, child, out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk_json(v, file, f"{pointer}/{i}", out)


def _scan_yaml_text(text: str, file: str) -> list[Finding]:
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _YAML_LINE_RE.match(line)
        if not m:
            continue
        key, val = m.group("key"), m.group("val")
        if is_import_path(val):
            out.append(_make_finding(key, val.strip(), file, f"line {lineno}"))
    return out


def scan_text(text: str, file: str = "<text>") -> list[Finding]:
    """Scan one config blob. Try JSON first; fall back to a YAML line scan."""
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return _scan_yaml_text(text, file)
        out: list[Finding] = []
        _walk_json(data, file, "", out)
        return out
    # YAML (or JSON that failed to parse as an object/array) -> line scan.
    try:
        data = json.loads(text)
        out = []
        _walk_json(data, file, "", out)
        return out
    except (json.JSONDecodeError, ValueError):
        return _scan_yaml_text(text, file)


def scan_file(path: str, result: ScanResult) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        result.errors.append(f"{path}: {exc}")
        return
    result.scanned_files.append(path)
    result.findings.extend(scan_text(text, path))


_CONFIG_EXTS = (".json", ".yaml", ".yml")


def _iter_targets(paths: Iterable[str]) -> Iterable[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in sorted(files):
                    if name.lower().endswith(_CONFIG_EXTS):
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
        prog="jsonargparse_config_scan",
        description=(
            "Static detector for jsonargparse/LightningCLI config-driven class "
            "instantiation (class_path / _class_path / _instantiator; the "
            "CVE-2026-58659 class). No execution, no network, stdlib only."
        ),
    )
    parser.add_argument("paths", nargs="+", help="config files or directories")
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
