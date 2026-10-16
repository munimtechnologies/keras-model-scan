# SPDX-License-Identifier: Apache-2.0
# Part of munimtechnologies/keras-model-scan by MV2, Munim, Inc.
# This file and the detector it implements were made with AI.
"""Static detector for Hydra / OmegaConf ``_target_`` config-instantiation injection
in model metadata and configuration files.

Why this exists
---------------
Several 2026 RCEs do **not** need a pickle or a code-bearing weight file at all: the
*configuration* shipped alongside a model names the callable to run.
``hydra.utils.instantiate()`` reads a ``_target_`` string from a config object and
calls *any* dotted-path callable it names, passing attacker-controlled ``_args_`` /
keyword arguments. When that config is untrusted model metadata pulled from a model
hub, a crafted ``_target_`` (e.g. ``builtins.exec``) yields arbitrary code execution
*even when the weights are stored in a "safe" format such as safetensors*.

Public precedent (all already disclosed; this detector documents the class, it does
not introduce a new exploit):

* CVE-2026-22584  -- Salesforce Uni2TS, Hydra ``instantiate()`` on model metadata (HIGH).
* CVE-2025-23304  -- NVIDIA NeMo, same class, fixed in NeMo 2.3.2.
* FlexTok (VILAB/EPFL/Apple) -- same class (Unit 42, 2026).
* GHSA-mwj6-rfh8-7qf4 -- Hydra 1.3.4 added a ``_target_`` blocklist, but it is
  bypassable: ``_locate()`` can resolve a mutation method (e.g. ``set.discard``) on an
  imported object, so a config with sibling ``_target_`` nodes can first remove an
  entry from the blocklist and then instantiate the now-unblocked target. Because the
  blocklist is not a security boundary, this detector treats the *presence* of any
  ``_target_`` in untrusted metadata as the risk signal (MEDIUM) and escalates a
  known-dangerous target to HIGH.

Scope and honesty
-----------------
This is a static, no-execution analyzer: it parses JSON (and text-scans YAML) and
inspects key names and string values only. It never imports, resolves or calls a
``_target_``. A clean scan does not prove a file is safe, and the real fix is to not
feed untrusted metadata to ``instantiate()`` (and to upgrade affected libraries).
Everything named above is already public.

Usage
-----
    python hydra_target_scan.py <file-or-directory> [--fail-on LEVEL] [--json]

Exit code is non-zero when a finding at or above ``--fail-on`` (default HIGH) is present.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Iterable, List

__version__ = "0.1.0"

# ---- severity ordering -----------------------------------------------------
_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "ERROR": 4}

# Config files that may carry model metadata handed to instantiate().
_JSON_NAMES = {"config.json", "generation_config.json", "model_config.json",
               "preprocessor_config.json", "hparams.json"}
_JSON_SUFFIXES = ("_config.json",)
_YAML_SUFFIXES = (".yaml", ".yml")

# Hydra/OmegaConf instantiation marker keys.
_TARGET_KEYS = {"_target_"}
_HELPER_KEYS = {"_args_", "_partial_", "_recursive_", "_convert_", "_target_wrapper_"}

# Dotted paths that mean "arbitrary code" if instantiated. Matched on the dotted
# prefix (module.callable) so e.g. "subprocess.Popen" and "subprocess.run" both hit.
_DANGEROUS_TARGETS = {
    "builtins.exec", "builtins.eval", "builtins.__import__", "builtins.compile",
    "builtins.getattr", "builtins.setattr",
    "os.system", "os.popen", "os.exec", "os.execv", "os.execve", "os.execvp",
    "os.spawnl", "os.spawnv", "os.posix_spawn",
    "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.getoutput",
    "pty.spawn", "platform.popen",
    "importlib.import_module", "pkgutil.resolve_name",
    "ctypes.CDLL", "ctypes.cdll", "ctypes.WinDLL", "ctypes.windll",
    "runpy.run_path", "runpy.run_module", "code.interact", "pdb.run",
    "functools.partial",  # commonly used to pre-bind a dangerous callable
}

# A conservative allowlist of obviously-benign instantiation targets so that
# legitimate configs (e.g. torch optimizers/schedulers) do not produce noise.
_SAFE_TARGET_PREFIXES = (
    "torch.optim.", "torch.nn.", "torch.utils.data.",
    "torchvision.transforms.", "torchaudio.transforms.",
    "transformers.",
)

_YAML_TARGET_RE = re.compile(r"""^\s*_target_\s*:\s*['"]?([A-Za-z_][\w\.]*)['"]?""")


@dataclass
class Finding:
    id: str
    severity: str
    file: str
    path: str
    message: str

    def as_line(self) -> str:
        return f"[{self.severity:6}] {self.id} {self.file}:{self.path}  {self.message}"


def _classify_target(value: str) -> str:
    """Return the severity for a given _target_ string value."""
    if not isinstance(value, str) or not value:
        return "MEDIUM"
    dotted = value.strip()
    # exact or prefix match against the dangerous set
    for bad in _DANGEROUS_TARGETS:
        if dotted == bad or dotted.startswith(bad + "."):
            return "HIGH"
    # module prefix of a dangerous module (e.g. "subprocess.<anything>")
    head = dotted.split(".", 1)[0]
    if head in {"subprocess", "ctypes", "pty"}:
        return "HIGH"
    if any(dotted.startswith(p) for p in _SAFE_TARGET_PREFIXES):
        return "LOW"
    return "MEDIUM"


def _walk(node, path: str) -> Iterable[tuple]:
    """Yield (key, value, path) for every mapping key in a nested JSON structure."""
    if isinstance(node, dict):
        for k, v in node.items():
            kp = f"{path}.{k}" if path else k
            yield (k, v, kp)
            yield from _walk(v, kp)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            kp = f"{path}[{i}]"
            yield from _walk(v, kp)


def scan_json_obj(obj, file_label: str) -> List[Finding]:
    findings: List[Finding] = []
    for key, value, path in _walk(obj, ""):
        if key in _TARGET_KEYS:
            sev = _classify_target(value if isinstance(value, str) else "")
            val = value if isinstance(value, str) else repr(value)
            if sev == "HIGH":
                msg = (f"_target_ resolves to a code-execution callable "
                       f"'{val}'; instantiate() would run it (CWE-94/502).")
                findings.append(Finding("HYD001", "HIGH", file_label, path, msg))
            else:
                msg = (f"_target_ '{val}' selects a callable for hydra instantiate(); "
                       f"untrusted metadata here is RCE-prone (blocklists are bypassable, "
                       f"GHSA-mwj6-rfh8-7qf4).")
                findings.append(Finding("HYD002", sev, file_label, path, msg))
        elif key in _HELPER_KEYS:
            findings.append(Finding(
                "HYD003", "INFO", file_label, path,
                f"Hydra instantiation helper key '{key}' present; corroborates "
                f"instantiate() usage on this config."))
    return findings


def scan_file(file_path: str) -> List[Finding]:
    name = os.path.basename(file_path)
    low = name.lower()
    is_json = low in _JSON_NAMES or low.endswith(_JSON_SUFFIXES) or low == "config.json"
    is_yaml = low.endswith(_YAML_SUFFIXES)
    if not (is_json or is_yaml):
        return []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return [Finding("HYD000", "ERROR", file_path, "", f"could not read file: {e}")]

    if is_json:
        try:
            obj = json.loads(text)
        except (ValueError, json.JSONDecodeError) as e:
            return [Finding("HYD000", "ERROR", file_path, "", f"could not parse JSON: {e}")]
        return scan_json_obj(obj, file_path)

    # YAML: dependency-free text scan for _target_ lines.
    findings: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _YAML_TARGET_RE.match(line)
        if m:
            val = m.group(1)
            sev = _classify_target(val)
            if sev == "HIGH":
                findings.append(Finding(
                    "HYD001", "HIGH", file_path, f"line {lineno}",
                    f"_target_ resolves to a code-execution callable '{val}' (CWE-94/502)."))
            else:
                findings.append(Finding(
                    "HYD002", sev, file_path, f"line {lineno}",
                    f"_target_ '{val}' selects a callable for hydra instantiate(); "
                    f"untrusted config here is RCE-prone (GHSA-mwj6-rfh8-7qf4)."))
    return findings


def scan_path(target: str) -> List[Finding]:
    findings: List[Finding] = []
    if os.path.isdir(target):
        for root, _dirs, files in os.walk(target):
            for fn in files:
                findings.extend(scan_file(os.path.join(root, fn)))
    else:
        findings.extend(scan_file(target))
    return findings


def _max_severity(findings: List[Finding]) -> str:
    worst = "INFO"
    for f in findings:
        if _SEVERITY_ORDER.get(f.severity, 0) > _SEVERITY_ORDER.get(worst, 0):
            worst = f.severity
    return worst


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Static Hydra _target_ config-injection scanner")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=list(_SEVERITY_ORDER.keys()),
                    help="minimum severity that makes the exit code non-zero (default HIGH)")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="emit findings as JSON")
    args = ap.parse_args(argv)

    findings = scan_path(args.path)

    if args.as_json:
        print(json.dumps([asdict(f) for f in findings], indent=1))
    else:
        if not findings:
            print(f"hydra_target_scan {__version__}: no findings in {args.path}")
        for f in findings:
            print(f.as_line())

    threshold = _SEVERITY_ORDER[args.fail_on]
    hit = any(_SEVERITY_ORDER.get(f.severity, 0) >= threshold
              and f.severity != "ERROR" for f in findings)
    err = any(f.severity == "ERROR" for f in findings)
    return 1 if (hit or err) else 0


if __name__ == "__main__":
    sys.exit(main())
