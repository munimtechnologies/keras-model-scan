# SPDX-License-Identifier: Apache-2.0
# Part of munimtechnologies/keras-model-scan by MV2, Munim, Inc.
# This file and the detector it implements were made with AI.
"""Static detector for config-driven class instantiation and expression evaluation
in model metadata and configuration files: Hydra / OmegaConf ``_target_`` keys,
pyannote-style ``pipeline: name:`` class references, sentence-transformers
``modules.json`` ``type`` class references, and MONAI bundle ``$`` Python-eval
expressions.

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
* pyannote-audio issues #2000 and #2019 (public, opened April and June 2026) --
  ``Pipeline.from_pretrained`` reads ``pipeline.name`` and each
  ``preprocessors.<key>.name`` from a hub repository's ``config.yaml``, resolves the
  dotted name with ``get_class_by_name()`` without an allowlist, and calls it with
  the config's ``params``. Same class, different key. At the time of writing the
  issues are open with no linked fix, so HYD004 flags any such reference that
  leaves the ``pyannote.`` namespace.
* CVE-2026-68770 / GHSA-jhr6-gm9c-rqjv / PYSEC-2026-4164 -- sentence-transformers.
  ``SentenceTransformer`` reads a model directory's ``modules.json``, a list of
  module entries each carrying a ``type`` (a dotted class path). The loader
  (``import_module_class``) treats a ``type`` that starts with
  ``sentence_transformers.`` as allowlisted and imports it directly; any other
  ``type`` is custom repository code that should require ``trust_remote_code=True``.
  Before the fix a local-path load could reach that custom code *even with*
  ``trust_remote_code=False`` because of an ``or os.path.exists(...)`` short-circuit,
  so a crafted ``modules.json`` on an attacker-influenced directory (a downloaded
  Hub snapshot, an unpacked archive, a mounted share) ran arbitrary Python at load
  time. Hardening landed in 6.0 (the short-circuit removed) and 6.1.0 (the resolved
  class is confirmed to be a sentence-transformers module class); 5.6.0 only warns.
  HYD005 flags any ``modules.json`` ``type`` that leaves the
  ``sentence_transformers.`` namespace, matching the loader's own trust boundary.
* CVE-2026-100840 / GHSA-873f-pvrv-4x83 / PYSEC-2026-4015 -- MONAI (<= 1.6.0). MONAI's
  bundle configuration engine resolves ``_target_`` values to arbitrary importable
  callables *without an allowlist* **and**, separately, evaluates any string that
  begins with ``$`` as a Python expression via ``eval()`` (its ``ConfigExpression``
  syntax: ``"$print(42)"``, ``"$from torchvision.models import resnet18"``). Loading an
  untrusted bundle with ``monai.bundle.load()`` / ``monai.bundle.run()`` therefore runs
  arbitrary code (CWE-95). The ``_target_`` sink is already covered by HYD001/HYD002;
  HYD006 adds the distinct ``$``-expression eval sink, which no existing model scanner
  documents a rule for. HYD006 flags a ``$``-leading string value anywhere in a bundle
  config (escalating to HIGH when the expression contains a code-execution token, and
  reporting MEDIUM for any other ``$`` expression in a file that shows MONAI bundle
  markers). It deliberately ignores OmegaConf ``${...}`` interpolation, which is a
  different mechanism.

Scope and honesty
-----------------
This is a static, no-execution analyzer: it parses JSON (and text-scans YAML) and
inspects key names and string values only. It never imports, resolves, calls or
evaluates a ``_target_``, class name or ``$`` expression. A clean scan does not prove a
file is safe, and the real fix is to not feed untrusted metadata to ``instantiate()`` /
``get_class_by_name()`` / ``import_module_class`` / ``monai.bundle.load`` (and to
upgrade affected libraries). Everything named above is already public.

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
from typing import Iterable, List, Optional

__version__ = "0.4.0"

# ---- severity ordering -----------------------------------------------------
_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "ERROR": 4}

# Config files that may carry model metadata handed to instantiate().
_JSON_NAMES = {"config.json", "generation_config.json", "model_config.json",
               "preprocessor_config.json", "hparams.json", "modules.json"}
_JSON_SUFFIXES = ("_config.json",)
_YAML_SUFFIXES = (".yaml", ".yml")

# Hydra/OmegaConf instantiation marker keys.
_TARGET_KEYS = {"_target_"}
_HELPER_KEYS = {"_args_", "_partial_", "_recursive_", "_convert_", "_target_wrapper_"}

# MONAI bundle marker keys. Their presence in a config means the file is parsed by
# MONAI's ConfigParser, which evaluates ``$`` expressions and instantiates ``_target_``.
_MONAI_KEYS = {"_requires_", "_disabled_", "_desc_", "_mode_"}

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

# Tokens that make a MONAI ``$`` expression an obvious code-execution payload. Matched
# as substrings against the text after the leading ``$`` (Python is case-sensitive).
_HYD006_DANGEROUS = (
    "__import__", "exec(", "eval(", "compile(",
    "os.system", "os.popen", "os.exec", "os.spawn", "os.remove", "os.rmdir",
    "subprocess", "popen", ".system(", "pty.spawn",
    "ctypes", "socket.", "getattr(", "setattr(", "globals(", "locals(",
    "breakpoint(", "marshal.", "pickle.", "base64", "shutil.",
    "__class__", "__subclasses__", "__globals__", "__builtins__", "__bases__",
    "__mro__", "__reduce__",
)

# A conservative allowlist of obviously-benign instantiation targets so that
# legitimate configs (e.g. torch optimizers/schedulers) do not produce noise.
_SAFE_TARGET_PREFIXES = (
    "torch.optim.", "torch.nn.", "torch.utils.data.",
    "torchvision.transforms.", "torchaudio.transforms.",
    "transformers.",
)

# pyannote resolves a bare (undotted) name inside its own default module, so only
# a dotted name outside this namespace can reach an arbitrary callable.
_PYANNOTE_PREFIX = "pyannote."

# sentence-transformers' loader allowlists a modules.json "type" iff it starts with
# this prefix; anything else is custom repository code (CVE-2026-68770 trust gate).
_ST_PREFIX = "sentence_transformers."

_YAML_TARGET_RE = re.compile(r"""^\s*_target_\s*:\s*['"]?([A-Za-z_][\w\.]*)['"]?""")
_YAML_KEY_RE = re.compile(r"""^(\s*)([A-Za-z_][\w\-]*)\s*:(?:\s+(.*))?$""")
# A line that declares a MONAI bundle marker key (optionally as a list item mapping).
_MONAI_YAML_RE = re.compile(
    r"(?m)^\s*(?:-\s+)?(?:_target_|_requires_|_disabled_|_desc_|_mode_)\s*:")


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


def _classify_class_ref(value: str) -> str:
    """Return the severity for a pyannote-style ``name:`` class reference."""
    dotted = value.strip()
    if _classify_target(dotted) == "HIGH":
        return "HIGH"
    if "." not in dotted or dotted.startswith(_PYANNOTE_PREFIX):
        return "LOW"
    return "MEDIUM"


def _classify_st_type(value: str) -> str:
    """Return the severity for a sentence-transformers ``modules.json`` type.

    Mirrors the loader's trust boundary: a ``type`` inside the
    ``sentence_transformers.`` namespace is allowlisted (LOW); anything else is
    custom repository code requiring ``trust_remote_code=True`` (MEDIUM), and a
    known code-execution callable is HIGH. A bare (undotted) name cannot be
    resolved by ``import_from_string`` (it needs a dot), so it is LOW.
    """
    dotted = value.strip()
    if _classify_target(dotted) == "HIGH":
        return "HIGH"
    if "." not in dotted or dotted.startswith(_ST_PREFIX):
        return "LOW"
    return "MEDIUM"


def _is_class_ref_path(keys: List[str]) -> bool:
    """True for ``pipeline.name`` and ``preprocessors.<key>.name``."""
    if keys == ["pipeline", "name"]:
        return True
    return len(keys) == 3 and keys[0] == "preprocessors" and keys[2] == "name"


def _class_ref_finding(value: str, file_label: str, path: str) -> Finding:
    sev = _classify_class_ref(value)
    if sev == "HIGH":
        msg = (f"class reference resolves to a code-execution callable '{value}'; "
               f"pyannote Pipeline.from_pretrained would call it with the config's "
               f"params (CWE-470/94).")
    elif sev == "MEDIUM":
        msg = (f"class reference '{value}' leaves the pyannote namespace; "
               f"get_class_by_name() resolves it without an allowlist and calls it "
               f"with the config's params (pyannote-audio issue #2000).")
    else:
        msg = (f"class reference '{value}' stays in the pyannote namespace; "
               f"corroborates config-driven instantiation of this file.")
    return Finding("HYD004", sev, file_label, path, msg)


def _st_type_finding(value: str, file_label: str, path: str) -> Finding:
    sev = _classify_st_type(value)
    if sev == "HIGH":
        msg = (f"modules.json 'type' resolves to a code-execution callable '{value}'; "
               f"SentenceTransformer load imports it via import_from_string (CWE-470/94).")
    elif sev == "MEDIUM":
        msg = (f"modules.json 'type' '{value}' leaves the sentence_transformers "
               f"namespace; loading it is custom repository code that should require "
               f"trust_remote_code=True, which CVE-2026-68770 could bypass on a local "
               f"path before the fix (GHSA-jhr6-gm9c-rqjv, fixed 6.0/6.1.0).")
    else:
        msg = (f"modules.json 'type' '{value}' stays in the sentence_transformers "
               f"namespace; corroborates config-driven module loading of this file.")
    return Finding("HYD005", sev, file_label, path, msg)


def _short(value: str, limit: int = 72) -> str:
    """Truncate a value for a finding message so output stays readable."""
    value = value.replace("\n", " ")
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _monai_expr_finding(value, has_monai: bool, file_label: str,
                        path: str) -> Optional[Finding]:
    """HYD006: a MONAI bundle ``$`` expression that MONAI evaluates with ``eval()``.

    A string value whose first character is ``$`` is a MONAI ``ConfigExpression`` and
    is passed to Python ``eval()`` (CVE-2026-100840). OmegaConf-style ``${...}``
    interpolation is a different mechanism and is ignored. A ``$`` expression that
    contains an obvious code-execution token is HIGH regardless of other markers; any
    other ``$`` expression is MEDIUM only when the file also shows MONAI bundle markers
    (a ``_target_`` or a MONAI underscore key), to avoid flagging stray ``$``-leading
    strings in unrelated configs (e.g. a ``"$5.00"`` price field).
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if len(v) < 2 or not v.startswith("$") or v.startswith("${"):
        return None
    expr = v[1:]
    if any(tok in expr for tok in _HYD006_DANGEROUS):
        return Finding(
            "HYD006", "HIGH", file_label, path,
            f"MONAI bundle '$' expression '{_short(v)}' is passed to eval() and "
            f"contains a code-execution token; monai.bundle.load/run would execute it "
            f"(CVE-2026-100840 / GHSA-873f-pvrv-4x83, CWE-95).")
    if has_monai:
        return Finding(
            "HYD006", "MEDIUM", file_label, path,
            f"MONAI bundle '$' expression '{_short(v)}' is evaluated as Python via "
            f"eval() by ConfigExpression; untrusted bundle config here is RCE-prone "
            f"(CVE-2026-100840 / GHSA-873f-pvrv-4x83).")
    return None


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


def _iter_str_scalars(node, path: str) -> Iterable[tuple]:
    """Yield (string, path) for every string value, incl. bare list elements.

    ``_walk`` only yields strings that are mapping values; a MONAI ``$`` expression can
    also be a bare list element (e.g. inside ``_requires_``), so this iterator yields
    those too.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            kp = f"{path}.{k}" if path else k
            if isinstance(v, str):
                yield (v, kp)
            else:
                yield from _iter_str_scalars(v, kp)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            kp = f"{path}[{i}]"
            if isinstance(v, str):
                yield (v, kp)
            else:
                yield from _iter_str_scalars(v, kp)


def scan_json_obj(obj, file_label: str) -> List[Finding]:
    findings: List[Finding] = []
    is_modules_json = os.path.basename(file_label).lower() == "modules.json"
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
        elif (key == "name" and isinstance(value, str) and value.strip()
              and _is_class_ref_path(path.split("."))):
            findings.append(_class_ref_finding(value.strip(), file_label, path))
        elif (is_modules_json and key == "type" and isinstance(value, str)
              and value.strip()):
            findings.append(_st_type_finding(value.strip(), file_label, path))

    # HYD006: MONAI bundle ``$`` Python-eval expressions (CVE-2026-100840).
    has_monai = any(k in _TARGET_KEYS or k in _MONAI_KEYS
                    for k, _v, _p in _walk(obj, ""))
    for sval, spath in _iter_str_scalars(obj, ""):
        f = _monai_expr_finding(sval, has_monai, file_label, spath)
        if f is not None:
            findings.append(f)
    return findings


def _clean_scalar(raw: str) -> str:
    """Strip a trailing comment and surrounding quotes from a YAML scalar."""
    value = raw.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()
    return value


def _yaml_line_value(line: str) -> Optional[str]:
    """Return the scalar value from a ``key: value`` or ``- value`` line, else None."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if s.startswith("- "):
        return _clean_scalar(s[2:])
    if s == "-":
        return None
    km = _YAML_KEY_RE.match(line)
    if km:
        return _clean_scalar(km.group(3) or "")
    return None


def scan_yaml_text(text: str, file_label: str) -> List[Finding]:
    """Dependency-free YAML text scan for _target_ lines, class references and MONAI
    ``$`` expressions."""
    findings: List[Finding] = []
    has_monai = bool(_MONAI_YAML_RE.search(text))
    stack: List[tuple] = []  # (indent, key) of the enclosing block mappings
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _YAML_TARGET_RE.match(line)
        if m:
            val = m.group(1)
            sev = _classify_target(val)
            if sev == "HIGH":
                findings.append(Finding(
                    "HYD001", "HIGH", file_label, f"line {lineno}",
                    f"_target_ resolves to a code-execution callable '{val}' (CWE-94/502)."))
            else:
                findings.append(Finding(
                    "HYD002", sev, file_label, f"line {lineno}",
                    f"_target_ '{val}' selects a callable for hydra instantiate(); "
                    f"untrusted config here is RCE-prone (GHSA-mwj6-rfh8-7qf4)."))

        # HYD006: a MONAI ``$`` expression as the value of this line.
        sval = _yaml_line_value(line)
        if sval is not None:
            f = _monai_expr_finding(sval, has_monai, file_label, f"line {lineno}")
            if f is not None:
                findings.append(f)

        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        km = _YAML_KEY_RE.match(line)
        if not km:
            continue
        indent = len(km.group(1).expandtabs())
        key = km.group(2)
        value = _clean_scalar(km.group(3) or "")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        keys = [k for _, k in stack] + [key]
        if value and _is_class_ref_path(keys):
            findings.append(_class_ref_finding(
                value, file_label, f"line {lineno} ({'.'.join(keys)})"))
        if not value:
            stack.append((indent, key))
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

    return scan_yaml_text(text, file_path)


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
    ap = argparse.ArgumentParser(
        description="Static config-driven class instantiation scanner: Hydra _target_, "
                    "pyannote class references, sentence-transformers modules.json type, "
                    "MONAI bundle $ expressions")
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
