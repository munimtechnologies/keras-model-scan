"""Static, no-execution scanner for SSTI risk in model chat templates.

A Hugging Face / GGUF model can carry a Jinja2 *chat template*: the rule that
turns a list of chat messages into the single prompt string the model sees. It
rides along inside the model's files in three places:

  * the ``chat_template`` field of ``tokenizer_config.json`` (a string, or a
    list of ``{"name": ..., "template": ...}`` objects for named templates);
  * a ``chat_template.jinja`` / ``*.jinja`` / ``*.j2`` sidecar file; and
  * the ``tokenizer.chat_template`` metadata key inside a ``.gguf`` file.

Several loaders have rendered that template with an UNSANDBOXED Jinja
environment -- ``jinja2.Environment(...).from_string(chat_template)`` -- so a
template written by whoever published the model could reach Python internals
and run code the moment the model was loaded. Public cases:

  * CVE-2024-34359 / GHSA-56xg-wfcc-g829 -- abetlen/llama-cpp-python rendered a
    GGUF chat template with a sandbox-less environment (fixed by switching to
    ``jinja2.sandbox.ImmutableSandboxedEnvironment``).
  * berriai/litellm -- ``hf_chat_template`` passed a model's ``chat_template``
    straight to Jinja (huntr report; fixed with a sandboxed environment).
  * guidance-ai/guidance PR #1475 -- chat templates from model files were
    rendered with an unsandboxed ``jinja2.Environment``.

This module NEVER renders a template. It reads the template *string* and flags
the server-side-template-injection "gadget" tokens that an ordinary chat
template has no reason to contain: Python dunder attribute walks, the Jinja
builtin globals used to pivot into Python (``cycler``/``lipsum``/``joiner``),
``os``/``subprocess``/``eval``/``exec`` calls, the ``attr`` bypass filter, web
framework globals, and ``{% import %}``-style tags. It is a lint, not a
sandbox: a clean result does NOT prove a template is safe, and the real fix is
to render any untrusted template only inside an ``ImmutableSandboxedEnvironment``
(CWE-94 code injection, CWE-1336 template injection).

Prior art, named honestly: promptfoo's ModelAudit ships a Jinja2 template
scanner and r0b0tlab/model-audit inspects ``tokenizer.chat_template``; both pull
in their own dependencies. This detector is standard-library only, reads the
template statically (no Jinja, no model framework, no execution), handles the
three carriers above, and maps each finding class to the public advisory. It
is made with AI by MV2 of Munim, Inc. Licensed under Apache-2.0.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional

__version__ = "0.1.0"

_SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# A Python dunder attribute such as __class__, __globals__, __subclasses__,
# __mro__, __init__, __builtins__ or __import__ -- the backbone of almost every
# Jinja SSTI chain. Benign chat templates never reach into dunder attributes.
_DUNDER_RE = re.compile(r"__[A-Za-z][A-Za-z0-9_]*__")

# Jinja builtin globals that exist in every environment and are the classic
# pivots from template space into Python. ``namespace`` is deliberately NOT here:
# real chat templates legitimately use ``{% set ns = namespace(...) %}``.
_GADGET_GLOBAL_RE = re.compile(r"\b(?:cycler|lipsum|joiner)\b")

# OS / process / dynamic-import calls. Patterns require a call or attribute
# context so the bare words ``system`` (the system *role*) or ``eval`` inside
# ordinary prose are not flagged.
_CODE_EXEC_RES = [
    re.compile(r"(?:os\s*\.\s*|\.\s*)system\s*\("),
    re.compile(r"\bpopen\s*\("),
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\bimportlib\b"),
    re.compile(r"\bpty\s*\.\s*spawn\b"),
    re.compile(r"\b__import__\s*\("),
]

# The ``attr`` filter / ``getattr`` are the standard way to dereference a hidden
# attribute by name and slip past naive string filters.
_ATTR_BYPASS_RES = [
    re.compile(r"\|\s*attr\b"),
    re.compile(r"\bgetattr\s*\("),
]

# Web-framework SSTI globals that have no place in a model chat template.
_WEB_CTX_RES = [
    re.compile(r"\brequest\s*\."),
    re.compile(r"\burl_for\s*\("),
    re.compile(r"\bget_flashed_messages\b"),
    re.compile(r"\bself\s*\.\s*_"),
]

# ``{% import %}`` / ``{% from ... import %}`` / ``{% include %}`` / ``{% extends %}``
# let a template pull in other templates or Python-backed macros.
_IMPORT_TAG_RE = re.compile(r"\{%-?\s*(?:import|from|include|extends)\b")

_JINJA_SIDECAR_SUFFIXES = (".jinja", ".jinja2", ".j2")


class Finding:
    __slots__ = ("code", "severity", "title", "carrier", "source", "detail")

    def __init__(self, code: str, severity: str, title: str, carrier: str,
                 source: str, detail: str) -> None:
        self.code = code
        self.severity = severity
        self.title = title
        self.carrier = carrier
        self.source = source
        self.detail = detail

    def as_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "carrier": self.carrier,
            "source": self.source,
            "detail": self.detail,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Finding({self.code}, {self.severity}, {self.source})"


def _excerpt(text: str, match: re.Match, width: int = 40) -> str:
    start = max(0, match.start() - width)
    end = min(len(text), match.end() + width)
    snippet = text[start:end].replace("\n", " ")
    return snippet.strip()


def scan_template_string(template: str, carrier: str, source: str) -> List[Finding]:
    """Flag SSTI gadget tokens in a single chat-template string.

    ``carrier`` is how the template travelled (``tokenizer_config.json``,
    ``jinja-sidecar`` or ``gguf-metadata``); ``source`` is a human-readable
    locator shown in output. The template is never rendered.
    """
    findings: List[Finding] = []
    if not isinstance(template, str) or not template:
        return findings

    seen_dunders = set()
    for m in _DUNDER_RE.finditer(template):
        token = m.group(0)
        if token in seen_dunders:
            continue
        seen_dunders.add(token)
        findings.append(Finding(
            "CT001", "HIGH",
            "Python dunder attribute access in chat template",
            carrier, source,
            f"template references {token}: {_excerpt(template, m)!r}",
        ))

    m = _GADGET_GLOBAL_RE.search(template)
    if m:
        findings.append(Finding(
            "CT002", "HIGH",
            "Jinja SSTI builtin global in chat template",
            carrier, source,
            f"template uses builtin global {m.group(0)!r}: {_excerpt(template, m)!r}",
        ))

    for rx in _CODE_EXEC_RES:
        m = rx.search(template)
        if m:
            findings.append(Finding(
                "CT003", "HIGH",
                "OS / process / dynamic-import call in chat template",
                carrier, source,
                f"template contains {m.group(0)!r}: {_excerpt(template, m)!r}",
            ))

    for rx in _ATTR_BYPASS_RES:
        m = rx.search(template)
        if m:
            findings.append(Finding(
                "CT004", "MEDIUM",
                "Dynamic attribute-access bypass (attr/getattr) in chat template",
                carrier, source,
                f"template contains {m.group(0)!r}: {_excerpt(template, m)!r}",
            ))

    for rx in _WEB_CTX_RES:
        m = rx.search(template)
        if m:
            findings.append(Finding(
                "CT005", "MEDIUM",
                "Web-framework SSTI global in chat template",
                carrier, source,
                f"template references {m.group(0)!r}: {_excerpt(template, m)!r}",
            ))

    m = _IMPORT_TAG_RE.search(template)
    if m:
        findings.append(Finding(
            "CT006", "MEDIUM",
            "Template import/include tag in chat template",
            carrier, source,
            f"template uses {m.group(0)!r}: {_excerpt(template, m)!r}",
        ))

    return findings


def _iter_templates_from_tokenizer_config(obj: object) -> Iterable[str]:
    """Yield every chat-template string from a parsed tokenizer_config.json.

    ``chat_template`` is either a string or a list of objects each with a
    ``template`` key (Hugging Face's multiple-named-template format).
    """
    if not isinstance(obj, dict):
        return
    ct = obj.get("chat_template")
    if isinstance(ct, str):
        yield ct
    elif isinstance(ct, list):
        for item in ct:
            if isinstance(item, dict) and isinstance(item.get("template"), str):
                yield item["template"]


def scan_tokenizer_config(path: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
    except (OSError, ValueError) as exc:
        return [Finding("CT000", "LOW", "Unreadable tokenizer config",
                        "tokenizer_config.json", path, str(exc))]
    for template in _iter_templates_from_tokenizer_config(obj):
        findings.extend(scan_template_string(template, "tokenizer_config.json", path))
    return findings


def scan_jinja_sidecar(path: str) -> List[Finding]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [Finding("CT000", "LOW", "Unreadable template sidecar",
                        "jinja-sidecar", path, str(exc))]
    return scan_template_string(text, "jinja-sidecar", path)


def scan_path(path: str) -> List[Finding]:
    """Scan a single file or walk a directory of model files."""
    findings: List[Finding] = []
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for name in sorted(files):
                findings.extend(scan_path(os.path.join(root, name)))
        return findings

    base = os.path.basename(path).lower()
    if base == "tokenizer_config.json":
        findings.extend(scan_tokenizer_config(path))
    elif base.endswith(_JINJA_SIDECAR_SUFFIXES):
        findings.extend(scan_jinja_sidecar(path))
    return findings


def _max_severity(findings: List[Finding]) -> Optional[str]:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: _SEV_ORDER.get(s, 0))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Static, no-execution SSTI scanner for model chat templates "
                    "(tokenizer_config.json and .jinja/.j2 sidecars). Made with "
                    "AI by MV2 of Munim, Inc.")
    parser.add_argument("paths", nargs="+", help="model files or directories")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH"],
                        default="HIGH",
                        help="exit non-zero if any finding is at least this "
                             "severity (default: HIGH)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit findings as JSON")
    parser.add_argument("--version", action="version",
                        version=f"chat_template_scan {__version__}")
    args = parser.parse_args(argv)

    findings: List[Finding] = []
    for path in args.paths:
        findings.extend(scan_path(path))

    if args.as_json:
        json.dump([f.as_dict() for f in findings], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        if not findings:
            print("No chat-template SSTI indicators found. "
                  "A clean scan does not prove a template is safe.")
        for f in findings:
            print(f"[{f.severity}] {f.code} {f.title}")
            print(f"    source: {f.source}")
            print(f"    {f.detail}")

    worst = _max_severity([f for f in findings if f.code != "CT000"])
    if worst is not None and _SEV_ORDER[worst] >= _SEV_ORDER[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
