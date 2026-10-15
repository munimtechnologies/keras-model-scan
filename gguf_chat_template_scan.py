"""Static, no-execution scanner for SSTI payloads in a GGUF model's embedded
chat template (``tokenizer.chat_template`` metadata).

Made with AI by MV2 of Munim, Inc. SPDX-License-Identifier: Apache-2.0

Why this exists
---------------
A ``.gguf`` file is a binary container with no code of its own, but llama.cpp
and its converters store the model's Jinja2 chat template as a *string* in the
GGUF metadata key ``tokenizer.chat_template`` (and, for multi-template models,
``tokenizer.chat_template.<name>`` keys). Several inference servers render that
template with an UNSANDBOXED ``jinja2.Environment``, so a crafted template is
server-side template injection (SSTI) and, in the worst case, remote code
execution at inference time. Public, fixed advisories for exactly this vector:

  * CVE-2024-34359 / GHSA-56xg-wfcc-g829 - llama-cpp-python, SSTI in model
    metadata chat template, CWE-76/CWE-1336, fixed by sandboxing the Jinja env.
  * CVE-2026-5760 - SGLang < 0.5.11 ``/v1/rerank`` RCE, CWE-94, CVSS 9.8, root
    cause an unsandboxed ``jinja2.Environment()`` rendering a GGUF chat template.

The companion ``chat_template_scan.py`` (v0.18.0) applies the SSTI heuristic to
``tokenizer_config.json`` strings and ``.jinja`` sidecars, but it never reads
the GGUF binary, so a template carried *inside* a single ``.gguf`` file is
missed. This module closes that carrier gap. The detection method itself is the
one publicly described by JFrog Security Research (parse the GGUF metadata,
extract the chat template, inspect for ``__class__`` / ``os`` / ``subprocess`` /
``eval`` / ``exec`` and friends): nothing here is a new vulnerability class or a
zero-day. The contribution is a free, dependency-free, standard-library,
no-execution implementation that plugs into an existing scanner suite and CI.

Safety and honesty
-------------------
  * No model framework is imported. ``jinja2`` is never imported and the
    extracted template is NEVER rendered - it is only pattern-matched as text.
  * Only the GGUF header and metadata key/value table are read; tensor data is
    never touched. Every declared length is bounded by the remaining buffer, so
    a hostile file cannot make the scanner over-allocate or loop unboundedly.
  * A clean scan guarantees nothing: this flags known-suspicious tokens, not all
    possible payloads. The real fix is to render chat templates only in an
    ``ImmutableSandboxedEnvironment`` (or to pin a known-good template).

CLI::

    python gguf_chat_template_scan.py ./model-dir --fail-on HIGH
    python gguf_chat_template_scan.py model.gguf --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from typing import List, Optional, Tuple

__version__ = "0.20.0"

# Severity ordering shared with the chat-template family.
_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# The vector-class references attached to code-execution-capable findings.
_SSTI_CVE = "CVE-2024-34359;CVE-2026-5760"


class Finding:
    """A single static detection. The template is never rendered."""

    __slots__ = ("code", "severity", "title", "carrier", "source", "detail", "cve")

    def __init__(self, code, severity, title, carrier, source, detail, cve=""):
        self.code = code
        self.severity = severity
        self.title = title
        self.carrier = carrier
        self.source = source
        self.detail = detail
        self.cve = cve

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "carrier": self.carrier,
            "source": self.source,
            "detail": self.detail,
            "cve": self.cve,
        }

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "Finding(%s, %s, %r)" % (self.code, self.severity, self.source)


# ---------------------------------------------------------------------------
# SSTI heuristic (text only; consistent with chat_template_scan's CT0xx codes).
# Each entry: code, severity, human title, list of compiled patterns.
# ---------------------------------------------------------------------------
_CHECKS: List[Tuple[str, str, str, List["re.Pattern"]]] = [
    (
        "CT001",
        "HIGH",
        "Python dunder attribute access",
        [re.compile(p) for p in (
            r"__class__", r"__mro__", r"__bases__", r"__base__",
            r"__subclasses__", r"__globals__", r"__builtins__",
            r"__import__", r"__init__", r"__dict__", r"__getattribute__",
            r"__reduce__",
        )],
    ),
    (
        "CT002",
        "HIGH",
        "Jinja SSTI builtin global",
        [re.compile(p) for p in (r"\blipsum\b", r"\bcycler\b", r"\bjoiner\b")],
    ),
    (
        "CT003",
        "HIGH",
        "OS / process / dynamic-import call",
        [re.compile(p) for p in (
            r"\bos\.", r"\bsubprocess\b", r"\bpopen\b", r"\bsystem\s*\(",
            r"\beval\s*\(", r"\bexec\s*\(", r"\b__import__\s*\(",
            r"\bimportlib\b", r"\bpty\b", r"\bcommands\b",
        )],
    ),
    (
        "CT004",
        "MEDIUM",
        "Dynamic attribute-access bypass",
        [re.compile(p) for p in (
            r"\|\s*attr\s*\(", r"\battr\s*\(", r"\bgetattr\s*\(",
            r"\bsetattr\s*\(", r"\bgetattribute\b",
        )],
    ),
    (
        "CT005",
        "MEDIUM",
        "Web-framework SSTI global",
        [re.compile(p) for p in (
            r"\brequest\b", r"\bconfig\b", r"\bsession\b", r"\burl_for\b",
            r"\bget_flashed_messages\b", r"\bself\b",
        )],
    ),
    (
        "CT006",
        "MEDIUM",
        "Template import/include tag",
        [re.compile(p) for p in (
            r"\{%\-?\s*include\b", r"\{%\-?\s*import\b",
            r"\{%\-?\s*from\b", r"\{%\-?\s*extends\b",
        )],
    ),
]

_HIGH_CODES = {"CT001", "CT002", "CT003"}


def scan_template_string(template: str, carrier: str, source: str) -> List[Finding]:
    """Apply the SSTI heuristic to one chat-template STRING. Never renders it."""
    findings: List[Finding] = []
    for code, severity, title, patterns in _CHECKS:
        hits = []
        for pat in patterns:
            m = pat.search(template)
            if m:
                hits.append(m.group(0))
        if hits:
            uniq = sorted(set(hits))
            detail = "matched %s" % ", ".join(repr(h) for h in uniq[:6])
            cve = _SSTI_CVE if code in _HIGH_CODES else ""
            findings.append(Finding(code, severity, title, carrier, source, detail, cve))
    return findings


# ---------------------------------------------------------------------------
# Minimal, bounded GGUF metadata reader (little- and big-endian, v1/v2/v3).
# Reads ONLY the header and metadata key/value table; extracts string values
# for keys under tokenizer.chat_template and skips everything else.
# ---------------------------------------------------------------------------
_MAGIC = b"GGUF"

# Scalar metadata value types -> byte width. STRING=8 and ARRAY=9 are special.
_SCALAR_WIDTH = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_TYPE_STRING = 8
_TYPE_ARRAY = 9


class _Truncated(Exception):
    pass


class _Reader:
    def __init__(self, raw: bytes, endian: str):
        self.raw = raw
        self.i = 0
        self.n = len(raw)
        self.e = endian  # "<" or ">"

    def _take(self, k: int) -> bytes:
        if k < 0 or self.i + k > self.n:
            raise _Truncated()
        b = self.raw[self.i:self.i + k]
        self.i += k
        return b

    def u32(self) -> int:
        return struct.unpack(self.e + "I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack(self.e + "Q", self._take(8))[0]

    def count(self, v1: bool) -> int:
        return self.u32() if v1 else self.u64()

    def string(self, v1: bool) -> str:
        ln = self.count(v1)
        if ln > self.n - self.i:
            raise _Truncated()
        return self._take(ln).decode("utf-8", "replace")

    def value(self, vtype: int, v1: bool):
        """Read one metadata value, advancing the cursor. Returns the string for
        STRING, a list of strings for ARRAY, and None for scalars."""
        if vtype in _SCALAR_WIDTH:
            self._take(_SCALAR_WIDTH[vtype])
            return None
        if vtype == _TYPE_STRING:
            return self.string(v1)
        if vtype == _TYPE_ARRAY:
            elem = self.u32()
            ln = self.count(v1)
            if ln > self.n:  # each element is >= 1 byte, so this cannot be valid
                raise _Truncated()
            out = []
            for _ in range(ln):
                v = self.value(elem, v1)
                if isinstance(v, str):
                    out.append(v)
            return out
        # Unknown type: we can no longer compute the stride, so stop safely.
        raise _Truncated()


def _pick_endian(raw: bytes) -> Optional[str]:
    """GGUF magic is byte-identical for both endiannesses; the version field
    disambiguates. Returns '<', '>' or None if neither yields a sane version."""
    if len(raw) < 8 or raw[0:4] != _MAGIC:
        return None
    for e in ("<", ">"):
        ver = struct.unpack(e + "I", raw[4:8])[0]
        if ver in (1, 2, 3):
            return e
    return None


def extract_chat_templates(raw: bytes) -> List[Tuple[str, str]]:
    """Return (key, template_string) for every metadata key whose name starts
    with 'tokenizer.chat_template'. Raises _Truncated on a malformed file."""
    endian = _pick_endian(raw)
    if endian is None:
        raise _Truncated()
    r = _Reader(raw, endian)
    r._take(4)  # magic
    version = r.u32()
    v1 = version == 1
    r.count(v1)  # tensor_count (unused)
    kv_count = r.count(v1)
    if kv_count > r.n:  # each KV pair is at least a few bytes
        raise _Truncated()
    found: List[Tuple[str, str]] = []
    for _ in range(kv_count):
        key = r.string(v1)
        vtype = r.u32()
        val = r.value(vtype, v1)
        if key.startswith("tokenizer.chat_template"):
            if isinstance(val, str):
                found.append((key, val))
            elif isinstance(val, list):
                for idx, s in enumerate(val):
                    found.append(("%s[%d]" % (key, idx), s))
    return found


def scan_bytes(raw: bytes, loc: str) -> List[Finding]:
    """Scan raw GGUF bytes. Emits GCT000 (LOW) if the metadata is unreadable."""
    try:
        templates = extract_chat_templates(raw)
    except _Truncated:
        return [Finding(
            "GCT000", "LOW", "Unreadable or truncated GGUF metadata",
            "gguf-metadata", loc,
            "the GGUF header or metadata table could not be parsed; "
            "it was not scanned for chat-template SSTI",
        )]
    findings: List[Finding] = []
    for key, template in templates:
        findings.extend(scan_template_string(template, "gguf-metadata", "%s::%s" % (loc, key)))
    return findings


def scan_file(path: str) -> List[Finding]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return [Finding("GCT000", "LOW", "Unreadable file", "gguf-metadata", path, str(exc))]
    return scan_bytes(raw, path)


def scan_path(path: str) -> List[Finding]:
    """Scan one .gguf file or walk a directory for .gguf files."""
    if os.path.isdir(path):
        findings: List[Finding] = []
        for root, _dirs, files in os.walk(path):
            for name in sorted(files):
                if name.lower().endswith(".gguf"):
                    findings.extend(scan_file(os.path.join(root, name)))
        return findings
    if path.lower().endswith(".gguf"):
        return scan_file(path)
    return []


def _max_severity(findings: List[Finding]) -> int:
    return max((_SEV_RANK.get(f.severity, 0) for f in findings), default=0)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Static, no-execution scanner for SSTI in GGUF chat templates. "
                    "Made with AI by MV2 of Munim, Inc.")
    parser.add_argument("path", help="a .gguf file or a directory to walk")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH"], default="HIGH",
                        help="exit non-zero if a finding at or above this severity is present")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--version", action="version", version="gguf_chat_template_scan " + __version__)
    args = parser.parse_args(argv)

    findings = scan_path(args.path)
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        if not findings:
            print("No GGUF chat-template findings in %s" % args.path)
        for f in findings:
            line = "%s  %-6s  %s  (%s)" % (f.severity.ljust(6), f.code, f.title, f.source)
            if f.cve:
                line += "  [%s]" % f.cve
            print(line)
            print("    %s" % f.detail)

    threshold = _SEV_RANK[args.fail_on]
    return 1 if _max_severity(findings) >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
