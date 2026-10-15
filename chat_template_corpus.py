#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Made with AI by MV2 of Munim, Inc.
"""Benign regression corpus for chat-template SSTI detection.

This module generates a small, self-contained set of crafted - but completely
harmless - model chat-template fixtures for regression-testing a static
server-side-template-injection (SSTI) scanner such as chat_template_scan.py.

Background: a chat template is a Jinja2 rule, shipped inside a model, that turns
chat messages into a prompt string. Several projects rendered that template with
an UNSANDBOXED jinja2.Environment, so a poisoned template could reach arbitrary
code. Public, already-fixed cases: CVE-2024-34359 / GHSA-56xg-wfcc-g829
(abetlen/llama-cpp-python, GGUF tokenizer.chat_template, fixed 0.2.72), the
berriai/litellm hf_chat_template huntr report, and guidance-ai/guidance PR #1475.
Weaknesses: CWE-94 (code injection), CWE-1336 (template injection). The fix in
every case is ImmutableSandboxedEnvironment, not a scanner.

The fixtures here carry only INERT detector-regression tokens. They are static
JSON/text that this module and its tests NEVER render; jinja2 is never imported.
The one OS-call fixture uses the universally harmless, read-only placeholder
command 'id' and deliberately omits the __subclasses__/__mro__ walk that a real
exploit would need, so nothing here is a working exploit.

Usage:
    python chat_template_corpus.py --out-dir ./corpus_chat_template

Fixtures map to the chat_template_scan.py finding codes:
    CT000 LOW     unreadable/unparseable carrier
    CT001 HIGH    Python dunder attribute access (e.g. __class__)
    CT002 HIGH    Jinja SSTI builtin global (cycler/lipsum/joiner)
    CT003 HIGH    OS/process/dynamic-import call
    CT004 MEDIUM  dynamic attribute-access bypass (attr filter / getattr)
    CT005 MEDIUM  web-framework SSTI global (request./url_for)
    CT006 MEDIUM  template import/include/extends tag

Code is Apache-2.0; the fixture data and manifest are CC BY 4.0.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List, Optional

__version__ = "0.19.0"

CVE = "CVE-2024-34359"
ADVISORY = "GHSA-56xg-wfcc-g829"
AFFECTED = "llama-cpp-python < 0.2.72 (class); see also litellm, guidance PR #1475"
CWE = "CWE-94, CWE-1336"
SCANNER = "chat_template_scan.py"

# Substrings that must never appear in a CLEAN control (gadget tokens) and,
# separately, tokens that would make a fixture a real exploit rather than an
# inert regression input. Kept explicit so the tests can assert both.
GADGET_SUBSTRS = (
    "__class__", "__globals__", "cycler", "lipsum", "joiner",
    "os.popen", "os.system", "subprocess", "|attr(", "getattr(",
    "request.", "url_for", "{% include", "{% import", "{% extends",
)
DESTRUCTIVE_SUBSTRS = (
    "__subclasses__", "__mro__", "__builtins__", "rm -rf", "/etc/passwd",
    "base64", "curl ", "wget ", "powershell", "nc -", "eval(",
)

# A realistic, safe Llama-style template reused by the clean control. It uses a
# namespace() (which the scanner deliberately does NOT flag) and a role loop.
_CLEAN_TEMPLATE = (
    "{% set ns = namespace(sys=false) %}"
    "{% for message in messages %}"
    "{% if message['role'] == 'user' %}"
    "{{ bos_token }}[INST] {{ message['content'] }} [/INST]"
    "{% elif message['role'] == 'assistant' %}"
    "{{ message['content'] }}{{ eos_token }}"
    "{% endif %}{% endfor %}"
)

# Each entry is a plain dict (not a dataclass). content is either a dict
# (serialized to JSON) or a raw string (written verbatim, for .jinja sidecars
# and the intentionally-malformed JSON).
CORPUS: List[Dict[str, Any]] = [
    {
        "filename": "clean_tokenizer_config.json",
        "carrier": "tokenizer_config.json",
        "expected_code": "",
        "expected_severity": "CLEAN",
        "trigger": "",
        "cwe": "",
        "note": "Benign Llama-style template: role loop, namespace(), bos/eos tokens.",
        "content": {
            "bos_token": "<s>",
            "eos_token": "</s>",
            "chat_template": _CLEAN_TEMPLATE,
        },
    },
    {
        "filename": "clean_chat_template.jinja",
        "carrier": ".jinja sidecar",
        "expected_code": "",
        "expected_severity": "CLEAN",
        "trigger": "",
        "cwe": "",
        "note": "Benign sidecar template: role markers and a message loop only.",
        "content": (
            "{% for message in messages %}"
            "{{ '<|' + message['role'] + '|>' }}\n{{ message['content'] }}\n"
            "{% endfor %}{{ '<|assistant|>' }}\n"
        ),
    },
    {
        "filename": "dunder_class_tokenizer_config.json",
        "carrier": "tokenizer_config.json",
        "expected_code": "CT001",
        "expected_severity": "HIGH",
        "trigger": "__class__",
        "cwe": "CWE-1336",
        "note": "Dunder attribute access in the template string; inert, never rendered.",
        "content": {
            "chat_template": (
                "{% for m in messages %}{{ m['content'] }}{% endfor %}"
                "{{ ''.__class__ }}"
            ),
        },
    },
    {
        "filename": "ssti_global_tokenizer_config.json",
        "carrier": "tokenizer_config.json (named-template list)",
        "expected_code": "CT002",
        "expected_severity": "HIGH",
        "trigger": "cycler",
        "cwe": "CWE-1336",
        "note": "Jinja builtin global 'cycler'; chat_template given as a named-template list.",
        "content": {
            "chat_template": [
                {
                    "name": "default",
                    "template": (
                        "{% for m in messages %}{{ m['content'] }}{% endfor %}"
                        "{{ cycler('a','b') }}"
                    ),
                }
            ],
        },
    },
    {
        "filename": "oscall_chat_template.jinja",
        "carrier": ".jinja sidecar",
        "expected_code": "CT003",
        "expected_severity": "HIGH",
        "trigger": "os.popen",
        "cwe": "CWE-94",
        "note": "OS-call token using the harmless read-only placeholder 'id'; "
                "inert static string, never rendered, not a subclass-walk chain.",
        "content": (
            "{% for m in messages %}{{ m['content'] }}{% endfor %}"
            "{{ handler.os.popen('id') }}"
        ),
    },
    {
        "filename": "attr_filter_tokenizer_config.json",
        "carrier": "tokenizer_config.json",
        "expected_code": "CT004",
        "expected_severity": "MEDIUM",
        "trigger": "|attr(",
        "cwe": "CWE-1336",
        "note": "Dynamic attribute bypass via the attr filter, with no dunder literal.",
        "content": {
            "chat_template": (
                "{% for m in messages %}{{ m|attr(field) }}{% endfor %}"
            ),
        },
    },
    {
        "filename": "web_global_tokenizer_config.json",
        "carrier": "tokenizer_config.json (named-template list)",
        "expected_code": "CT005",
        "expected_severity": "MEDIUM",
        "trigger": "url_for",
        "cwe": "CWE-1336",
        "note": "Flask SSTI global url_for, which has no place in a chat template.",
        "content": {
            "chat_template": [
                {
                    "name": "tool_use",
                    "template": (
                        "{% for m in messages %}{{ m['content'] }}{% endfor %}"
                        "{{ url_for('static', filename='x') }}"
                    ),
                }
            ],
        },
    },
    {
        "filename": "include_tag_chat_template.jinja",
        "carrier": ".jinja sidecar",
        "expected_code": "CT006",
        "expected_severity": "MEDIUM",
        "trigger": "{% include",
        "cwe": "CWE-1336",
        "note": "Template include tag pulling an external file into the render.",
        "content": (
            "{% include 'extra_prompt.jinja' %}"
            "{% for m in messages %}{{ m['content'] }}{% endfor %}"
        ),
    },
    {
        "filename": "malformed_tokenizer_config.json",
        "carrier": "tokenizer_config.json",
        "expected_code": "CT000",
        "expected_severity": "LOW",
        "trigger": "",
        "cwe": "",
        "note": "Truncated JSON that will not parse; exercises the unreadable-file path.",
        # Raw string on purpose: unterminated, so json.loads raises.
        "content": "{\"chat_template\": \"{% for m in messages %}{{ m['content'] }}",
    },
]


def write_corpus(out_dir: str) -> Dict[str, Any]:
    """Write every fixture plus manifest.json to out_dir; return the manifest."""
    os.makedirs(out_dir, exist_ok=True)
    files: List[Dict[str, Any]] = []
    for entry in CORPUS:
        path = os.path.join(out_dir, entry["filename"])
        content = entry["content"]
        if isinstance(content, str):
            text = content
        else:
            text = json.dumps(content, indent=2, sort_keys=True) + "\n"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        files.append({k: entry[k] for k in (
            "filename", "carrier", "expected_code", "expected_severity",
            "trigger", "cwe", "note",
        )})
    manifest = {
        "corpus": "chat-template-ssti",
        "version": __version__,
        "cve": CVE,
        "advisory": ADVISORY,
        "affected": AFFECTED,
        "cwe": CWE,
        "scanner": SCANNER,
        "finding_codes": {
            "CT000": "unreadable/unparseable carrier (LOW)",
            "CT001": "Python dunder attribute access (HIGH)",
            "CT002": "Jinja SSTI builtin global (HIGH)",
            "CT003": "OS/process/dynamic-import call (HIGH)",
            "CT004": "dynamic attribute-access bypass (MEDIUM)",
            "CT005": "web-framework SSTI global (MEDIUM)",
            "CT006": "template import/include/extends tag (MEDIUM)",
        },
        "carriers": [
            "tokenizer_config.json chat_template (string)",
            "tokenizer_config.json chat_template (named-template list)",
            ".jinja/.jinja2/.j2 sidecar",
        ],
        "note": "Inert regression fixtures; never rendered. Code Apache-2.0, data CC BY 4.0.",
        "files": files,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write the benign chat-template SSTI regression corpus.")
    parser.add_argument("--out-dir", default="corpus_chat_template",
                        help="directory to write fixtures and manifest.json into")
    args = parser.parse_args(argv)
    manifest = write_corpus(args.out_dir)
    sev = [f["expected_severity"] for f in manifest["files"]]
    print("wrote {} fixtures + manifest.json to {}".format(
        len(manifest["files"]), args.out_dir))
    print("  HIGH={} MEDIUM={} LOW={} CLEAN={}".format(
        sev.count("HIGH"), sev.count("MEDIUM"),
        sev.count("LOW"), sev.count("CLEAN")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
