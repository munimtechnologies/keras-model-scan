# SPDX-License-Identifier: Apache-2.0
# Part of keras-model-scan. Made with AI by MV2 of Munim, Inc.
"""Payload-free regression corpus of crafted .gguf files for GGUF chat-template SSTI.

This module is a self-contained, standard-library-only generator of crafted-but-
harmless ``.gguf`` fixtures whose embedded ``tokenizer.chat_template`` metadata
either is clean or carries a single INERT detector token. It pairs with the
``gguf_chat_template_scan.py`` static scanner (keras-model-scan v0.20.0), which
reads only a GGUF file's header and metadata key/value table (never tensor data),
extracts every ``tokenizer.chat_template`` / ``tokenizer.chat_template.<name>``
string, and flags server-side-template-injection (SSTI) tokens purely as TEXT.

The corpus lets any such scanner be regression-tested end to end on the real GGUF
binary carrier, not just JSON/.jinja sidecars, so a parser regression that stops
chat-template metadata from being reached shows up as a missed finding.

SAFETY. Nothing here is exploitable. Every fixture is just metadata strings in a
GGUF file; no template is ever rendered and jinja2 is never imported. The flagged
fixtures each contain only the smallest INERT token that trips one scanner rule
(for example ``__class__`` alone, or ``popen('id')`` with the harmless read-only
``id`` command) and deliberately OMIT the object-walk (``__mro__`` /
``__subclasses__`` / ``__globals__`` / ``eval(`` / ``exec(``) a real exploit
needs. ``build_corpus`` asserts this before returning, and the test re-checks it.

Finding codes mirror the scanner family:
    CT001 HIGH    Python dunder attribute access      (__class__)
    CT002 HIGH    Jinja SSTI builtin globals          (cycler / lipsum / joiner)
    CT003 HIGH    OS / process / dynamic-import calls  (os. / popen / system()
    CT004 MEDIUM  Dynamic attribute-access bypass      (|attr( / getattr()
    CT005 MEDIUM  Web-framework SSTI globals           (request / config / session)
    CT006 MEDIUM  Template tags                        (import / include / extends)
    GCT000 LOW    GGUF header/metadata unreadable or truncated (not scanned)

The code is Apache-2.0; the generated fixtures and manifest are CC BY 4.0.

Usage:
    python gguf_chat_template_corpus.py --out-dir ./gguf_ct_corpus
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct

# --- GGUF binary format (minimal, string-metadata only) ---------------------

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3
GGUF_TYPE_STRING = 8  # ggml metadata value type for a UTF-8 string


class GGUFReadError(Exception):
    """Raised when a GGUF file is truncated or uses an unsupported value type."""


def _u32(n: int) -> bytes:
    return struct.pack("<I", n)


def _u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def _gguf_str(s: str) -> bytes:
    body = s.encode("utf-8")
    return _u64(len(body)) + body


def write_gguf(path: str, metadata: "dict[str, str]", truncate_bytes=None) -> bytes:
    """Write a minimal little-endian GGUF v3 file with STRING metadata only.

    No tensors are written (tensor_count = 0), which is valid: a GGUF chat-template
    scanner reads only the header and KV table. When ``truncate_bytes`` is given the
    file is cut to that length to simulate unreadable metadata (-> GCT000).
    """
    out = bytearray()
    out += GGUF_MAGIC
    out += _u32(GGUF_VERSION)
    out += _u64(0)                 # tensor_count
    out += _u64(len(metadata))     # metadata_kv_count
    for key, value in metadata.items():
        out += _gguf_str(key)
        out += _u32(GGUF_TYPE_STRING)
        out += _gguf_str(value)
    data = bytes(out)
    if truncate_bytes is not None:
        data = data[:truncate_bytes]
    with open(path, "wb") as f:
        f.write(data)
    return data


def _read_gguf_str(data: bytes, off: int):
    if off + 8 > len(data):
        raise GGUFReadError("truncated string length")
    n = struct.unpack_from("<Q", data, off)[0]
    off += 8
    if off + n > len(data):
        raise GGUFReadError("truncated string body")
    s = data[off:off + n].decode("utf-8", "replace")
    return s, off + n


def read_gguf_metadata(path: str) -> "dict[str, str]":
    """Parse the STRING metadata KV table of a minimal GGUF file.

    Raises GGUFReadError for a bad magic, a truncated file, or a non-STRING value
    type (this corpus only emits STRING values). Mirrors how a scanner would hit
    GCT000 on unreadable metadata.
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise GGUFReadError("header too short")
    if data[:4] != GGUF_MAGIC:
        raise GGUFReadError("bad magic")
    off = 4
    _version = struct.unpack_from("<I", data, off)[0]
    off += 4
    _tensor_count = struct.unpack_from("<Q", data, off)[0]
    off += 8
    kv_count = struct.unpack_from("<Q", data, off)[0]
    off += 8
    md: "dict[str, str]" = {}
    for _ in range(kv_count):
        key, off = _read_gguf_str(data, off)
        if off + 4 > len(data):
            raise GGUFReadError("truncated value type")
        vtype = struct.unpack_from("<I", data, off)[0]
        off += 4
        if vtype != GGUF_TYPE_STRING:
            raise GGUFReadError("unsupported value type %d" % vtype)
        value, off = _read_gguf_str(data, off)
        md[key] = value
    return md


def template_keys(metadata: "dict[str, str]") -> "list[str]":
    """Return the metadata keys that a GGUF chat-template scanner would read."""
    keys = []
    for k in metadata:
        if k == "tokenizer.chat_template" or k.startswith("tokenizer.chat_template."):
            keys.append(k)
    return sorted(keys)


# --- Template fragments -----------------------------------------------------
# Benign controls: real-shape templates, including a namespace(...) call, which a
# good scanner must NOT flag. Flagged fixtures carry one inert detector token.

_BENIGN_CHATML = (
    "{% for message in messages %}"
    "{{ '<|im_start|>' + message['role'] + '\n' + message['content'] + '<|im_end|>' + '\n' }}"
    "{% endfor %}"
    "{% if add_generation_prompt %}{{ '<|im_start|>assistant\n' }}{% endif %}"
)

_BENIGN_NAMESPACE = (
    "{% set ns = namespace(found=false) %}"
    "{% for message in messages %}"
    "{{ message['role'] + ': ' + message['content'].strip() + '\n' }}"
    "{% endfor %}"
)

_BENIGN_TOOL_USE = (
    "{% for message in messages %}"
    "{{ message['role'] + ': ' + message['content'] }}"
    "{% if message.get('tool_calls') %}{{ ' [tool]' }}{% endif %}"
    "{% endfor %}"
)


def _flagged(token_expr: str) -> str:
    return "{% for m in messages %}{{ m['content'] }}{% endfor %}" + token_expr


# code -> severity, matching the scanner family.
_SEVERITY = {
    "CLEAN": "CLEAN",
    "CT001": "HIGH", "CT002": "HIGH", "CT003": "HIGH",
    "CT004": "MEDIUM", "CT005": "MEDIUM", "CT006": "MEDIUM",
    "GCT000": "LOW",
}

# Exploit-completing / destructive tokens that MUST NOT appear in any fixture.
# (Note: the inert CT001 token ``__class__`` and the harmless CT003 ``popen('id')``
# are intentionally absent from this list.)
UNSAFE_TOKENS = (
    "__subclasses__", "__mro__", "__globals__", "__builtins__", "__import__",
    "__base__", "__bases__", "__reduce__", "__dict__", "__init__",
    "eval(", "exec(", "compile(", "subprocess", "system(", "importlib",
    "rm -rf", "/etc/passwd", "; cat", "&&", "| sh", "wget ", "curl ",
)


def _fixtures() -> "list[dict]":
    """Each fixture: filename, the GGUF metadata to write, label and expected code."""
    return [
        {
            "filename": "clean_chatml.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _BENIGN_CHATML,
            },
            "status": "benign", "code": "CLEAN", "token": "",
            "note": "Standard ChatML template. Control: must not be flagged.",
            "truncate_bytes": None,
        },
        {
            "filename": "clean_namespace_multi.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _BENIGN_NAMESPACE,
                "tokenizer.chat_template.tool_use": _BENIGN_TOOL_USE,
            },
            "status": "benign", "code": "CLEAN", "token": "",
            "note": "Benign default + named tool_use template with a legitimate "
                    "namespace(...) call. Control for the multi-template path.",
            "truncate_bytes": None,
        },
        {
            "filename": "dunder_class.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _flagged("{{ self.__class__ }}"),
            },
            "status": "flagged", "code": "CT001", "token": "__class__",
            "note": "Inert dunder attribute access; omits the mro/subclasses walk.",
            "truncate_bytes": None,
        },
        {
            "filename": "ssti_global.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _flagged("{{ cycler }}{{ lipsum }}"),
            },
            "status": "flagged", "code": "CT002", "token": "cycler",
            "note": "Jinja SSTI builtin global names, no payload.",
            "truncate_bytes": None,
        },
        {
            "filename": "oscall.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _flagged("{{ handler.os.popen('id') }}"),
            },
            "status": "flagged", "code": "CT003", "token": "popen",
            "note": "Harmless read-only `id`; no object-walk to actually reach os.",
            "truncate_bytes": None,
        },
        {
            "filename": "attr_filter.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _flagged("{{ data|attr('upper')() }}"),
            },
            "status": "flagged", "code": "CT004", "token": "|attr(",
            "note": "Dynamic attribute-access bypass token only.",
            "truncate_bytes": None,
        },
        {
            "filename": "web_global.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _flagged("{{ request }}{{ config }}"),
            },
            "status": "flagged", "code": "CT005", "token": "request",
            "note": "Web-framework SSTI global names, inert.",
            "truncate_bytes": None,
        },
        {
            "filename": "include_tag.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _flagged("{% include 'base.jinja' %}"),
            },
            "status": "flagged", "code": "CT006", "token": "include",
            "note": "Template-inclusion tag; references a non-existent file.",
            "truncate_bytes": None,
        },
        {
            "filename": "named_template_ssti.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _BENIGN_CHATML,
                "tokenizer.chat_template.tool_use": _flagged("{{ self.__class__ }}"),
            },
            "status": "flagged", "code": "CT001", "token": "__class__",
            "note": "Benign default but the named tool_use template carries the "
                    "inert token: exercises the per-name scan path.",
            "truncate_bytes": None,
        },
        {
            "filename": "malformed_truncated.gguf",
            "metadata": {
                "general.architecture": "llama",
                "tokenizer.chat_template": _BENIGN_CHATML,
            },
            "status": "malformed", "code": "GCT000", "token": "",
            "note": "Valid magic/header but truncated inside the KV table so the "
                    "metadata is unreadable (-> GCT000).",
            "truncate_bytes": 30,
        },
    ]


def _assert_inert(name: str, metadata: "dict[str, str]") -> None:
    blob = "\n".join(metadata.values())
    for tok in UNSAFE_TOKENS:
        if tok in blob:
            raise AssertionError("fixture %s contains unsafe token %r" % (name, tok))


def build_corpus(out_dir: str) -> dict:
    """Write every fixture plus a labelled manifest.json into ``out_dir``."""
    os.makedirs(out_dir, exist_ok=True)
    entries = []
    for fx in _fixtures():
        _assert_inert(fx["filename"], fx["metadata"])
        path = os.path.join(out_dir, fx["filename"])
        data = write_gguf(path, fx["metadata"], truncate_bytes=fx["truncate_bytes"])
        entries.append({
            "filename": fx["filename"],
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "carrier": "gguf",
            "template_keys": template_keys(fx["metadata"]),
            "status": fx["status"],
            "code": fx["code"],
            "severity": _SEVERITY[fx["code"]],
            "representative_token": fx["token"],
            "note": fx["note"],
        })
    manifest = {
        "name": "gguf-chat-template-ssti-corpus",
        "version": "0.21.0",
        "license": "CC BY 4.0",
        "made_with": "AI, by MV2 of Munim, Inc.",
        "generator": "gguf_chat_template_corpus.py",
        "description": (
            "Payload-free crafted .gguf fixtures whose embedded chat_template "
            "metadata regression-tests a static GGUF chat-template SSTI scanner. "
            "No template is ever rendered; every risky fixture carries only an "
            "inert detector token."
        ),
        "scanner": "gguf_chat_template_scan.py (keras-model-scan v0.20.0)",
        "cve_reference": ["CVE-2024-34359", "CVE-2026-5760"],
        "cwe_reference": ["CWE-94", "CWE-1336"],
        "codes": _SEVERITY,
        "counts": {
            "total": len(entries),
            "benign": sum(1 for e in entries if e["status"] == "benign"),
            "flagged": sum(1 for e in entries if e["status"] == "flagged"),
            "malformed": sum(1 for e in entries if e["status"] == "malformed"),
        },
        "fixtures": entries,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the GGUF chat-template SSTI corpus.")
    ap.add_argument("--out-dir", default="gguf_ct_corpus",
                    help="directory to write fixtures and manifest.json into")
    args = ap.parse_args(argv)
    manifest = build_corpus(args.out_dir)
    print("wrote %d fixtures + manifest.json to %s"
          % (manifest["counts"]["total"], args.out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
