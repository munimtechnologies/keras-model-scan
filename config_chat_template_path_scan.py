# config_chat_template_path_scan.py
#
# Static detector for the HuggingFace Transformers "chat_template key as
# filename" path-traversal arbitrary-file-write class (CVE-2026-9856,
# GHSA-xrqw-3rrv-vx5w, CWE-22, CVSS 7.1, transformers < 5.10.0).
#
# When a tokenizer's chat_template is a DICT (multiple named templates), the
# vulnerable save_chat_templates() path in PreTrainedTokenizerBase /
# ProcessorMixin.save_pretrained() iterates chat_template.items() and writes
# each one to:
#     template_filepath = os.path.join(chat_template_dir, f"{name}.jinja")
# where `name` is the dict KEY taken verbatim from tokenizer_config.json. A
# malicious Hub repo whose chat_template dict has a key like
# "../../../../etc/cron.d/evil" (or an absolute path) escapes the intended
# save directory, so a victim who downloads the tokenizer and calls
# save_pretrained() gets an attacker-controlled file written to an arbitrary
# location (cron ignores the .jinja extension, so this escalates to RCE).
# The fix (transformers 5.10.0) validates template names before joining.
#
# Static signature: a chat_template value that is a DICT whose KEYS are not
# bare template identifiers. A legitimate multi-template key is a plain name
# ("default", "tool_use", "rag"); a key containing a path separator, a ".."
# parent component, or an absolute/drive/UNC prefix is a filename-injection
# surface. This reads the config JSON only (recursively, to reach a
# chat_template inside a processor sub-config); it never writes a file, never
# calls save_pretrained(), never instantiates a tokenizer.
# Class: CWE-22 (improper limitation of a pathname to a restricted directory).
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

__version__ = "0.1.0"

# The config key whose DICT form is written out one file per sub-key.
_CHAT_TEMPLATE_KEY = "chat_template"
# Path separators that must never appear in a legitimate template name.
_SEPARATORS = ("/", "\\")
# A leading drive letter (C:...) marks a Windows absolute path.
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _finding(rule: str, level: str, key: str, value: str, cwe: str, cve: str,
             message: str) -> Dict[str, Any]:
    return {
        "rule": rule, "level": level, "key": key, "value": value,
        "cwe": cwe, "cve": cve, "message": message,
    }


def _is_absolute(name: str) -> bool:
    """True if the template name is an absolute path (POSIX, Windows drive, or
    UNC), which escapes the save directory outright."""
    if name.startswith("/") or name.startswith("\\"):
        return True
    if _DRIVE_RE.match(name):
        return True
    return False


def _has_parent_component(name: str) -> bool:
    """True if any path component of the name is '..' (upward escape)."""
    parts = re.split(r"[\\/]", name)
    return any(p == ".." for p in parts)


def _has_separator(name: str) -> bool:
    return any(sep in name for sep in _SEPARATORS)


def _classify_name(name: str) -> Optional[Dict[str, Any]]:
    """Classify one chat_template dict key. Returns a finding dict, or None if
    the key is a safe bare template identifier."""
    if not isinstance(name, str):
        # Non-string keys cannot occur in JSON objects, but guard anyway.
        return None
    written = json.dumps(f"{name}.jinja")[:120]
    if _has_parent_component(name) or _is_absolute(name):
        return _finding(
            "CTP001", "CRITICAL", name, written, "CWE-22", "CVE-2026-9856",
            "chat_template is a dict whose key '%s' is an absolute path or "
            "contains a '..' parent component. On save_pretrained() this key "
            "is joined as a filename (os.path.join(dir, name + '.jinja')) with "
            "no validation, so it escapes the save directory and writes an "
            "attacker-controlled file to an arbitrary location (e.g. "
            "/etc/cron.d, where the .jinja extension is ignored) -- arbitrary "
            "file write escalating to code execution (CVE-2026-9856, "
            "transformers < 5.10.0)." % name)
    if _has_separator(name):
        return _finding(
            "CTP002", "HIGH", name, written, "CWE-22", "CVE-2026-9856",
            "chat_template is a dict whose key '%s' contains a path separator. "
            "A legitimate template name is a bare identifier; a separated key "
            "is written to a sub-path of the save directory with no "
            "validation (os.path.join(dir, name + '.jinja')), a filename-"
            "injection surface on save_pretrained() (CVE-2026-9856, "
            "transformers < 5.10.0)." % name)
    return None


def _walk(node: Any, out: List[Dict[str, Any]]) -> None:
    """Recursively find every chat_template DICT and classify its keys. A
    string-valued chat_template is not written per-key, so it is not flagged."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == _CHAT_TEMPLATE_KEY and isinstance(v, dict):
                for name in v.keys():
                    f = _classify_name(name)
                    if f is not None:
                        out.append(f)
            _walk(v, out)
    elif isinstance(node, list):
        for item in node:
            _walk(item, out)


def scan(path: str) -> List[Dict[str, Any]]:
    """Scan one tokenizer_config.json / config.json for a chat_template dict
    whose keys would escape the save directory (CVE-2026-9856). Returns a list
    of finding dicts. Reads the file as JSON only; never writes a file, never
    calls save_pretrained(), never instantiates a tokenizer."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [_finding("CTP000", "ERROR", "", "", "", "",
                         f"config could not be read: {exc!r}")]
    try:
        parsed = json.loads(text)
    except Exception as exc:
        return [_finding("CTP000", "ERROR", "", "", "", "",
                         f"config is not valid JSON: {exc!r}")]
    out: List[Dict[str, Any]] = []
    _walk(parsed, out)
    return out


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        print(json.dumps({"path": p, "findings": scan(p)}, indent=2))
