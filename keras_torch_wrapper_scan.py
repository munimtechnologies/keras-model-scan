# keras_torch_wrapper_scan.py
#
# Static detector for the keras.layers.TorchModuleWrapper RCE sink: its public
# from_config method calls torch.load(..., weights_only=False) on serialized
# module data with no explicit unsafe opt-in and no ambient SafeModeScope(True)
# guard, so deserializing a .keras model whose config names a TorchModuleWrapper
# layer unpickles attacker-controlled PyTorch data (arbitrary code execution at
# load time). CWE-502 (Deserialization of Untrusted Data).
#
# This ONE sink carries TWO authoritative OSV advisories across a regression:
#   CVE-2025-49655 (GHSA-cvhh-q5g5-qprp / PYSEC-2026-368): keras 3.11.0-3.11.2,
#       fixed 3.11.3.
#   CVE-2026-12484 (GHSA-v2w2-w228-c444 / PYSEC-2026-3634): affected < 3.12.3,
#       then REGRESSED on the 3.13.x line (introduced 3.13.0, fixed 3.15.0).
#       CVSS 7.8 HIGH (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H).
# Both verified OSV-200. promptfoo ModelAudit's keras_zip_scanner flags this
# layer but cites only CVE-2025-49655, so this detector's attribution is the
# more current one (it names the 2026 regression too).
#
# A .keras file is a ZIP whose config.json is the serialized model graph. This
# detector reads only that JSON (or a raw config.json), walks the serialized
# object tree, and reports any layer whose class_name / registered_name is
# TorchModuleWrapper. It NEVER imports keras or torch, never calls from_config,
# never unpickles, never loads a model.
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.

from __future__ import annotations

import json
import zipfile
from typing import Any, Dict, List

__version__ = "0.2.0"

# The Keras-registered layer whose from_config triggers torch.load with
# weights_only=False by default. Matched against both the class_name and
# registered_name fields of a serialized Keras object.
_TARGET_CLASS = "TorchModuleWrapper"

# The current CVE for the sink (the 2026 regression on the 3.13.x line); the
# related CVE is the original 2025 advisory for the same TorchModuleWrapper path.
_CVE = "CVE-2026-12484"
_RELATED_CVE = "CVE-2025-49655"

_CONFIG_MEMBER = "config.json"


def _finding(rule: str, level: str, where: str, cwe: str, cve: str,
             message: str, related_cve: str = "") -> Dict[str, Any]:
    return {
        "rule": rule, "level": level, "layer": where,
        "cwe": cwe, "cve": cve, "related_cve": related_cve,
        "message": message,
    }


def _walk(node: Any, hits: List[str]) -> None:
    """Record a hit for every serialized object naming TorchModuleWrapper via
    its class_name or registered_name field, at any depth of the config tree."""
    if isinstance(node, dict):
        name = node.get("class_name")
        reg = node.get("registered_name")
        if name == _TARGET_CLASS or reg == _TARGET_CLASS:
            hits.append(name if name == _TARGET_CLASS else (reg or _TARGET_CLASS))
        for v in node.values():
            _walk(v, hits)
    elif isinstance(node, list):
        for item in node:
            _walk(item, hits)


def _scan_config_text(text: str) -> List[Dict[str, Any]]:
    try:
        parsed = json.loads(text)
    except Exception as exc:
        return [_finding("KTW000", "ERROR", "", "", "",
                         f"config.json is not valid JSON: {exc!r}")]
    hits: List[str] = []
    _walk(parsed, hits)
    out: List[Dict[str, Any]] = []
    for _h in hits:
        out.append(_finding(
            "KTW001", "HIGH", _TARGET_CLASS, "CWE-502", _CVE,
            "model config declares a TorchModuleWrapper layer; its from_config "
            "calls torch.load(..., weights_only=False) with no SafeModeScope "
            "guard, so loading this model deserializes attacker-controlled "
            "PyTorch pickle data (arbitrary code execution at load time). "
            "This sink has two advisories across a regression: " + _RELATED_CVE +
            " (fixed keras 3.11.3) and " + _CVE + " (affected < 3.12.3, then "
            "regressed on the 3.13.x line, fixed 3.15.0), both CWE-502. Load "
            "only under SafeModeScope(True), only from a trusted source, and "
            "prefer keras >= 3.15.0.",
            related_cve=_RELATED_CVE))
    return out


def scan(path: str) -> List[Dict[str, Any]]:
    """Scan a .keras archive (or a raw config.json) for a TorchModuleWrapper
    layer. Returns a list of finding dicts (possibly empty). Reads JSON only;
    never imports keras/torch, never unpickles, never loads the model."""
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                if _CONFIG_MEMBER not in zf.namelist():
                    return [_finding("KTW000", "ERROR", "", "", "",
                                     "keras archive has no config.json member")]
                text = zf.read(_CONFIG_MEMBER).decode("utf-8", errors="replace")
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            return [_finding("KTW000", "ERROR", "", "", "",
                             f"keras archive could not be read: {exc!r}")]
        return _scan_config_text(text)
    # Not a zip -> treat the path as a raw config.json
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [_finding("KTW000", "ERROR", "", "", "",
                         f"file could not be read: {exc!r}")]
    return _scan_config_text(text)


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        print(json.dumps({"path": p, "findings": scan(p)}, indent=2))
