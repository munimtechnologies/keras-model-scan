# config_trust_remote_code_scan.py
#
# Static detector for the HuggingFace Transformers "serialized
# trust_remote_code override" remote-code-execution class (CVE-2026-5241,
# CWE-829, CVSS 8.0, AV:L/UI:R, fixed just after transformers 5.2.0).
#
# trust_remote_code is a CALLER-supplied argument to from_pretrained() /
# from_config(); it is never a legitimate serialized configuration field.
# On the vulnerable LightGlue path (transformers 5.2.0), LightGlueConfig
# stored a deserialized trust_remote_code read from a remote config.json and
# treated config.trust_remote_code as authoritative, propagating it into
# nested AutoConfig.from_pretrained() / AutoModelForKeypointDetection
# .from_config() calls. A victim who called from_pretrained(..., trust_remote
# _code=False) therefore had their explicit False SILENTLY REPLACED by an
# attacker-controlled value baked into the config file, so an attacker-set
# "trust_remote_code": true (together with an auto_map pointing at attacker
# modules) caused custom Python to be imported and executed at load time.
# The fix removed the trust_remote_code field from LightGlueConfig and stopped
# propagating it into the nested from_config() calls.
#
# Static signature: the PRESENCE of a "trust_remote_code" key inside a
# serialized config.json is anomalous (it should never be serialized). A
# truthy serialized value is the CVE-2026-5241 override signature; any other
# serialized value is still an injection surface. An auto_map value present in
# the same file is reported as the custom-code execution target, because
# trust_remote_code only matters when there is custom code to trust.
#
# This reads config.json as JSON (recursively, to reach nested sub-configs
# such as text_config / vision_config / keypoint_detector_config), never
# imports anything, never resolves auto_map, never instantiates a model.
# Class: CWE-829 (inclusion of functionality from an untrusted control sphere).
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.

from __future__ import annotations

import json
from typing import Any, Dict, List

__version__ = "0.1.0"

# The caller-only argument that must never be deserialized from a config file.
_TRC_KEY = "trust_remote_code"
# The field that points from_pretrained() at custom architecture code; its
# presence is the execution target that trust_remote_code gates. auto_map is a
# legitimate field for custom-code repos, so it is reported as CONTEXT only,
# never as a standalone finding.
_AUTO_MAP_KEY = "auto_map"

# String spellings that mean "true" for a serialized trust_remote_code value.
_TRUTHY_STRINGS = frozenset({"true", "1", "yes", "on"})


def _finding(rule: str, level: str, key: str, value: str, cwe: str, cve: str,
             message: str) -> Dict[str, Any]:
    return {
        "rule": rule, "level": level, "key": key, "value": value,
        "cwe": cwe, "cve": cve, "message": message,
    }


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _TRUTHY_STRINGS
    if isinstance(value, (int, float)):
        return value != 0
    return False


def _classify(value: Any, auto_map_present: bool) -> Dict[str, Any]:
    target = (" An auto_map entry is also present in this config, naming the "
              "custom module/class that would be imported and executed."
              if auto_map_present else "")
    if _is_truthy(value):
        return _finding(
            "CTR001", "CRITICAL", _TRC_KEY, json.dumps(value)[:120],
            "CWE-829", "CVE-2026-5241",
            "serialized config.json sets the caller-only argument "
            "'trust_remote_code' to a truthy value. trust_remote_code is a "
            "from_pretrained() argument and must never be stored in a config "
            "file; on transformers 5.2.0 (LightGlue path) the serialized value "
            "overrides the caller's explicit trust_remote_code=False and is "
            "propagated into nested from_config() calls, so custom Python is "
            "imported and executed at load time -- arbitrary code execution "
            "(CVE-2026-5241)." + target)
    return _finding(
        "CTR002", "HIGH", _TRC_KEY, json.dumps(value)[:120],
        "CWE-829", "CVE-2026-5241",
        "serialized config.json contains the caller-only argument "
        "'trust_remote_code'. It is never a legitimate config field; its "
        "presence at rest is a tampering / injection surface, and on the "
        "vulnerable LightGlue propagation path even a serialized value can be "
        "treated as authoritative (CVE-2026-5241)." + target)


def _auto_map_present(node: Any) -> bool:
    """True if an auto_map key appears anywhere in the config tree."""
    if isinstance(node, dict):
        if _AUTO_MAP_KEY in node:
            return True
        return any(_auto_map_present(v) for v in node.values())
    if isinstance(node, list):
        return any(_auto_map_present(item) for item in node)
    return False


def _walk(node: Any, auto_map_present: bool, out: List[Dict[str, Any]]) -> None:
    """Recursively visit every dict key so nested sub-configs (text_config,
    vision_config, keypoint_detector_config, ...) are covered. A trust_remote
    _code key yields one finding; recursion continues into every value."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == _TRC_KEY:
                out.append(_classify(v, auto_map_present))
            _walk(v, auto_map_present, out)
    elif isinstance(node, list):
        for item in node:
            _walk(item, auto_map_present, out)


def scan(path: str) -> List[Dict[str, Any]]:
    """Scan one HuggingFace config.json (or any JSON config) for a serialized
    trust_remote_code override (CVE-2026-5241). Returns a list of finding
    dicts. Reads the file as JSON only; never imports a module, never resolves
    auto_map, never instantiates a model."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [_finding("CTR000", "ERROR", "", "", "", "",
                         f"config could not be read: {exc!r}")]
    try:
        parsed = json.loads(text)
    except Exception as exc:
        return [_finding("CTR000", "ERROR", "", "", "", "",
                         f"config is not valid JSON: {exc!r}")]
    out: List[Dict[str, Any]] = []
    _walk(parsed, _auto_map_present(parsed), out)
    return out


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        print(json.dumps({"path": p, "findings": scan(p)}, indent=2))
