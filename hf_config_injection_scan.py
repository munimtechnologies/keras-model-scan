"""Static, no-execution scanner for HuggingFace config-injection RCE (CVE-2026-4372).

Background
----------
A HuggingFace model config (``config.json`` and its nested sub-configs) is plain
JSON and carries no code of its own. But ``transformers`` builds a
``PretrainedConfig`` by calling ``setattr`` for every key in the JSON with no
allowlist. Before the fix, the underscore-prefixed internal field
``_attn_implementation_internal`` (and its companion
``_experts_implementation_internal``) reached an unsandboxed kernel loader: when
its value looked like an ``owner/repo`` Hub id and the ``kernels`` package was
installed, the library downloaded that repository and imported it via
``importlib``, running module-level code in ``__init__.py`` at ``from_pretrained``
time (CVE-2026-4372 / GHSA-29pf-2h5f-8g72, CWE-1066 / CWE-502, CVSS 7.8 HIGH,
transformers < 5.3.0, fixed in 5.3.0). The public ``trust_remote_code`` flag never
gated this path, so a crafted config executes code even with
``trust_remote_code=False``.

The fix (``PretrainedConfig.from_dict``) simply DROPS these keys from the loaded
dict, including nested sub-configs, because transformers never writes them itself.
That is exactly what makes a static detector reliable: a legitimately serialised
config never contains ``_attn_implementation_internal`` or
``_experts_implementation_internal``, so their mere presence is a high-confidence
indicator of a config-injection payload - and it is invisible to scanners that only
grep for ``trust_remote_code`` or ``auto_map``.

This scanner reads only JSON. It never loads a model, never imports a kernel and
never touches the network. It walks every config file in a directory, recurses
through nested dicts and lists (so sub-configs like ``text_config`` are covered),
and flags:

- HCI001 (HIGH): ``_attn_implementation_internal`` present (CVE-2026-4372).
- HCI002 (HIGH): ``_experts_implementation_internal`` present (CVE-2026-4372).
- HCI003 (INFO): ``auto_map`` / ``custom_pipeline`` / ``auto_pipeline`` present -
  the model carries custom Python that runs only under ``trust_remote_code=True``.
  This is legitimate for custom-architecture models, so it is informational, not a
  finding of a vulnerability; review the referenced module before loading with
  remote code.

Honesty: every identifier named here is already public and the vulnerability is
fixed in transformers 5.3.0; the real remediation is upgrading transformers. This
tool describes detection, not exploitation, and a clean scan guarantees nothing.

Usage::

    python hf_config_injection_scan.py ./model-dir --fail-on HIGH

Made with AI by MV2 of Munim, Inc. Licence: Apache-2.0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass

__version__ = "0.1.0"

# Config keys that transformers never serialises itself; their presence in a
# stored config is the CVE-2026-4372 kernel-injection signal.
KERNEL_INJECTION_KEYS = frozenset(
    {"_attn_implementation_internal", "_experts_implementation_internal"}
)

# Keys that point transformers/diffusers at bundled custom Python (the classic
# trust_remote_code vector). Legitimate for custom models -> informational only.
REMOTE_CODE_KEYS = frozenset({"auto_map", "custom_pipeline", "auto_pipeline"})

# The owner/repo Hub id shape that the vulnerable is_kernel() check accepted.
_KERNEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")

SEVERITY = {
    "HCI000": "ERROR",
    "HCI001": "HIGH",
    "HCI002": "HIGH",
    "HCI003": "INFO",
}

_LEVELS = {"ERROR": 3, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Transformers/diffusers config filenames scanned inside a directory.
_EXACT_CONFIG_NAMES = frozenset(
    {
        "config.json",
        "generation_config.json",
        "preprocessor_config.json",
        "tokenizer_config.json",
        "feature_extractor_config.json",
        "image_processor_config.json",
        "processor_config.json",
        "model_index.json",
        "scheduler_config.json",
    }
)

# Configs over this size are not real transformers configs; skip them.
_MAX_BYTES = 8 * 1024 * 1024


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    key: str
    value: str
    data_location: int
    message: str


def _truncate(value, limit: int = 200) -> str:
    text = value if isinstance(value, str) else json.dumps(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _walk(node, dotted: str, depth: int, source: str, findings: list) -> None:
    """Recurse through a parsed config, flagging dangerous keys wherever they sit."""
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{dotted}.{key}" if dotted else str(key)
            if key in KERNEL_INJECTION_KEYS:
                rule = "HCI001" if key == "_attn_implementation_internal" else "HCI002"
                looks_like_id = isinstance(value, str) and bool(
                    _KERNEL_ID_RE.match(value)
                )
                extra = (
                    " Its value matches an owner/repo Hub id, the exact shape the "
                    "vulnerable is_kernel() check accepted."
                    if looks_like_id
                    else ""
                )
                findings.append(
                    Finding(
                        rule=rule,
                        severity=SEVERITY[rule],
                        path=source,
                        key=child,
                        value=_truncate(value),
                        data_location=depth,
                        message=(
                            f"config key {key!r} is never written by transformers; "
                            f"its presence indicates CVE-2026-4372 config injection, "
                            f"which imports an attacker-named kernel repo at load time "
                            f"and bypasses trust_remote_code (upgrade transformers to "
                            f">= 5.3.0).{extra}"
                        ),
                    )
                )
            elif key in REMOTE_CODE_KEYS:
                findings.append(
                    Finding(
                        rule="HCI003",
                        severity=SEVERITY["HCI003"],
                        path=source,
                        key=child,
                        value=_truncate(value),
                        data_location=depth,
                        message=(
                            f"config key {key!r} points transformers/diffusers at "
                            f"bundled custom Python that runs under "
                            f"trust_remote_code=True; this is normal for "
                            f"custom-architecture models - review the referenced "
                            f"module before loading with remote code."
                        ),
                    )
                )
            _walk(value, child, depth + 1, source, findings)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk(item, f"{dotted}[{index}]", depth + 1, source, findings)


def scan_bytes(data, source: str = "<bytes>") -> list:
    """Scan the bytes (or str) of one config file. Returns a list of Finding."""
    findings: list = []
    try:
        text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
        obj = json.loads(text)
    except (ValueError, UnicodeDecodeError) as exc:
        findings.append(
            Finding(
                rule="HCI000",
                severity=SEVERITY["HCI000"],
                path=source,
                key="",
                value="",
                data_location=0,
                message=f"could not parse as JSON: {exc}",
            )
        )
        return findings
    _walk(obj, "", 0, source, findings)
    return findings


def scan_file(path: str) -> list:
    """Scan a single config file on disk. Oversized files are skipped."""
    with open(path, "rb") as handle:
        data = handle.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        return []
    return scan_bytes(data, source=path)


def _is_config_name(name: str) -> bool:
    return name in _EXACT_CONFIG_NAMES or name.endswith("_config.json")


def _iter_config_files(directory: str):
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            if _is_config_name(name):
                yield os.path.join(root, name)


def scan_path(target: str) -> list:
    """Scan a config file, or every config file under a directory."""
    findings: list = []
    if os.path.isdir(target):
        for file_path in _iter_config_files(target):
            findings.extend(scan_file(file_path))
    else:
        findings.extend(scan_file(target))
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="hf-config-injection-scan",
        description=(
            "Static, no-execution scanner for HuggingFace config-injection RCE "
            "(CVE-2026-4372) in model config JSON."
        ),
    )
    parser.add_argument("target", help="a config .json file or a model directory")
    parser.add_argument(
        "--fail-on",
        default="HIGH",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "ERROR"],
        help="exit non-zero if a finding at or above this severity is seen",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--version",
        action="version",
        version=f"hf-config-injection-scan {__version__}",
    )
    args = parser.parse_args(argv)

    findings = scan_path(args.target)

    if args.as_json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif not findings:
        print("hf-config-injection-scan: no findings")
    else:
        for finding in findings:
            print(
                f"{finding.severity} {finding.rule} {finding.path} "
                f"key={finding.key!r} {finding.message}"
            )

    worst = max((_LEVELS[f.severity] for f in findings), default=-1)
    return 1 if worst >= _LEVELS[args.fail_on] else 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
