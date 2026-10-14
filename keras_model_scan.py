"""keras-model-scan: a static, no-execution safety scanner for .keras model files.

A .keras model is a ZIP archive whose config.json is turned back into a live model
when you call keras.models.load_model(). That rebuild step has been the source of a
string of remote-code-execution and path-traversal CVEs, because attacker-controlled
strings in config.json decide which Python callables get resolved and what archive
members get written to disk.

This tool answers one question before you ever load a model someone sent you:
"does this file contain any of the patterns behind the known Keras load-time CVEs?"

It is deliberately defensive and conservative:
  * It NEVER imports keras / tensorflow and NEVER calls load_model / model_from_json.
  * It NEVER executes, unpickles, marshals, or evaluates anything in the file.
  * It only opens the archive with the stdlib `zipfile`, reads config.json as text,
    parses it as JSON, and walks the resulting data structure for known-bad patterns.

Every rule cites the public CVE / advisory whose pattern it detects. A hit means
"this matches a pattern associated with a known class of malicious model file and
deserves review" -- not a proof of maliciousness. Clean output is not a guarantee
of safety; it only means none of the catalogued patterns were found.

Made by AI agents working as MV2 of Munim, Inc. Apache-2.0 licensed.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from dataclasses import dataclass, asdict
from typing import Any, Iterator

__version__ = "0.1.0"

# Top-level packages Keras' own class resolver (_retrieve_class_or_fn) will import
# from. A function/class node pointing anywhere else is the CVE-2025-1550 shape
# (module="subprocess", config="Popen"). Keep in sync with the Keras allowlist.
KERAS_IMPORT_ALLOWLIST = frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"})

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    location: str
    cve: str

    def as_dict(self) -> dict:
        return asdict(self)


def _walk(node: Any, path: str = "$") -> Iterator[tuple[dict, str]]:
    """Yield every dict node in a parsed-JSON structure, with its JSON-path."""
    if isinstance(node, dict):
        yield node, path
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _walk(value, f"{path}[{i}]")


def _top_package(module: str) -> str:
    return module.split(".", 1)[0] if module else ""


def scan_config(config_text: str, source: str = "config.json") -> list[Finding]:
    """Scan the text of a Keras config.json for known load-time danger patterns."""
    findings: list[Finding] = []

    # KMS003 - config that disables safe mode from inside the load (CVE-2025-9906).
    # Raw-text check: the call can hide in any string field.
    if "enable_unsafe_deserialization" in config_text:
        findings.append(Finding(
            rule="KMS003",
            severity="CRITICAL",
            title="Config references enable_unsafe_deserialization",
            detail="The config references keras.config.enable_unsafe_deserialization. "
                   "A model that turns off safe mode from within its own load sequence "
                   "can then run otherwise-blocked gadgets (e.g. Lambda bytecode). "
                   "Do not load this file.",
            location=source,
            cve="CVE-2025-9906",
        ))

    try:
        data = json.loads(config_text)
    except (ValueError, json.JSONDecodeError) as exc:
        findings.append(Finding(
            rule="KMS000",
            severity="LOW",
            title="config.json is not valid JSON",
            detail=f"Could not parse config as JSON ({exc}); static checks are "
                   "incomplete for this file.",
            location=source,
            cve="",
        ))
        return findings

    for node, path in _walk(data):
        class_name = node.get("class_name")
        module = node.get("module") or ""

        # KMS002 - Lambda layer carrying marshalled Python (CVE-2025-1550 / 2026-12481).
        if class_name == "__lambda__":
            findings.append(Finding(
                rule="KMS002",
                severity="HIGH",
                title="Lambda layer with serialized Python code",
                detail="A '__lambda__' node holds a marshalled Python code object that "
                       "runs when the layer is called. This is blocked under safe_mode, "
                       "but has repeatedly been reachable via safe_mode bypasses. Only "
                       "load from a fully trusted source.",
                location=path,
                cve="CVE-2025-1550, CVE-2026-12481",
            ))

        # KMS001 - function/class node resolving a callable outside the Keras
        # import allowlist: the exact CVE-2025-1550 gadget shape.
        if class_name in ("function", "class") and module:
            pkg = _top_package(module)
            if pkg not in KERAS_IMPORT_ALLOWLIST:
                callable_name = node.get("config")
                nodes = node.get("inbound_nodes")
                has_args = bool(nodes) and any(
                    isinstance(n, dict) and (n.get("args") or n.get("kwargs"))
                    for n in nodes if isinstance(nodes, list)
                )
                sev = "HIGH" if class_name == "function" else "MEDIUM"
                findings.append(Finding(
                    rule="KMS001",
                    severity=sev,
                    title=f"{class_name} node imports from non-Keras module '{module}'",
                    detail=f"class_name='{class_name}' resolves '{callable_name}' from "
                           f"module '{module}', outside the Keras import allowlist "
                           f"{sorted(KERAS_IMPORT_ALLOWLIST)}. This is the shape of the "
                           "subprocess.Popen RCE gadget" +
                           (" and it carries inbound_nodes args that are passed to the "
                            "resolved callable" if has_args else "") +
                           ". Treat as hostile unless the custom object is known.",
                    location=path,
                    cve="CVE-2025-1550",
                ))

        # KMS004 - TFSMLayer loads a TF SavedModel even under safe_mode (CVE-2026-1462).
        if class_name == "TFSMLayer":
            findings.append(Finding(
                rule="KMS004",
                severity="MEDIUM",
                title="TFSMLayer loads an external TensorFlow SavedModel",
                detail="A TFSMLayer causes a TensorFlow SavedModel to be loaded during "
                       "deserialization, which executed even with safe_mode=True. A "
                       "SavedModel can carry its own executable graph ops. Verify the "
                       "referenced SavedModel path and source.",
                location=path,
                cve="CVE-2026-1462",
            ))

    return findings


def _path_traversal(name: str) -> bool:
    norm = name.replace("\\", "/")
    if norm.startswith("/"):
        return True
    if len(norm) >= 2 and norm[1] == ":":  # windows drive letter e.g. C:
        return True
    return ".." in norm.split("/")


def scan_file(path: str) -> list[Finding]:
    """Scan a .keras / .zip model archive, or a raw config.json, statically."""
    findings: list[Finding] = []

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                # KMS005 - Zip/TarSlip: a member that escapes the extraction dir.
                if _path_traversal(name):
                    findings.append(Finding(
                        rule="KMS005",
                        severity="HIGH",
                        title="Archive member escapes the extraction directory",
                        detail=f"Member '{name}' uses an absolute path or '..' and can "
                               "overwrite files outside the target directory when an "
                               "unsafe extractor writes it (Zip/TarSlip).",
                        location=name,
                        cve="CVE-2026-9257",
                    ))
            for cfg_name in ("config.json", "metadata.json"):
                if cfg_name in zf.namelist():
                    try:
                        text = zf.read(cfg_name).decode("utf-8", "replace")
                    except KeyError:
                        continue
                    findings.extend(scan_config(text, source=cfg_name))
    else:
        # Treat the file as a raw config.json / model_from_json payload.
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            findings.extend(scan_config(fh.read(), source=path))
        lower = path.lower()
        if lower.endswith((".h5", ".hdf5")):
            findings.append(Finding(
                rule="KMS007",
                severity="INFO",
                title="Legacy .h5/.hdf5 format",
                detail="The legacy HDF5 format has had load paths where safe_mode was "
                       "not honoured. Prefer the modern .keras format and load with "
                       "safe_mode=True from trusted sources only.",
                location=path,
                cve="CVE-2025-9905",
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return findings


def format_report(path: str, findings: list[Finding]) -> str:
    if not findings:
        return (f"{path}: OK - none of the catalogued Keras load-time patterns were "
                "found.\n(Static scan only; not a guarantee the model is safe.)")
    lines = [f"{path}: {len(findings)} finding(s)\n"]
    for f in findings:
        cve = f" [{f.cve}]" if f.cve else ""
        lines.append(f"  [{f.severity}] {f.rule} {f.title}{cve}")
        lines.append(f"      at {f.location}")
        lines.append(f"      {f.detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keras-model-scan",
        description="Static, no-execution safety scanner for .keras model files.",
    )
    parser.add_argument("paths", nargs="+", help=".keras / .zip archive or config.json")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    total = 0
    json_out = {}
    for path in args.paths:
        try:
            findings = scan_file(path)
        except FileNotFoundError:
            print(f"{path}: not found", file=sys.stderr)
            return 2
        total += len(findings)
        if args.json:
            json_out[path] = [f.as_dict() for f in findings]
        else:
            print(format_report(path, findings))
    if args.json:
        print(json.dumps(json_out, indent=2))
    # Exit 1 if anything was flagged, so this is usable as a CI/pre-load gate.
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
