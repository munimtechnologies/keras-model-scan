"""keras_lookup_vocab_scan.py - static, no-execution detector for the Keras
preprocessing-layer "vocabulary" file/URL sink (CVE-2025-12058, CWE-502).

A .keras model is a ZIP archive whose config.json is turned back into a live
model when you call keras.models.load_model(). The StringLookup, IndexLookup
and IntegerLookup preprocessing layers accept a `vocabulary` argument that is
either an inline list of tokens (safe) or a *string path / URL*. When it is a
string, Keras opens it with tf.io.gfile during deserialization - before any
safe_mode object checks - so loading a crafted model reads an attacker-chosen
local file (e.g. ~/.ssh/id_rsa) or fetches an attacker-chosen URL
(e.g. http://169.254.169.254/... cloud-metadata), giving arbitrary local file
read and server-side request forgery (SSRF). safe_mode=True does NOT block it
(CVE-2025-12058, GHSA-qg93-c7p6-gg7f; Keras <= 3.11.3, fixed 3.11.4).

This module reads config.json statically - it never imports keras, never
executes the model, never opens any path named in the config. It flags any
lookup layer whose `vocabulary` is a string, and separates URL/remote-scheme
values (SSRF) from plain paths (local file read).

Rules:
  KLV000 info     config.json is not valid JSON.
  KLV001 medium   lookup layer with a string `vocabulary` path (local file read).
  KLV002 high     lookup layer with a `vocabulary` URL / remote scheme (SSRF).
  KLV003 info     config.json too large to scan safely (decompression-bomb cap).

Exit code 1 if any actionable (non-info) finding, else 0 - usable as a CI gate.

Made with AI by MV2 of Munim, Inc. Apache-2.0.

Prior art: promptfoo's ModelAudit flags Keras Lambda layers but (per its docs)
does not flag the lookup-layer vocabulary file/URL sink. No public static model
scanner was found that covers CVE-2025-12058; this is a stdlib check for it.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from dataclasses import dataclass, asdict
from typing import Any, Iterator

__version__ = "0.1.0"

CVE = "CVE-2025-12058"
CWE = "CWE-502"

# Keras preprocessing layers whose `vocabulary` argument may be a string path
# or URL that is read via tf.io.gfile during load_model (CVE-2025-12058).
LOOKUP_LAYERS = frozenset({"StringLookup", "IndexLookup", "IntegerLookup"})

# URL / remote-filesystem schemes that turn the file read into an SSRF or a
# remote fetch (tf.io.gfile handlers: GCS, HDFS, S3, Azure, plus file:// and
# http(s):// when TensorFlow-IO is present).
REMOTE_SCHEMES = (
    "http://", "https://", "ftp://", "file://",
    "gs://", "hdfs://", "s3://", "az://", "abfs://", "abfss://",
)

# Cap on the config.json we will decompress from a .keras archive, so a
# decompression bomb cannot exhaust memory before we even parse it.
MAX_CONFIG_BYTES = 64 * 1024 * 1024

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


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


def _iter_dicts(node: Any, path: str) -> Iterator[tuple[dict, str]]:
    """Yield (dict_node, json_path) for every dict anywhere in the tree."""
    if isinstance(node, dict):
        yield node, path
        for key, value in node.items():
            yield from _iter_dicts(value, f"{path}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _iter_dicts(value, f"{path}[{i}]")


def _layer_class(node: dict) -> str | None:
    """Return the lookup-layer class name for this node, or None.

    Handles dotted class names ("keras.layers.StringLookup") and registered
    names ("Custom>StringLookup") by comparing the final component.
    """
    for key in ("class_name", "registered_name"):
        raw = node.get(key)
        if isinstance(raw, str) and raw:
            name = raw.split(">")[-1].split(".")[-1]
            if name in LOOKUP_LAYERS:
                return name
    return None


def _classify(vocab: str) -> tuple[str, str, str]:
    """Return (rule, severity, impact) for a string vocabulary value."""
    low = vocab.strip().lower()
    for scheme in REMOTE_SCHEMES:
        if low.startswith(scheme):
            return ("KLV002", "high",
                    "remote fetch / server-side request forgery (SSRF)")
    return ("KLV001", "medium", "arbitrary local file read")


def scan_config(config_text: str, source: str = "config.json") -> list[Finding]:
    """Scan the text of a Keras config.json for lookup vocabulary sinks."""
    try:
        data = json.loads(config_text)
    except (ValueError, TypeError) as exc:
        return [Finding("KLV000", "info", "config.json is not valid JSON",
                        f"could not parse {source}: {exc}", source, "")]

    findings: list[Finding] = []
    for node, path in _iter_dicts(data, source):
        name = _layer_class(node)
        if name is None:
            continue
        cfg = node.get("config")
        if not isinstance(cfg, dict):
            continue
        vocab = cfg.get("vocabulary")
        if not isinstance(vocab, str) or not vocab.strip():
            continue
        rule, severity, impact = _classify(vocab)
        layer_name = cfg.get("name")
        hint = f" (name={layer_name!r})" if isinstance(layer_name, str) else ""
        findings.append(Finding(
            rule, severity,
            f"{name} layer reads its vocabulary from an external source",
            (f"{name} layer{hint} has a string `vocabulary` {vocab!r}, which "
             f"Keras opens with tf.io.gfile during load_model - {impact}. "
             f"safe_mode=True does not block this (the read happens before "
             f"safe_mode object checks)."),
            f"{path}/config/vocabulary",
            CVE,
        ))
    return findings


def scan_file(path: str, max_config_bytes: int = MAX_CONFIG_BYTES) -> list[Finding]:
    """Scan a .keras archive (reads config.json) or a raw config.json file."""
    findings: list[Finding]
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            if "config.json" not in zf.namelist():
                return []
            info = zf.getinfo("config.json")
            if info.file_size > max_config_bytes:
                return [Finding(
                    "KLV003", "info", "config.json too large to scan safely",
                    (f"config.json declares {info.file_size} uncompressed "
                     f"bytes (> cap {max_config_bytes}); skipped to avoid a "
                     f"decompression bomb."),
                    f"{path}!config.json", "")]
            with zf.open("config.json") as fh:
                raw = fh.read(max_config_bytes + 1)
            if len(raw) > max_config_bytes:
                return [Finding(
                    "KLV003", "info", "config.json too large to scan safely",
                    (f"config.json decompressed past the cap "
                     f"{max_config_bytes}; skipped to avoid a decompression "
                     f"bomb."),
                    f"{path}!config.json", "")]
            findings = scan_config(raw.decode("utf-8", "replace"),
                                   f"{path}!config.json")
    else:
        with open(path, "rb") as fh:
            raw = fh.read(max_config_bytes + 1)
        if len(raw) > max_config_bytes:
            return [Finding(
                "KLV003", "info", "file too large to scan safely",
                f"{path} is larger than the cap {max_config_bytes}; skipped.",
                path, "")]
        findings = scan_config(raw.decode("utf-8", "replace"), path)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


def format_report(results: list[tuple[str, list[Finding]]]) -> str:
    lines: list[str] = []
    total = 0
    for path, findings in results:
        if not findings:
            lines.append(f"{path}: OK (no external-source vocabulary found)")
            continue
        for f in findings:
            total += 1
            tail = f"  ({f.cve})" if f.cve else ""
            lines.append(f"{path}: [{f.rule} {f.severity}] {f.title}")
            lines.append(f"    {f.detail}")
            lines.append(f"    location: {f.location}{tail}")
    lines.append("")
    lines.append(f"{total} finding(s)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keras-lookup-vocab-scan",
        description="Static detector for Keras lookup-layer vocabulary "
                    "file/URL sinks (CVE-2025-12058).")
    parser.add_argument("paths", nargs="+",
                        help=".keras archives or config.json files to scan")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    results: list[tuple[str, list[Finding]]] = []
    for path in args.paths:
        try:
            findings = scan_file(path)
        except FileNotFoundError:
            print(f"error: no such file: {path}", file=sys.stderr)
            return 2
        results.append((path, findings))

    actionable = sum(1 for _, fs in results for f in fs if f.severity != "info")
    if args.json:
        out = [{"path": p, "findings": [f.as_dict() for f in fs]}
               for p, fs in results]
        print(json.dumps(out, indent=2))
    else:
        print(format_report(results))
    return 1 if actionable else 0


if __name__ == "__main__":
    raise SystemExit(main())
