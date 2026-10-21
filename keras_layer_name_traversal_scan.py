"""keras_layer_name_traversal_scan.py - static, no-execution detector for the
DiskIOStore path traversal driven by Keras 3 layer names
(CVE-2026-12479, GHSA-gh82-f9x8-5frx, CWE-22).

Background. When Keras 3 saves or loads a model it stores each object's state in
a per-object directory whose path is built from the object's name. The
DiskIOStore.make method joins user-controlled layer names onto a temporary
working directory. Keras restricts the forward slash ('/') in a name but does
not restrict parent-directory sequences, so a layer named '..' (or one that
nests several '..' through the layer tree) escapes the temporary directory. A
crafted model can therefore create directories or write/read files in arbitrary
locations when it is saved or loaded. Affected: Keras < 3.12.3 and 3.13.0 up to
(not including) 3.15.0; fixed in 3.12.3 and 3.15.0.

Why existing checks miss it. keras-model-scan's archive scanners check the
*archive member names* inside a .keras ZIP (zip-slip, KMS005 and the nested
container scanner), and the safetensors index scanner checks weight_map *shard
paths*. Neither inspects the layer "name" fields inside config.json, which is
where DiskIOStore gets its path components. ModelAudit, ModelScan, picklescan
and fickling likewise do not parse Keras layer names for traversal. This module
closes that gap by reading only the JSON config and flagging names that are not
safe to turn into a filesystem path.

This module never imports keras and never loads the model. It opens the .keras
archive (a ZIP), reads config.json (and any other .json member) as text, parses
it, walks the layer tree, and classifies every "name" value it finds.

Rules
  DLT000 info    a .json member could not be parsed as JSON.
  DLT001 high    a name contains a parent-directory ('..') path component - the
                 CVE-2026-12479 DiskIOStore escape.
  DLT002 high    a name is an absolute path (POSIX root, Windows drive or UNC) -
                 it redirects the per-object directory to a fixed location.
  DLT003 medium  a name contains a path separator ('/' or '\\') without '..' -
                 current Keras blocks '/', and on Windows '\\' is not covered by
                 a '/'-only filter, so DiskIOStore nests into subdirectories;
                 abnormal for a layer name.
  DLT004 medium  a name contains a NUL byte or other control character - it can
                 truncate or smuggle the on-disk path.
  DLT005 info    a .keras member too large to scan in memory, or an archive
                 member could not be read.

Limits: only JSON model configs are inspected (the .keras format and a bare
config.json). Legacy .h5 models that keep model_config as an HDF5 attribute are
not parsed here. The weights store's internal paths derive from these same
names, so scanning the config names covers the DiskIOStore sink without loading
weights. A clean scan does not prove a file is safe.

Usage
    python keras_layer_name_traversal_scan.py model.keras config.json
    python keras_layer_name_traversal_scan.py --json model.keras

Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
import zlib
from dataclasses import dataclass, asdict
from typing import Iterator

__version__ = "0.1.0"

CVE = "CVE-2026-12479"

# A name component splits on either separator: '/' is what Keras tries to block,
# '\\' is the Windows separator a '/'-only filter leaves open.
_SEP_RE = re.compile(r"[/\\]")

# Absolute-path shapes: POSIX root ('/...'), a leading backslash / UNC ('\\...'),
# or a Windows drive prefix ('C:...').
_DRIVE_RE = re.compile(r"^[A-Za-z]:")

# .keras members larger than this are not read into memory.
MAX_MEMBER_BYTES = 1 << 28


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


def _iter_names(obj: object, parent_label: str = "") -> Iterator[tuple[str, str]]:
    """Yield (name_value, enclosing_label) for every string "name" field.

    The enclosing label is the nearest class_name above the name, so a finding
    can say which kind of object the name belongs to.
    """
    if isinstance(obj, dict):
        cls = obj.get("class_name")
        label = cls if isinstance(cls, str) and cls else parent_label
        nm = obj.get("name")
        if isinstance(nm, str):
            yield (nm, label or "object")
        for key, value in obj.items():
            if key == "name":
                continue
            yield from _iter_names(value, label)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_names(item, parent_label)


def _is_absolute(name: str) -> bool:
    return (name.startswith("/") or name.startswith("\\")
            or bool(_DRIVE_RE.match(name)))


def _has_control_char(name: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in name)


def _classify(name: str) -> tuple[str, str, str, str] | None:
    """(rule, severity, title, detail) for a dangerous name, else None."""
    if not name:
        return None
    components = _SEP_RE.split(name)
    if any(part == ".." for part in components):
        return ("DLT001", "high",
                "Layer name contains a parent-directory traversal component",
                "a '..' component escapes the per-object directory that "
                "DiskIOStore builds from this name, so saving or loading the "
                "model reads or writes outside the intended temporary directory")
    if _is_absolute(name):
        return ("DLT002", "high",
                "Layer name is an absolute path",
                "an absolute path redirects the per-object directory that "
                "DiskIOStore builds from this name to a fixed location outside "
                "the intended temporary directory")
    if _SEP_RE.search(name):
        return ("DLT003", "medium",
                "Layer name contains a path separator",
                "current Keras restricts '/' in a name; a '/' or '\\' here nests "
                "the DiskIOStore directory into subdirectories (and on Windows "
                "'\\' is not covered by a '/'-only filter), abnormal for a name")
    if _has_control_char(name):
        return ("DLT004", "medium",
                "Layer name contains a control or NUL character",
                "a NUL or control character can truncate or smuggle the on-disk "
                "path DiskIOStore builds from this name, abnormal for a name")
    return None


def scan_config(config: object, member: str = "") -> list[Finding]:
    """Scan one parsed Keras config object for traversal-unsafe names."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for name, label in _iter_names(config):
        if name in seen:
            continue
        seen.add(name)
        verdict = _classify(name)
        if verdict is None:
            continue
        rule, severity, title, detail = verdict
        cve = CVE if rule in ("DLT001", "DLT002") else "CWE-22"
        where = f"{member}: " if member else ""
        findings.append(Finding(rule, severity, title, detail,
                                where + f"{label} name {name!r}", cve))
    return findings


def scan_bytes(buf: bytes, member: str = "") -> list[Finding]:
    """Scan the bytes of one JSON model config."""
    try:
        config = json.loads(buf)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [Finding("DLT000", "info", "Config is not readable JSON",
                        str(exc), member or "config", "")]
    return scan_config(config, member)


def _scan_zip(path: str) -> list[Finding]:
    findings: list[Finding] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir() or not name.lower().endswith(".json"):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                findings.append(Finding(
                    "DLT005", "info", "JSON member too large to scan in memory",
                    f"{info.file_size} bytes; extract it and scan it directly",
                    name, ""))
                continue
            try:
                data = zf.read(info)
            except (zipfile.BadZipFile, EOFError, NotImplementedError,
                    zlib.error) as exc:
                findings.append(Finding("DLT005", "info",
                                        "JSON member could not be read",
                                        str(exc), name, ""))
                continue
            findings.extend(scan_bytes(data, member=name))
    return findings


def scan_file(path: str) -> list[Finding]:
    """Scan a .keras archive (its .json members) or a bare JSON config."""
    if zipfile.is_zipfile(path):
        return _scan_zip(path)
    with open(path, "rb") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            return [Finding("DLT000", "info", "Config is not readable JSON",
                            "empty file", "config", "")]
        return scan_bytes(fh.read(), member=os.path.basename(path))


def format_report(results: list[tuple[str, list[Finding]]]) -> str:
    lines: list[str] = []
    total = 0
    for path, findings in results:
        if not findings:
            lines.append(f"{path}: OK (no traversal-unsafe layer name found)")
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
        prog="keras-layer-name-traversal-scan",
        description="Static detector for the CVE-2026-12479 DiskIOStore path "
                    "traversal (a Keras layer name such as '..' used to build "
                    "an on-disk path) in Keras model configs.")
    parser.add_argument("paths", nargs="+",
                        help=".keras archives or JSON config files to scan")
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
