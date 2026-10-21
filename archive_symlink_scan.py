# archive_symlink_scan.py
#
# Static detector for symlink / hardlink members in model-package archives
# (zip and tar). A symlink member whose target escapes the extraction directory
# is a load-time path-traversal sink: a loader that extracts the package follows
# the link out of the model dir to read or overwrite arbitrary files.
# Class: CWE-61 (UNIX symbolic link following) + CWE-22 (path traversal).
# Known instances: CVE-2026-27489, CVE-2026-34447 (ONNX external-data symlink
# traversal, fixed onnx 1.21.0); CVE-2026-65010 (Hugging Face datasets
# Extractor.extract() symlink-following arbitrary file write, CWE-61).
#
# Reads archive metadata only. Never extracts regular files, never opens a
# referenced data file, never loads or runs the model. For members already
# identified as symlinks it reads only the (tiny) link-target bytes, size-capped.
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.

from __future__ import annotations

import os
import stat
import tarfile
import zipfile
from typing import Any, Dict, List

__version__ = "0.1.0"

_SYMLINK_TARGET_CAP = 4096  # bytes; real symlink targets are tiny


def _target_escapes(target: str) -> bool:
    """True if a link target is absolute or walks out of the archive root."""
    if not target:
        return False
    t = target.replace("\\", "/")
    if t.startswith("/"):
        return True
    if len(target) >= 2 and target[1] == ":":
        return True
    if target.startswith("\\\\"):
        return True
    parts = [p for p in t.split("/") if p not in ("", ".")]
    depth = 0
    for p in parts:
        if p == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def _finding(rule: str, level: str, member: str, target: str,
             cwe: str, cve: str, message: str) -> Dict[str, Any]:
    return {
        "rule": rule, "level": level, "member": member, "target": target,
        "cwe": cwe, "cve": cve, "message": message,
    }


def _scan_zip(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with zipfile.ZipFile(path) as zf:
        for zi in zf.infolist():
            mode = (zi.external_attr >> 16) & 0xFFFF
            if not stat.S_ISLNK(mode):
                continue
            target = ""
            try:
                if zi.file_size <= _SYMLINK_TARGET_CAP:
                    target = zf.read(zi).decode("utf-8", "replace")
            except Exception:
                target = ""
            if _target_escapes(target):
                out.append(_finding(
                    "ASL001", "HIGH", zi.filename, target,
                    "CWE-61+CWE-22", "CVE-2026-27489",
                    "zip member is a symlink whose target escapes the "
                    "extraction directory (absolute or '..')."))
            else:
                out.append(_finding(
                    "ASL004", "MEDIUM", zi.filename, target, "CWE-61", "",
                    "zip member is a symlink; target stays in-dir but a "
                    "symlink in a model package is unusual."))
    return out


def _scan_tar(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            if not (m.issym() or m.islnk()):
                continue
            target = m.linkname or ""
            escapes = _target_escapes(target)
            if m.issym():
                rule = "ASL002" if escapes else "ASL004"
                kind = "symlink"
            else:
                rule = "ASL003" if escapes else "ASL004"
                kind = "hardlink"
            if escapes:
                out.append(_finding(
                    rule, "HIGH", m.name, target, "CWE-61+CWE-22",
                    "CVE-2026-27489",
                    f"tar {kind} member whose target escapes the "
                    "extraction directory (absolute or '..')."))
            else:
                out.append(_finding(
                    "ASL004", "MEDIUM", m.name, target, "CWE-61", "",
                    f"tar {kind} member; target stays in-dir but a link "
                    "member in a model package is unusual."))
    return out


def scan(path: str) -> List[Dict[str, Any]]:
    """Scan one archive file. Returns a list of finding dicts (possibly empty)."""
    try:
        if zipfile.is_zipfile(path):
            return _scan_zip(path)
        if tarfile.is_tarfile(path):
            return _scan_tar(path)
    except Exception as exc:  # unreadable / truncated archive
        return [_finding("ASL000", "ERROR", os.path.basename(path), "",
                         "", "", f"archive could not be read: {exc!r}")]
    return []


if __name__ == "__main__":
    import json
    import sys
    for p in sys.argv[1:]:
        print(json.dumps({"path": p, "findings": scan(p)}, indent=2))
