# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# safetensors_index_scan.py -- static path-safety validator for the sharded-model
# index files that sit beside large checkpoints (model.safetensors.index.json,
# pytorch_model.bin.index.json, and any HF-style *.index.json with a weight_map).
#
# This work was made with AI, by MV2 of Munim, Inc.
#
# A large checkpoint is split into shards. A small JSON index maps each tensor
# name to the shard file that holds it:
#
#   {"metadata": {"total_size": 13476837376},
#    "weight_map": {"lm_head.weight": "model-00002-of-00002.safetensors", ...}}
#
# To load a shard, a loader resolves the map value against the model directory --
# typically ``os.path.join(model_dir, value)`` or ``Path(model_dir) / value``.
# The value comes straight from the attacker-controlled index file, and a loader
# that does not sanitise it has a path-traversal / arbitrary-file-read primitive
# (CWE-22). Two patterns make this concrete and are the reason this check exists:
#
#   * An ABSOLUTE value (``/etc/passwd`` or ``C:\\Windows\\win.ini``). Both
#     ``os.path.join`` and ``pathlib`` DISCARD the model-directory prefix when the
#     second component is absolute, so the loader opens exactly the attacker's
#     path. This is the bug class reported against several 2026 sharded loaders
#     (e.g. the qwen-mtp / weight_map absolute-path issues and the transformers
#     save_pretrained chat-template path traversal, CVE-2026-9856).
#   * A RELATIVE value with ``..`` segments (``../../../../etc/shadow`` or the
#     Windows ``..\\..\\secret``) that climbs out of the model directory.
#
# The reference huggingface_hub loader hardens this (it rejects anything that is
# not a bare filename in the model directory); many hand-written and research
# loaders do not. This scanner flags index files whose weight_map would let a
# naive loader read or write outside the model directory. It reads ONLY the JSON
# text, never opens a shard, never resolves a path on disk, and never loads or
# executes a model. A finding means the index deserves review before use; it is
# not proof of malice, and a clean result is not a guarantee of safety.
#
# Standard library only. No third-party dependencies.

from __future__ import annotations

import argparse
import json
import ntpath
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Optional

__version__ = "0.1.0"

# A real shard index is a few KB to a few MB of filenames. Anything far larger is
# abnormal and would make a loader that json.load()s it allocate the whole thing;
# we read at most this many bytes and never allocate the declared size blindly.
INDEX_CAP = 50_000_000

# Maximum JSON nesting depth before we refuse to parse, mirroring the safetensors
# header scanner: a deeply nested index is malformed and is the uncontrolled-
# recursion DoS class (CWE-674).
DEPTH_CAP = 100

# Drive-letter-relative Windows paths like ``C:shard`` (no separator) are neither
# caught by posixpath.isabs nor by a ``..`` check, but a Windows loader resolves
# them against the drive's current directory, not the model directory.
_DRIVE_RELATIVE = re.compile(r"^[A-Za-z]:(?![\\/])")

# A URL / fsspec scheme in a shard value (``https://``, ``file://``, ``s3://``):
# loaders built on fsspec or huggingface_hub can fetch a remote or local resource
# the packager chose, turning a shard read into SSRF or an arbitrary-file read.
_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    location: str
    cve: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "location": self.location,
            "cve": self.cve,
        }


def _max_bracket_depth(raw: bytes) -> int:
    """Maximum nesting depth of { and [ in the bytes, ignoring brackets inside
    JSON strings. A single byte pass, so attacker-controlled depth never reaches
    json.loads()."""
    depth = 0
    maxd = 0
    in_str = False
    esc = False
    for b in raw:
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:  # backslash
                esc = True
            elif b == 0x22:  # closing quote
                in_str = False
            continue
        if b == 0x22:  # opening quote
            in_str = True
        elif b == 0x7B or b == 0x5B:  # { or [
            depth += 1
            if depth > maxd:
                maxd = depth
        elif b == 0x7D or b == 0x5D:  # } or ]
            if depth > 0:
                depth -= 1
    return maxd


def _is_absolute_anyos(value: str) -> bool:
    """True if ``value`` is an absolute path under POSIX or Windows rules. We test
    both because the index may be loaded on either OS, and either os.path.join or
    pathlib discards the model-dir prefix when the shard value is absolute."""
    return (posixpath.isabs(value) or ntpath.isabs(value)
            or bool(_DRIVE_RELATIVE.match(value)))


def _split_segments(value: str) -> list[str]:
    """Split on both separators so ``..`` is found whichever OS wrote the path."""
    return re.split(r"[\\/]+", value)


def _classify_value(name: str, value: Any, loc: str) -> Optional[Finding]:
    """Return the dominant path-safety finding for one weight_map entry, or None
    if the value is a safe bare filename. One finding per entry keeps output
    readable; checks run most-dangerous-first."""
    tloc = f"{loc} [weight_map {name!r}]"

    if not isinstance(value, str):
        return Finding(
            "STI007", "LOW", "Malformed weight_map entry",
            f"Tensor {name!r} maps to {value!r} ({type(value).__name__}), not a "
            "string filename.", tloc, "CWE-20")

    if not value:
        return Finding(
            "STI007", "LOW", "Empty shard path",
            f"Tensor {name!r} maps to an empty string.", tloc, "CWE-20")

    if "\x00" in value:
        return Finding(
            "STI006", "MEDIUM", "NUL byte in shard path",
            f"Tensor {name!r} maps to a path containing a NUL byte "
            f"({value!r}). A NUL can truncate the path in a C-backed open(), "
            "hiding the real target from a string check.", tloc, "CWE-158")

    if _URL_SCHEME.match(value) or value.lower().startswith("file:"):
        return Finding(
            "STI004", "MEDIUM", "Remote or scheme-qualified shard path",
            f"Tensor {name!r} maps to {value!r}, which carries a URL/fsspec "
            "scheme. A loader built on fsspec or huggingface_hub may fetch a "
            "remote or arbitrary local resource (SSRF / arbitrary read) instead "
            "of a shard in the model directory.", tloc, "CWE-918")

    if _is_absolute_anyos(value):
        return Finding(
            "STI001", "HIGH", "Absolute shard path escapes the model directory",
            f"Tensor {name!r} maps to the absolute path {value!r}. os.path.join "
            "and pathlib both DISCARD the model-directory prefix when the shard "
            "value is absolute, so a loader opens exactly this path -- an "
            "arbitrary-file read/write primitive from an untrusted index.",
            tloc, "CWE-22")

    if ".." in _split_segments(value):
        return Finding(
            "STI002", "HIGH", "Path traversal in shard path",
            f"Tensor {name!r} maps to {value!r}, which contains a '..' segment. "
            "Resolved against the model directory this climbs out of it, letting "
            "an untrusted index make a naive loader read/write outside the model "
            "package.", tloc, "CWE-22")

    if "\\" in value:
        return Finding(
            "STI003", "MEDIUM", "Backslash separator in shard path",
            f"Tensor {name!r} maps to {value!r}. A shard map should carry bare "
            "filenames; a backslash is a Windows path separator (a literal "
            "character on POSIX), so the same index resolves to different files "
            "on different systems and can smuggle a subdirectory or drive.",
            tloc, "CWE-22")

    if "/" in value:
        return Finding(
            "STI005", "LOW", "Subdirectory component in shard path",
            f"Tensor {name!r} maps to {value!r}, which points into a "
            "subdirectory rather than a bare filename beside the index. This is "
            "unusual for a shard map and worth review.", tloc, "CWE-22")

    return None


def scan_text(text: str, loc: str) -> list[Finding]:
    """Validate the JSON text of a sharded-model index. Pure: no file I/O."""
    findings: list[Finding] = []

    depth = _max_bracket_depth(text.encode("utf-8", "surrogatepass"))
    if depth > DEPTH_CAP:
        return [Finding(
            "STI008", "MEDIUM", "Excessively nested index JSON",
            f"Index nests {depth} levels deep (cap {DEPTH_CAP}); json.loads can "
            "raise an uncaught RecursionError (uncontrolled-recursion DoS). "
            "Parsing was skipped to avoid the same crash.", loc, "CWE-674")]

    try:
        doc = json.loads(text)
    except (ValueError, UnicodeDecodeError) as exc:
        return [Finding(
            "STI009", "HIGH", "Malformed index JSON",
            f"Index is not valid JSON: {exc}. A loader whose error handling does "
            "not catch this crashes on the file.", loc, "CWE-20")]
    except RecursionError:
        return [Finding(
            "STI008", "MEDIUM", "Excessively nested index JSON",
            "json.loads raised RecursionError on the index "
            "(uncontrolled-recursion DoS).", loc, "CWE-674")]

    if not isinstance(doc, dict):
        return [Finding(
            "STI009", "HIGH", "Index is not a JSON object",
            f"Top-level index JSON is {type(doc).__name__}, not an object.",
            loc, "CWE-20")]

    weight_map = doc.get("weight_map")
    if weight_map is None:
        return [Finding(
            "STI000", "INFO", "Not a sharded-tensor index",
            "No 'weight_map' object; this file is not a sharded-model index, so "
            "there are no shard paths to validate.", loc, "")]

    if not isinstance(weight_map, dict):
        return [Finding(
            "STI007", "MEDIUM", "Malformed weight_map",
            f"'weight_map' is {type(weight_map).__name__}, not an object of "
            "tensor-name -> shard-filename.", loc, "CWE-20")]

    for name, value in weight_map.items():
        f = _classify_value(str(name), value, loc)
        if f is not None:
            findings.append(f)

    if not findings:
        findings.append(Finding(
            "STI000", "INFO", "Well-formed shard index",
            f"All {len(weight_map)} weight_map entries are bare filenames that "
            "resolve inside the model directory. No path-traversal, absolute, "
            "remote or NUL-byte shard paths were found.", loc, ""))
    return findings


def scan_file(path: str) -> list[Finding]:
    loc = os.fspath(path)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return [Finding("STI009", "LOW", "Unreadable file",
                        f"Could not stat file: {exc}", loc, "CWE-20")]

    findings: list[Finding] = []
    if size > INDEX_CAP:
        findings.append(Finding(
            "STI010", "MEDIUM", "Oversized index file",
            f"Index is {size} bytes, above the {INDEX_CAP}-byte sanity cap. A "
            "real shard index is at most a few MB of filenames; a loader that "
            "json.load()s this allocates the whole file (allocation DoS). Only "
            "the first portion was parsed.", loc, "CWE-400"))

    try:
        with open(path, "rb") as fh:
            raw = fh.read(INDEX_CAP)
    except OSError as exc:
        return [Finding("STI009", "LOW", "Unreadable file",
                        f"Could not read file: {exc}", loc, "CWE-20")]

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return findings + [Finding(
            "STI009", "HIGH", "Index is not valid UTF-8",
            f"Index bytes are not valid UTF-8: {exc}.", loc, "CWE-20")]

    return findings + scan_text(text, loc)


def _looks_like_index(name: str) -> bool:
    return name.lower().endswith(".index.json")


def scan_path(path: str) -> list[Finding]:
    """Scan one file, or walk a directory for *.index.json files."""
    if os.path.isdir(path):
        out: list[Finding] = []
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if _looks_like_index(fn):
                    out.extend(scan_file(os.path.join(root, fn)))
        return out
    return scan_file(path)


def _max_severity(findings: Iterable[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="safetensors-index-scan",
        description="Static path-safety validator for sharded-model index files "
                    "(model.safetensors.index.json and the like). Flags shard "
                    "paths that escape the model directory. Never opens a shard "
                    "or executes a model. Made with AI by MV2 of Munim, Inc.")
    parser.add_argument("paths", nargs="*", help="files or directories to scan")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit findings as JSON")
    parser.add_argument("--fail-on", default="LOW",
                        choices=list(SEVERITY_ORDER),
                        help="exit 1 if any finding is at least this severity "
                             "(default LOW)")
    parser.add_argument("--version", action="version",
                        version=f"safetensors-index-scan {__version__}")
    args = parser.parse_args(argv)

    if not args.paths:
        parser.print_help()
        return 2

    all_findings: list[Finding] = []
    for p in args.paths:
        all_findings.extend(scan_path(p))

    if args.as_json:
        print(json.dumps([f.as_dict() for f in all_findings], indent=2))
    else:
        for f in all_findings:
            cve = f" [{f.cve}]" if f.cve else ""
            print(f"{f.severity:>8}  {f.rule}{cve}  {f.title}")
            print(f"          {f.detail}")
            print(f"          @ {f.location}")

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if _max_severity(all_findings) >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
