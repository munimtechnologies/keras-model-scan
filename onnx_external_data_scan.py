# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# onnx_external_data_scan.py - static, no-execution scanner for path traversal
# in the external_data `location` field of ONNX model files (CWE-22).
#
# An .onnx file is a protobuf ModelProto. A TensorProto whose data_location is
# EXTERNAL stores its weights in a separate file named by an `external_data`
# key/value entry with key "location". The ONNX spec requires this location to
# be a RELATIVE path inside the model directory, but naive loaders join it onto
# the model directory without checking, so an absolute path, a ".." segment, a
# URL scheme or a NUL byte reads (or writes) an arbitrary local file at load
# time - with no pickle and no code in the package. Public cases:
#   * onnx < 1.13.0  - CVE-2022-25882 / GHSA-ffxj-547x-5j7c (CWE-22)
#   * tract-onnx     - CVE-2026-55832 / GHSA-h668-6x6g-f8r5 (CWE-22)
#
# This module parses the protobuf wire format itself (standard library only,
# no onnx dependency), reads ONLY the external_data location strings, never
# opens a referenced data file and never loads or runs the model. A clean scan
# guarantees nothing; it flags the specific field that these advisories abuse.
#
# This work was made with AI, by MV2 of Munim, Inc.

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Optional

__version__ = "0.1.0"

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Caps so a malformed or hostile file cannot exhaust memory or recursion.
MAX_BYTES = 256 * 1024 * 1024      # read at most 256 MiB of a file
MAX_DEPTH = 64                      # subgraph nesting
MAX_FINDINGS = 10000

# Protobuf field numbers (onnx.proto).
_F_MODEL_GRAPH = 7                  # ModelProto.graph (GraphProto)
_F_GRAPH_NODE = 1                  # GraphProto.node (repeated NodeProto)
_F_GRAPH_INIT = 5                 # GraphProto.initializer (repeated TensorProto)
_F_GRAPH_SPARSE = 15               # GraphProto.sparse_initializer (SparseTensorProto)
_F_NODE_ATTR = 5                   # NodeProto.attribute (repeated AttributeProto)
_F_ATTR_T = 5                      # AttributeProto.t (TensorProto)
_F_ATTR_G = 6                      # AttributeProto.g (GraphProto)
_F_ATTR_TENSORS = 10               # AttributeProto.tensors (repeated TensorProto)
_F_ATTR_GRAPHS = 11                # AttributeProto.graphs (repeated GraphProto)
_F_ATTR_SPARSE = 22                # AttributeProto.sparse_tensor (SparseTensorProto)
_F_ATTR_SPARSES = 23               # AttributeProto.sparse_tensors (repeated)
_F_SPARSE_VALUES = 1               # SparseTensorProto.values (TensorProto)
_F_SPARSE_INDICES = 2              # SparseTensorProto.indices (TensorProto)
_F_TENSOR_NAME = 8                 # TensorProto.name (string)
_F_TENSOR_EXTDATA = 13             # TensorProto.external_data (StringStringEntryProto)
_F_TENSOR_DATALOC = 14             # TensorProto.data_location (int32)
_F_SSE_KEY = 1                     # StringStringEntryProto.key (string)
_F_SSE_VALUE = 2                   # StringStringEntryProto.value (string)

_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
_DRIVE_RE = re.compile(r"[A-Za-z]:[\\/]")


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


# --------------------------------------------------------------------------
# Minimal protobuf wire-format reader (no third-party dependency).
# --------------------------------------------------------------------------

def _read_varint(buf: bytes, pos: int):
    """Return (value, new_pos), or (None, pos) on truncation."""
    shift = 0
    result = 0
    n = len(buf)
    while pos < n:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:          # guard against absurd varints
            return None, pos
    return None, pos


def _iter_fields(buf: bytes):
    """Yield (field_number, wire_type, value) over one protobuf message.

    For wire type 2 the value is the raw bytes slice; for varint it is the int;
    for 32/64-bit it is the raw bytes. Stops silently on any truncation so a
    malformed tail cannot raise.
    """
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        if tag is None:
            return
        field = tag >> 3
        wt = tag & 0x07
        if wt == 0:
            val, pos = _read_varint(buf, pos)
            if val is None:
                return
            yield field, wt, val
        elif wt == 2:
            ln, pos = _read_varint(buf, pos)
            if ln is None or ln < 0 or pos + ln > n:
                return
            yield field, wt, buf[pos:pos + ln]
            pos += ln
        elif wt == 1:
            if pos + 8 > n:
                return
            yield field, wt, buf[pos:pos + 8]
            pos += 8
        elif wt == 5:
            if pos + 4 > n:
                return
            yield field, wt, buf[pos:pos + 4]
            pos += 4
        else:
            # Groups (3/4) are deprecated and never used by ONNX; stop here.
            return


def _as_text(b: bytes) -> str:
    # Preserve every byte (including NUL and high bytes) so control-character
    # and NUL-injection checks see the real content.
    return b.decode("utf-8", "surrogateescape")


# --------------------------------------------------------------------------
# Targeted walk of the ONNX message tree.
# --------------------------------------------------------------------------

def _add(findings: list, seen: set, rule: str, severity: str, title: str,
         detail: str, location: str, cve: str) -> None:
    if len(findings) >= MAX_FINDINGS:
        return
    key = (rule, location)
    if key in seen:
        return
    seen.add(key)
    findings.append(Finding(rule, severity, title, detail, location, cve))


def _lint_location(value: str, name: str, data_location: int,
                   loc: str, findings: list, seen: set) -> None:
    where = "%s (tensor %r)" % (loc, name) if name else loc
    ext = "" if data_location == 1 else " (data_location is not EXTERNAL)"
    quoted = repr(value)

    if any(ord(c) < 0x20 for c in value):
        _add(findings, seen, "OED004", "HIGH",
             "NUL or control byte in external_data location",
             "location %s contains a control/NUL byte, which can truncate or "
             "bypass a path check%s." % (quoted, ext), where, "CWE-22")

    if _URL_RE.match(value):
        _add(findings, seen, "OED003", "HIGH",
             "Remote URL scheme in external_data location",
             "location %s uses a URL scheme; external_data must be a relative "
             "local file, so a loader that fetches it reads a remote/attacker "
             "resource%s." % (quoted, ext), where, "CWE-918")

    is_abs = (value.startswith("/") or value.startswith("\\")
              or bool(_DRIVE_RE.match(value)))
    if is_abs:
        _add(findings, seen, "OED002", "HIGH",
             "Absolute path in external_data location",
             "location %s is absolute; a loader that joins it onto the model "
             "directory still opens the attacker-chosen absolute path%s."
             % (quoted, ext), where, "CWE-22")

    if ".." in re.split(r"[\\/]", value):
        _add(findings, seen, "OED001", "HIGH",
             "Parent-directory traversal in external_data location",
             "location %s contains a '..' segment that escapes the model "
             "directory into an arbitrary file read/write at load time%s."
             % (quoted, ext), where, "CWE-22")

    if "\\" in value:
        _add(findings, seen, "OED005", "MEDIUM",
             "Backslash path separator in external_data location",
             "location %s uses a backslash; ONNX locations must be POSIX "
             "relative paths, and a backslash can act as a separator on "
             "Windows and bypass naive '..' checks%s." % (quoted, ext),
             where, "CWE-22")


def _walk_tensor(buf: bytes, loc: str, findings: list, seen: set) -> None:
    name = ""
    data_location = 0
    entries = []
    for field, wt, val in _iter_fields(buf):
        if field == _F_TENSOR_NAME and wt == 2:
            name = _as_text(val)
        elif field == _F_TENSOR_DATALOC and wt == 0:
            data_location = val
        elif field == _F_TENSOR_EXTDATA and wt == 2:
            key = value = None
            for f2, w2, v2 in _iter_fields(val):
                if w2 == 2 and f2 == _F_SSE_KEY:
                    key = _as_text(v2)
                elif w2 == 2 and f2 == _F_SSE_VALUE:
                    value = _as_text(v2)
            entries.append((key, value))
    for key, value in entries:
        if key == "location" and value is not None and value != "":
            _lint_location(value, name, data_location, loc, findings, seen)


def _walk_sparse(buf: bytes, loc: str, findings: list, seen: set) -> None:
    for field, wt, val in _iter_fields(buf):
        if wt == 2 and field in (_F_SPARSE_VALUES, _F_SPARSE_INDICES):
            _walk_tensor(val, loc, findings, seen)


def _walk_attribute(buf: bytes, loc: str, findings: list, seen: set,
                    depth: int) -> None:
    for field, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if field in (_F_ATTR_T, _F_ATTR_TENSORS):
            _walk_tensor(val, loc, findings, seen)
        elif field in (_F_ATTR_SPARSE, _F_ATTR_SPARSES):
            _walk_sparse(val, loc, findings, seen)
        elif field in (_F_ATTR_G, _F_ATTR_GRAPHS):
            _walk_graph(val, loc, findings, seen, depth + 1)


def _walk_node(buf: bytes, loc: str, findings: list, seen: set,
               depth: int) -> None:
    for field, wt, val in _iter_fields(buf):
        if wt == 2 and field == _F_NODE_ATTR:
            _walk_attribute(val, loc, findings, seen, depth)


def _walk_graph(buf: bytes, loc: str, findings: list, seen: set,
                depth: int) -> None:
    if depth > MAX_DEPTH:
        return
    for field, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if field == _F_GRAPH_INIT:
            _walk_tensor(val, loc, findings, seen)
        elif field == _F_GRAPH_SPARSE:
            _walk_sparse(val, loc, findings, seen)
        elif field == _F_GRAPH_NODE:
            _walk_node(val, loc, findings, seen, depth)


# --------------------------------------------------------------------------
# Public API.
# --------------------------------------------------------------------------

def scan_bytes(data: bytes, loc: str) -> list:
    """Scan raw .onnx (ModelProto) bytes. Pure: no file I/O."""
    findings: list = []
    seen: set = set()
    found_graph = False
    for field, wt, val in _iter_fields(data):
        if wt == 2 and field == _F_MODEL_GRAPH:
            found_graph = True
            _walk_graph(val, loc, findings, seen, 0)
    if not found_graph:
        # Be lenient: a bare GraphProto, or a file we could not frame as a
        # ModelProto, is still walked as a graph so nothing is silently missed.
        _walk_graph(data, loc, findings, seen, 0)
    findings.sort(key=lambda f: (f.rule, f.location))
    return findings


def scan_file(path: str) -> list:
    with open(path, "rb") as fh:
        data = fh.read(MAX_BYTES)
    return scan_bytes(data, path)


def scan_path(path: str) -> list:
    """Scan one .onnx file, or walk a directory for *.onnx files."""
    findings: list = []
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(".onnx"):
                    findings.extend(scan_file(os.path.join(root, fn)))
    else:
        findings.extend(scan_file(path))
    return findings


def _max_severity(findings: Iterable[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="onnx-external-data-scan",
        description="Static, no-execution scanner for path traversal in the "
                    "external_data location of ONNX model files (CWE-22).")
    parser.add_argument("paths", nargs="*",
                        help="ONNX files or directories to scan")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="emit findings as JSON")
    parser.add_argument("--fail-on", default="LOW", choices=list(SEVERITY_ORDER),
                        help="exit 1 if any finding meets/exceeds this severity "
                             "(default: LOW)")
    parser.add_argument("--version", action="version",
                        version="onnx-external-data-scan " + __version__)
    args = parser.parse_args(argv)

    if not args.paths:
        parser.print_help()
        return 2

    findings: list = []
    for p in args.paths:
        findings.extend(scan_path(p))

    if args.as_json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        if not findings:
            print("No external_data location issues found.")
        for f in findings:
            print("[%s] %s  %s\n    %s\n    at %s%s" % (
                f.severity, f.rule, f.title, f.detail, f.location,
                ("  (%s)" % f.cve) if f.cve else ""))

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if _max_severity(findings) >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
