#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Small pure helpers shared by fetch_hub_pte.py and the census scripts
(jobs pte-census-v1 and pte-dtype-v1; unchanged). Tested by test_pte_lib.py.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import os
import re
import struct

COUNTED = (".pte", ".ptd", ".pt2", ".bin", ".safetensors", ".gguf", ".onnx",
           ".tflite", ".json")
FILE_IDENTIFIER = b"ET12"
HEADER_MAGIC = b"eh00"
HEADER_MIN_LENGTH = 24
GATE_SEVERITIES = ("medium", "high", "critical")
INTEGRITY_RULES = ("PTE001", "PTE002", "PTE004")
_NEXT_RX = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')
_DELEGATE_RX = re.compile(r"^backend delegate (.+?): that backend")


def ext_of(name):
    """Lower-case last suffix of a repo file name ('' if none)."""
    base = name.rsplit("/", 1)[-1]
    if "." not in base.strip("."):
        return ""
    return "." + base.rsplit(".", 1)[-1].lower()


def next_link(header):
    """URL of rel="next" in an HTTP Link header, or None."""
    if not header:
        return None
    m = _NEXT_RX.search(header)
    return m.group(1) if m else None


def parse_head(head):
    """Read the first bytes of a .pte file without trusting them.

    Returns a dict: identifier (bytes 4:8 as text), has_header (an eh00
    extended header at offset 8), and, when present and well-formed,
    header_length, program_size, segment_base_offset, segment_data_size.
    'error' is set when the header is present but cannot be read."""
    out = {"identifier": head[4:8].decode("ascii", "backslashreplace")
           if len(head) >= 8 else None,
           "has_header": len(head) >= 12 and head[8:12] == HEADER_MAGIC}
    if not out["has_header"]:
        return out
    if len(head) < 32:
        out["error"] = "head too short for the extended header"
        return out
    length = struct.unpack_from("<I", head, 12)[0]
    out["header_length"] = length
    if length < HEADER_MIN_LENGTH:
        out["error"] = "extended header length %d is below %d" % (
            length, HEADER_MIN_LENGTH)
        return out
    out["program_size"] = struct.unpack_from("<Q", head, 16)[0]
    out["segment_base_offset"] = struct.unpack_from("<Q", head, 24)[0]
    if length >= 32:
        if len(head) < 40:
            out["error"] = "head too short for segment_data_size"
            return out
        out["segment_data_size"] = struct.unpack_from("<Q", head, 32)[0]
    else:
        out["segment_data_size"] = 0
    return out


def fetch_plan(info, total, cap):
    """How many leading bytes the census needs to scan this file exactly.

    The scanner reads only the eh00 header (first 40 bytes) and the
    FlatBuffer program (the first program_size bytes); for segments it
    compares offsets and sizes with the file length and never reads their
    bytes. So the first program_size bytes plus the true length are enough.
    Without a header the whole file is the program.
    Returns (n_bytes, reason): n_bytes None means skip."""
    if not isinstance(total, int) or total <= 0:
        return None, "size unknown"
    if info.get("error"):
        return (total, "whole (header unreadable)") if total <= cap else (
            None, "header unreadable and file over cap")
    if info.get("has_header") and isinstance(info.get("program_size"), int):
        n = min(info["program_size"], total)
        if n < 40:
            n = min(40, total)
        if n > cap:
            return None, "program over cap"
        return n, "program"
    if total > cap:
        return None, "no header and file over cap"
    return total, "whole (no header)"


def make_sparse(path, head, size):
    """Write HEAD at offset 0 and extend the file to SIZE bytes without
    writing the rest (a sparse file: the tail reads as zeros and uses no
    disk on file systems that support holes)."""
    if len(head) > size:
        raise ValueError("head longer than the file")
    with open(path, "wb") as fh:
        fh.write(head)
        fh.truncate(size)
    return os.path.getsize(path)


def normalise(findings):
    """Comparable form of a finding list: sorted (rule, severity, message,
    evidence) tuples."""
    return sorted((str(f.get("rule")), str(f.get("severity")),
                   str(f.get("message")), str(f.get("evidence")))
                  for f in findings)


def delegates(findings):
    """Backend names named by PTE003 findings."""
    names = []
    for f in findings:
        if f.get("rule") != "PTE003":
            continue
        m = _DELEGATE_RX.match(str(f.get("message", "")))
        if m:
            names.append(m.group(1))
    return names


def gate_fails(findings):
    """True when model-file-scan's default gate (--fail-on medium) would
    fail on these findings (any medium, high or critical)."""
    return any(str(f.get("severity", "")).lower() in GATE_SEVERITIES
               for f in findings)


def share(n, d):
    return round(n / d, 6) if d else None
