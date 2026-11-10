#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Small pure helpers shared by fetch_hub_archives.py and census_scan.py
(job pt2-census-v1). Tested by test_census_helpers.py.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import re

# Extensions counted per model in the census table.
COUNTED = (".pt2", ".torchscript", ".ptl", ".pte", ".pt", ".pth", ".bin",
           ".ckpt", ".safetensors", ".onnx", ".gguf", ".tflite")
# The torch archive families this census samples and scans.
TARGETS = (".pt2", ".torchscript", ".ptl")
NATIVE = (".so", ".dll", ".dylib", ".cubin", ".fatbin", ".ptx")
SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_NEXT_RX = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')


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


def classify_head(head):
    """'zip' for PK\\x03\\x04, 'pickle' for PROTO 2-5, else 'other'."""
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return "pickle"
    return "other"


def member_of(location):
    """Archive member named in a finding location '<src>!<member> @ byte N'
    (None if the location names no member)."""
    if not location or "!" not in location:
        return None
    member = location.split("!", 1)[1]
    if " @ byte" in member:
        member = member.rsplit(" @ byte", 1)[0]
    return member


def member_role(name):
    """Coarse role of a member of a torch archive, from its name only."""
    low = name.lower()
    parts = low.split("/")
    if ext_of(low) in NATIVE:
        return "native-library"
    if "/data/sample_inputs/" in "/" + low:
        return "sample_inputs"
    if "/data/weights/" in "/" + low:
        return "weights"
    if "/data/constants/" in "/" + low:
        return "constants"
    if parts[-1] in ("data.pkl", "constants.pkl", "bytecode.pkl"):
        return "pickle:" + parts[-1]
    if "/code/" in "/" + low:
        return "torchscript-code"
    if parts[-1].startswith("serialized_"):
        return "legacy-export:" + parts[-1]
    if parts[-1] in ("archive_format", "version", ".data/version",
                     "byteorder"):
        return "marker:" + parts[-1]
    if len(parts) >= 2 and parts[-2] == "data" and parts[-1].isdigit():
        return "tensor-storage"
    if "/models/" in "/" + low and low.endswith(".json"):
        return "export-json"
    return "other"


def max_severity(rows):
    best = -1
    for r in rows:
        best = max(best, SEVERITY.get(str(r.get("severity", "")).upper(), -1))
    return best


def share(n, d):
    return round(n / d, 6) if d else None
