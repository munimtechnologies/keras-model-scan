# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Ground truth for jobs hfcfg-census-v1 and ctr-cal-v1, written
independently of the scanners under test: an iterative (stack-based) walk over
a parsed JSON document that counts keys at any depth and collects model_type
values. Pure functions, standard library only. (Unchanged copy from
hfcfg-census-v1.)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json

TRC = "trust_remote_code"
HCI_KEYS = ("_attn_implementation_internal", "_experts_implementation_internal")
CODE_KEYS = ("auto_map", "custom_pipeline", "auto_pipeline")


def parse(data):
    """(doc, None) for UTF-8 JSON bytes, else (None, reason)."""
    try:
        return json.loads(data.decode("utf-8")), None
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return None, type(exc).__name__


def count_keys(doc, keys):
    """How many times each key in ``keys`` appears as a dict key anywhere."""
    want = set(keys)
    counts = {k: 0 for k in keys}
    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if k in want:
                    counts[k] += 1
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return counts


def values_of(doc, key):
    """Every value stored under ``key`` anywhere in the document."""
    out = []
    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if k == key:
                    out.append(v)
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return out


def model_types(doc):
    return sorted({str(v).lower() for v in values_of(doc, "model_type")
                   if isinstance(v, str)})


def severity_of(finding):
    """Upper-case severity of a finding object or dict (any scanner)."""
    for name in ("severity", "level"):
        val = getattr(finding, name, None)
        if val is None and isinstance(finding, dict):
            val = finding.get(name)
        if val:
            return str(val).upper()
    return ""


def rule_of(finding):
    for name in ("rule", "code"):
        val = getattr(finding, name, None)
        if val is None and isinstance(finding, dict):
            val = finding.get(name)
        if val:
            return str(val)
    return ""
