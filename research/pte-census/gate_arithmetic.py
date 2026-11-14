#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
"""Gate arithmetic on the published pte-census-v1 per-file findings.

Made with AI agents working in the name of MV2 of Munim, Inc. Licence: Apache-2.0.

Reads pte_census_files.json (the recorded findings of executorch_pte_scan 0.1.0
on 450 honest, published ExecuTorch .pte files) and answers by counting only;
nothing is scanned or downloaded:

* which backend delegates each file names in its PTE003 findings, and how many
  files name more than one;
* how many files fail model-file-scan's default gate today (any finding rated
  medium or higher);
* how many would still fail if the findings that two staged, pre-registered
  integrity fixes target were gone (PTE004 whose only evidence is
  "scalar_type 9", and PTE005 on a single-segment program);
* for an ordered list of backends whose PTE003 is imagined as "low", how many
  files would still fail, adding one backend at a time.

These are what-ifs on recorded findings, NOT measurements of a patched scanner
and NOT a claim about which backends load native code. Which backends (if any)
get a lower PTE003 rating is decided only by a pre-registered check of each
backend's ExecuTorch runtime source; the integrity fixes are graded on real
files by their own pre-registered jobs. A finding is not a claim that a model
is unsafe.

Usage: python gate_arithmetic.py [pte_census_files.json] [Backend ...]
With no backends, they are added in descending order of file count (a neutral
order, not a ranking of safety).
"""

import json
import os
import re
import sys
from collections import Counter

GATE = frozenset({"medium", "high", "critical"})
_BACKEND = re.compile(r"^backend delegate (\S+?):")
_SCALAR9 = re.compile(r"^plan \d+ value \d+: scalar_type 9 is not an ExecuTorch dtype$")


def backend_of(finding):
    """Backend name quoted in a PTE003 message, or '?' if it cannot be read."""
    match = _BACKEND.match(str(finding.get("message", "")))
    return match.group(1) if match else "?"


def backends(record):
    """Set of backend names in a file's PTE003 findings."""
    return frozenset(backend_of(f) for f in (record.get("findings") or [])
                     if f.get("rule") == "PTE003")


def is_scalar9_only(evidence):
    """True if every part of a PTE004 evidence string is a scalar_type 9 note."""
    parts = [p.strip() for p in str(evidence).split(";") if p.strip()]
    return bool(parts) and all(_SCALAR9.match(p) for p in parts)


def targeted(finding):
    """True for findings the two staged integrity fixes are meant to clear."""
    rule = finding.get("rule")
    if rule == "PTE004":
        return is_scalar9_only(finding.get("evidence", ""))
    if rule == "PTE005":
        return str(finding.get("evidence", "")).strip() == "1 segments"
    return False


def fails(findings, low=frozenset()):
    """Default gate: any finding rated medium or higher, with PTE003 for a
    backend in `low` counted as low."""
    for f in findings:
        if f.get("rule") == "PTE003" and backend_of(f) in low:
            continue
        if str(f.get("severity", "")).lower() in GATE:
            return True
    return False


def summarize(records, order=None):
    per_file = [backends(r) for r in records]
    by_backend = Counter(b for s in per_file for b in s)
    if order is None:
        order = [b for b, _ in sorted(by_backend.items(), key=lambda kv: (-kv[1], kv[0]))]
    findings = [list(r.get("findings") or []) for r in records]
    after = [[f for f in fs if not targeted(f)] for fs in findings]
    n = len(records)

    def pct(k):
        return round(100.0 * k / n, 1) if n else 0.0

    steps = []
    low = set()
    for name in [None] + list(order):
        if name is not None:
            low.add(name)
        k = sum(fails(fs, frozenset(low)) for fs in after)
        steps.append({"low": sorted(low), "added": name, "gate_fail": k, "pct": pct(k)})
    fail_now = sum(fails(fs) for fs in findings)
    fail_after = sum(fails(fs) for fs in after)
    return {
        "files": n,
        "models": len({r.get("model") for r in records}),
        "files_with_pte003": sum(1 for s in per_file if s),
        "backends_per_file": {str(k): v for k, v in sorted(Counter(len(s) for s in per_file).items())},
        "files_by_backend": dict(sorted(by_backend.items(), key=lambda kv: (-kv[1], kv[0]))),
        "multi_backend_files": [
            {"model": r.get("model"), "rfilename": r.get("rfilename"), "backends": sorted(s)}
            for r, s in zip(records, per_file) if len(s) > 1],
        "multi_backend_combos": dict(Counter("+".join(sorted(s)) for s in per_file if len(s) > 1)),
        "targeted_findings": sum(1 for fs in findings for f in fs if targeted(f)),
        "untargeted_non_pte003": sum(1 for fs in after for f in fs if f.get("rule") != "PTE003"),
        "gate_fail_now": fail_now,
        "gate_fail_now_pct": pct(fail_now),
        "gate_fail_without_targeted": fail_after,
        "gate_fail_without_targeted_pct": pct(fail_after),
        "what_if_low": steps,
    }


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    path = argv[1] if len(argv) > 1 else os.path.join(here, "pte_census_files.json")
    order = argv[2:] or None
    with open(path, encoding="utf-8") as fh:
        records = json.load(fh)
    json.dump(summarize(records, order), sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
