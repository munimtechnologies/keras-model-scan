#!/usr/bin/env python3
# Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""Structural linter for a model-file scanner coverage matrix (scanner_coverage.json).

This validates the SHAPE of a coverage-matrix document only. It asserts NO security
facts: it does not know which scanner really detects which vector, and it never runs
a scanner. Its job is to keep the matrix internally consistent (known ids, valid
statuses, no duplicate or dangling cells, a citation behind every positive claim)
so a reviewer can trust the structure while judging the content on its sources.

Usage:
    python coverage_matrix_lint.py scanner_coverage.json [--strict]

Exit code is non-zero when any ERROR is found (also on WARN when --strict).
"""

import argparse
import json
import sys

ALLOWED_STATUS = {"detects", "partial", "no", "out-of-scope", "unknown"}
# A positive coverage claim must be backed by at least one citation.
NEEDS_SOURCE = {"detects", "partial"}
REQUIRED_TOP = ("schema", "generated", "methodology", "scanners", "vectors", "cells")


def load_matrix(path):
    """Read and JSON-parse a matrix document. Raises on I/O or JSON errors."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def lint_matrix(data):
    """Return a list of (level, message) findings. level in ERROR/WARN/INFO."""
    out = []

    def err(msg):
        out.append(("ERROR", msg))

    def warn(msg):
        out.append(("WARN", msg))

    if not isinstance(data, dict):
        err("top-level value is not an object")
        return out

    for key in REQUIRED_TOP:
        if key not in data:
            err("missing top-level key: %s" % key)

    scanners = data.get("scanners")
    if not isinstance(scanners, list) or not scanners:
        err("'scanners' must be a non-empty list")
        scanners = scanners if isinstance(scanners, list) else []

    vectors = data.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        err("'vectors' must be a non-empty list")
        vectors = vectors if isinstance(vectors, list) else []

    cells = data.get("cells")
    if not isinstance(cells, list):
        err("'cells' must be a list")
        cells = []

    scanner_ids = set()
    for i, s in enumerate(scanners):
        if not isinstance(s, dict):
            err("scanner[%d] is not an object" % i)
            continue
        sid = s.get("id")
        if not isinstance(sid, str) or not sid.strip():
            err("scanner[%d] missing a non-empty 'id'" % i)
            continue
        if sid in scanner_ids:
            err("duplicate scanner id: %s" % sid)
        scanner_ids.add(sid)
        if not (isinstance(s.get("name"), str) and s["name"].strip()):
            warn("scanner %s missing a 'name'" % sid)

    vector_ids = set()
    for i, v in enumerate(vectors):
        if not isinstance(v, dict):
            err("vector[%d] is not an object" % i)
            continue
        vid = v.get("id")
        if not isinstance(vid, str) or not vid.strip():
            err("vector[%d] missing a non-empty 'id'" % i)
            continue
        if vid in vector_ids:
            err("duplicate vector id: %s" % vid)
        vector_ids.add(vid)
        if not (isinstance(v.get("title"), str) and v["title"].strip()):
            warn("vector %s missing a 'title'" % vid)

    seen_pairs = set()
    for i, c in enumerate(cells):
        if not isinstance(c, dict):
            err("cell[%d] is not an object" % i)
            continue
        v = c.get("vector")
        sc = c.get("scanner")
        st = c.get("status")
        if v not in vector_ids:
            err("cell[%d] references unknown vector: %r" % (i, v))
        if sc not in scanner_ids:
            err("cell[%d] references unknown scanner: %r" % (i, sc))
        if st not in ALLOWED_STATUS:
            err("cell[%d] has invalid status: %r" % (i, st))
        pair = (v, sc)
        if pair in seen_pairs:
            err("duplicate cell for vector/scanner: %s/%s" % (v, sc))
        seen_pairs.add(pair)

        srcs = c.get("sources", [])
        if not isinstance(srcs, list):
            err("cell[%d] 'sources' is not a list" % i)
            srcs = []
        nonempty = [x for x in srcs if isinstance(x, str) and x.strip()]
        if st in NEEDS_SOURCE and not nonempty:
            err("cell[%d] (%s/%s) status '%s' requires at least one source"
                % (i, v, sc, st))
        if "note" in c and not isinstance(c["note"], str):
            warn("cell[%d] (%s/%s) 'note' is not a string" % (i, v, sc))

    # Completeness: a full matrix covers every (vector, scanner) pair exactly once.
    for vid in sorted(vector_ids):
        for sid in sorted(scanner_ids):
            if (vid, sid) not in seen_pairs:
                warn("no cell for vector/scanner: %s/%s" % (vid, sid))

    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="Lint a scanner coverage matrix.")
    parser.add_argument("path", help="path to scanner_coverage.json")
    parser.add_argument("--strict", action="store_true",
                        help="treat WARN as failure too")
    args = parser.parse_args(argv)

    try:
        data = load_matrix(args.path)
    except (OSError, ValueError) as exc:
        print("ERROR could not read %s: %s" % (args.path, exc))
        return 2

    findings = lint_matrix(data)
    for level, msg in findings:
        print("%s %s" % (level, msg))

    errors = [f for f in findings if f[0] == "ERROR"]
    warns = [f for f in findings if f[0] == "WARN"]
    if errors:
        print("FAIL: %d error(s), %d warning(s)" % (len(errors), len(warns)))
        return 1
    if args.strict and warns:
        print("FAIL (strict): %d warning(s)" % len(warns))
        return 1
    print("OK: matrix is structurally valid (%d warning(s))" % len(warns))
    return 0


if __name__ == "__main__":
    sys.exit(main())
