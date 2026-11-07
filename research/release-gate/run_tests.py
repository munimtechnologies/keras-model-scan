#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run keras-model-scan's whole unit-test suite from inside TREE.

Writes OUT/tests_summary.json (counts and the names of failing tests). Always
exits 0 so the graded check that follows still runs; the result is row G2.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import sys
import unittest


def names(pairs):
    return [str(t) for t, _ in pairs][:60]


def main():
    tree, out = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(out, exist_ok=True)
    os.chdir(tree)
    sys.path.insert(0, tree)
    try:
        suite = unittest.defaultTestLoader.discover(tree, pattern="test_*.py")
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        summary = {"ran": result.testsRun, "failures": names(result.failures),
                   "errors": names(result.errors),
                   "skipped": len(result.skipped),
                   "ok": result.wasSuccessful()}
    except Exception as exc:
        summary = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
    with open(os.path.join(out, "tests_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
