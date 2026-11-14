#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run the executorch_pte_scan unit tests found in DIR.

Usage: run_tests.py DIR OUT NAME. Discovers test_executorch_pte*.py in DIR
(only those: the rest of the tree is not part of this check) and writes
OUT/NAME with counts and the names of failing tests. Always exits 0 so the
graded check that follows still runs.

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
    name = sys.argv[3]
    os.makedirs(out, exist_ok=True)
    here = os.getcwd()
    os.chdir(tree)
    sys.path.insert(0, tree)
    try:
        suite = unittest.defaultTestLoader.discover(
            tree, pattern="test_executorch_pte*.py")
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        summary = {"ran": result.testsRun, "failures": names(result.failures),
                   "errors": names(result.errors),
                   "skipped": len(result.skipped),
                   "ok": result.wasSuccessful(), "error": None}
    except Exception as exc:
        summary = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
    os.chdir(here)
    with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
