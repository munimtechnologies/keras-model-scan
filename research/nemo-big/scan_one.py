#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one scanner module (loaded from a file path) on one file, in its own
process, and print JSON: rules, count, seconds, peak RSS. Exits 0.

Usage: scan_one.py MODULE_PATH FILE

The module is put in sys.modules before it runs (dataclasses and some
imports look it up there; job oed-functions-v1 lost its scan rows to this).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import importlib.util
import json
import resource
import sys
import time

NAME = "scanner_under_test"


def _rule(f):
    return f["rule"] if isinstance(f, dict) else getattr(f, "rule", "?")


def main():
    mod_path, target = sys.argv[1], sys.argv[2]
    out = {"module": mod_path, "file": target}
    try:
        spec = importlib.util.spec_from_file_location(NAME, mod_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[NAME] = mod
        spec.loader.exec_module(mod)
        out["version"] = getattr(mod, "__version__", None)
        t0 = time.time()
        findings = mod.scan_file(target)
        out["seconds"] = round(time.time() - t0, 3)
        out["n"] = len(findings)
        out["rules"] = sorted({_rule(f) for f in findings})
        out["evidence"] = [str(f.get("evidence", ""))[:200]
                           for f in findings if isinstance(f, dict)][:6]
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    out["maxrss_mb"] = round(
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
