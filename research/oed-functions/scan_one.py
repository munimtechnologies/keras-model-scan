#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one scanner module (loaded from a file path) on one file, in its own
process, and print JSON: rules, keys, count, seconds, peak RSS. Exits 0.

Usage: scan_one.py MODULE_PATH FILE

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import importlib.util
import json
import resource
import sys
import time


def main():
    mod_path, target = sys.argv[1], sys.argv[2]
    out = {"module": mod_path, "file": target}
    try:
        spec = importlib.util.spec_from_file_location("scanner_under_test",
                                                      mod_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out["version"] = getattr(mod, "__version__", None)
        t0 = time.time()
        findings = mod.scan_file(target)
        out["seconds"] = round(time.time() - t0, 3)
        out["n"] = len(findings)
        out["rules"] = sorted({f.rule for f in findings})
        out["keys"] = sorted({getattr(f, "key", "") for f in findings
                              if getattr(f, "key", "")})
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    out["maxrss_mb"] = round(
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
