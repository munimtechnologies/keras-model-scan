#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one version of pickle_model_scan over a list of files, in its own
process. Static only: scan_file reads bytes and disassembles opcodes; it
never unpickles or loads anything.

Usage: probe.py SRC LIST_JSON OUT_JSON
  SRC        the source tree to import pickle_model_scan from
  LIST_JSON  a JSON list of file paths
  OUT_JSON   {"version": ..., "files": {path: {"findings": [...]} or
             {"error": ...}}}

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import sys


def main():
    src, list_json, out_json = sys.argv[1:4]
    sys.path.insert(0, os.path.abspath(src))
    import pickle_model_scan as pms
    with open(list_json, encoding="utf-8") as fh:
        paths = json.load(fh)
    res = {"version": pms.__version__, "files": {}}
    for path in paths:
        try:
            found = pms.scan_file(path) or []
            res["files"][path] = {"findings": [
                {"rule": f.rule, "severity": f.severity,
                 "location": f.location} for f in found]}
        except Exception as exc:
            res["files"][path] = {"error": "%s: %s" % (type(exc).__name__,
                                                       str(exc)[:200])}
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    print(json.dumps({"version": res["version"], "files": len(paths)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
