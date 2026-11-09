#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one version of nemo_container_scan on .nemo files, in its own process.

Usage: probe_nemo.py VERSION_DIR OUT_JSON FILE...
For each file: scan_file() findings, and for each regular tar member the
pickles the scanner reports (_member_pickles: where, dangerous imports, all
imports as "module name"). Only reads bytes; nothing is unpickled or
extracted. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import sys
import tarfile


def main():
    vdir, out, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    sys.path.insert(0, vdir)
    import nemo_container_scan as scan
    res = {"version": scan.__version__, "files": {}}
    for path in files:
        r = {"members": {}}
        try:
            r["findings"] = scan.scan_file(path)
            with tarfile.open(path, mode="r:*") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    unchecked = []
                    hits = scan._member_pickles(tar, member, unchecked)
                    r["members"][member.name] = {
                        "size": member.size,
                        "pickles": [{"where": w,
                                     "dangerous": ["%s %s" % p for p in d],
                                     "imports": ["%s %s" % p for p in a]}
                                    for w, d, a in hits],
                        "unchecked": [list(u) for u in unchecked]}
        except Exception as exc:
            r["error"] = "%s: %s" % (type(exc).__name__, exc)
        res["files"][path] = r
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
