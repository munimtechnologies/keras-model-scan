#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Last run step for job pte-dtype-v2 (no network): grade the rows
pre-registered in research/PREREG_PTE_DTYPE_FIX_V2.md and write
OUT/dtype_v2_summary.json.

Rows (each held / failed / untestable):
- P1  patch_pte edits each match once, old table equals the released one,
      patched module imports (same definition as pte-dtype-v1).
- T1  patched executorch_pte tests pass, at least 41 ran (same as v1).
- U1  the corrected grader's own unit tests (test_vendor_check.py) pass.
- F1  all four ExecuTorch files were fetched at commit 3e85cae1 and each
      SHA-256 equals the one job pte-dtype-v1 recorded.
- V1  as v1's V1, with backslash line continuations joined before parsing.
- V2  unchanged from v1.
- V3  parse completeness: entry starts = parsed entries = comments, and the
      comments are 0..N-1.
release_rule_met = every row held. Rows G1, E1 and D1-D4 are NOT re-run:
they held in pte-dtype-v1 (published) on the same patched code.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import importlib.util
import io
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
T1_MIN_TESTS = 41
ROWS = ("P1", "T1", "U1", "F1", "V1", "V2", "V3")


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"_error": "%s: %s" % (type(exc).__name__, exc)}


def main():
    out = os.path.abspath(sys.argv[sys.argv.index("--out") + 1]
                          if "--out" in sys.argv else "/out")
    res = {}

    def put(key, ok, why, testable=True):
        res[key] = {"result": ("held" if ok else "failed") if testable
                    else "untestable", "why": why}

    patch = read_json(os.path.join(out, "patch_report.json"))
    new_error = None
    try:
        spec = importlib.util.spec_from_file_location(
            "pte_new_grade", os.path.join(HERE, "patched",
                                          "executorch_pte_scan.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        new_version = mod.__version__
    except Exception as exc:
        mod, new_version = None, None
        new_error = "%s: %s" % (type(exc).__name__, exc)
    put("P1", bool(patch.get("ok")) and mod is not None,
        "patch ok=%s; edits %s; import %s" % (
            patch.get("ok"), [e.get("matches") for e in patch.get("edits", [])],
            new_error or "ok"))

    t_new = read_json(os.path.join(out, "tests_patched.json"))
    t_old = read_json(os.path.join(out, "tests_base.json"))
    put("T1", bool(t_new.get("ok")) and (t_new.get("ran") or 0) >= T1_MIN_TESTS,
        "patched: ran %s, failures %s, errors %s; base: ran %s ok %s" % (
            t_new.get("ran"), t_new.get("failures"), t_new.get("errors"),
            t_old.get("ran"), t_old.get("ok")))

    try:
        sys.path.insert(0, HERE)
        suite = unittest.defaultTestLoader.loadTestsFromName(
            "test_vendor_check")
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        u_ok = result.wasSuccessful() and result.testsRun > 0
        put("U1", u_ok, "ran %d, failures %s, errors %s" % (
            result.testsRun, [str(t) for t, _ in result.failures],
            [str(t) for t, _ in result.errors]))
        with open(os.path.join(out, "tests_grader.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(stream.getvalue())
    except Exception as exc:
        put("U1", False, "%s: %s" % (type(exc).__name__, exc))

    vc = read_json(os.path.join(out, "vendor_check.json"))
    fetch = vc.get("fetch") or {}
    files = fetch.get("files") or {}
    same = {n: bool(f.get("same_as_v1")) for n, f in files.items()}
    put("F1", len(same) == 4 and all(same.values())
        and fetch.get("commit") == "3e85cae1e744454713413db4deb31090a505adf4",
        "commit %s; same SHA-256 as v1: %s" % (fetch.get("commit"), same),
        testable=bool(files))
    for key in ("V1", "V2", "V3"):
        row = vc.get(key) or {}
        res[key] = {"result": row.get("result", "untestable"),
                    "why": row.get("why", vc.get("_error", "no vendor_check"))}

    release = all(res[k]["result"] == "held" for k in ROWS)
    summary = {
        "rows": res,
        "release_rule_met": release,
        "held": sorted(k for k in ROWS if res[k]["result"] == "held"),
        "failed": sorted(k for k in ROWS if res[k]["result"] == "failed"),
        "untestable": sorted(k for k in ROWS
                             if res[k]["result"] == "untestable"),
        "recorded": {
            "scanner_new": new_version,
            "vendor_commit": fetch.get("commit"),
            "counts": vc.get("counts"),
            "entries": [(e.get("index"), e.get("name"), e.get("size"))
                        for e in vc.get("entries", [])],
            "unpatched_missing": vc.get("unpatched_missing"),
            "prereg_check": read_json(os.path.join(HERE,
                                                   "prereg_check.json")),
            "v1_rows_carried": ["G1", "E1", "D1", "D2", "D3", "D4"],
        },
    }
    with open(os.path.join(out, "dtype_v2_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"rows": {k: res[k]["result"] for k in ROWS},
                      "release_rule_met": release}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
