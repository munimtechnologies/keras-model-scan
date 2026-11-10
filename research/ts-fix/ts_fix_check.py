#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step: grade the pre-registered rows of research/PREREG_TS_FIX.md.

Inputs (all written earlier in this job): patch_report.json,
tests_summary.json and tests_base.json in OUT; base_dump.json and
patched_dump.json (scan_dump.py on ./base and ./tree); fixtures_report.json
(make_fixtures.py, torch's own writers and loaders).

Usage: ts_fix_check.py --out OUT
Writes OUT/ts_fix_summary.json and prints held/failed/not_run.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import json
import os
import shutil
import sys

ALL = ["model.pt", "model.torchscript", "model.ptl", "model.pt2",
       "weights.pth"]
TS = ("F1", "F2", "F3")
SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def top(rows):
    vals = [SEV.get(r.get("severity"), 9) for r in rows if "error" not in r]
    return max(vals) if vals else -1


def key(rows):
    return sorted((r.get("rule"), r.get("severity"), r.get("location"))
                  for r in rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    out = ap.parse_args().out
    os.makedirs(out, exist_ok=True)
    patch = load(os.path.join(out, "patch_report.json")) or {}
    tests = load(os.path.join(out, "tests_summary.json")) or {}
    tests0 = load(os.path.join(out, "tests_base.json")) or {}
    base = load("base_dump.json") or {}
    new = load("patched_dump.json") or {}
    fx = load("fixtures_report.json") or {}
    have = {k: k in (fx.get("fixtures") or {})
            for k in ("F1", "F2", "F3", "F4", "F5")}
    rows = {}

    def row(k, ok, why=""):
        rows[k] = {"result": ("not_run" if ok is None else
                              "held" if ok else "failed"), "why": why}

    bv, nv = base.get("versions") or {}, new.get("versions") or {}
    row("P1", bool(patch.get("ok")) and nv.get("model_file_scan") == "0.14.0"
        and nv.get("pickle_model_scan") == "0.7.0"
        and bv.get("model_file_scan") == "0.13.2"
        and bv.get("pickle_model_scan") == "0.6.0",
        "patch ok=%s error=%s base=%s patched=%s"
        % (patch.get("ok"), patch.get("error"), bv, nv))

    row("S1", (bool(tests.get("ok")) and tests.get("ran", 0)
               > tests0.get("ran", 0)) if patch.get("ok") else None,
        "patched ran=%s ok=%s failures=%s errors=%s; base ran=%s ok=%s"
        % (tests.get("ran"), tests.get("ok"), tests.get("failures"),
           tests.get("errors"), tests0.get("ran"), tests0.get("ok")))

    have_all = all(have.values())
    wk, bk = new.get("walk_kept") or [], base.get("walk_kept") or []
    row("W3", (sorted(ALL) == sorted(wk)
               and sorted(bk) == ["model.pt", "weights.pth"])
        if have_all else None, "patched=%s base=%s" % (wk, bk))

    bd, nd = base.get("direct") or {}, new.get("direct") or {}

    def torch3(rows_):
        return [r for r in rows_ if r.get("rule") == "PKL003"
                and "__torch__." in r.get("detail", "")]

    t1 = {}
    for k in TS:
        n40 = [r for r in nd.get(k, []) if r.get("rule") == "PKL040"]
        t1[k] = {"pkl040": len(n40),
                 "pkl040_medium": all(r.get("severity") == "MEDIUM"
                                      for r in n40),
                 "torch_pkl003_patched": len(torch3(nd.get(k, []))),
                 "torch_pkl003_base": len(torch3(bd.get(k, [])))}
    row("T1", all(v["pkl040"] == 1 and v["pkl040_medium"]
                  and v["torch_pkl003_patched"] == 0
                  and v["torch_pkl003_base"] >= 1 for v in t1.values())
        if all(have[k] for k in TS) else None, json.dumps(t1))

    hi = {k: [r.get("rule") or r.get("error") for r in v
              if "error" in r or SEV.get(r.get("severity"), 9) >= 3]
          for k, v in nd.items()}
    row("T2", not any(hi.values()) if nd else None, "high+=%s" % hi)

    t3 = {k: key(bd.get(k, [])) == key(nd.get(k, [])) for k in ("F4", "F5")
          if have[k]}
    row("T3", all(t3.values()) if have["F5"] else None, json.dumps(t3))

    t4 = {k: [top(bd.get(k, [])), top(nd.get(k, []))] for k in nd}
    row("T4", all(a == b for a, b in t4.values()) if have_all else None,
        json.dumps(t4))

    bc, nc = base.get("cli") or {}, new.get("cli") or {}

    def ex(d, k):
        return (d.get(k) or {}).get("exit")

    c2 = {"F1": ex(nc, "F1"), "dir": ex(nc, "dir"), "F5": ex(nc, "F5"),
          "F5_base": ex(bc, "F5")}
    row("C2", (c2["F1"] not in (0, None) and c2["dir"] not in (0, None)
               and c2["F5"] == 0 and c2["F5_base"] == 0)
        if None not in c2.values() else None, json.dumps(c2))

    ld = fx.get("loaders") or {}
    lok = [(ld.get(n) or {}).get("ok")
           for n in ("jit_load_F1", "jit_load_F2", "lite_load_F3")]
    row("L0", all(lok) if None not in lok else None, "ok=%s" % lok)

    held = sorted(k for k, v in rows.items() if v["result"] == "held")
    failed = sorted(k for k, v in rows.items() if v["result"] == "failed")
    not_run = sorted(k for k, v in rows.items() if v["result"] == "not_run")
    summary = {"versions": {"base": bv, "patched": nv,
                            "torch": fx.get("torch")},
               "have": have, "rows": rows,
               "recorded": {"F4_patched": nd.get("F4"),
                            "F4_base": bd.get("F4"),
                            "members": fx.get("members"),
                            "loaders": ld},
               "held": held, "failed": failed, "not_run": not_run}
    with open(os.path.join(out, "ts_fix_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    for name in ("base_dump.json", "patched_dump.json", "fixtures_report.json",
                 "setup_report.json", "fetch_report.json"):
        if os.path.isfile(name):
            shutil.copyfile(name, os.path.join(out, name))
    print(json.dumps({"held": held, "failed": failed, "not_run": not_run},
                     indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
