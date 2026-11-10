#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Grade the rows of research/PREREG_PT2_NEST.md from the job's outputs.

Reads OUT/patch_report.json, OUT/tests_summary.json, OUT/tests_base.json,
OUT/base_dump.json, OUT/patched_dump.json and ./fixtures_report.json; writes
OUT/nest_summary.json. A row whose inputs are missing is "not run".

Release rows: P1 S1 M1 M2 N1 N2 N3 T3 T4 C2 L0.
Diagnostic row (does not decide the release): D1.

Usage: nest_check.py --out OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import shutil
import sys

SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
NESTED = "model/data/sample_inputs/model.pt"
RELEASE = ("P1", "S1", "M1", "M2", "N1", "N2", "N3", "T3", "T4", "C2", "L0")


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def top(rows):
    if rows is None:
        return None
    return max([SEV.get(r.get("severity"), -1) for r in rows] or [-1])


def keyset(rows):
    return sorted((r.get("rule"), r.get("severity"), r.get("location"))
                  for r in rows or [])


def has_error(rows):
    return any("error" in r for r in rows or [])


def main():
    args = sys.argv[1:]
    out = args[args.index("--out") + 1] if "--out" in args else "/out"
    patch = load(os.path.join(out, "patch_report.json"))
    tests = load(os.path.join(out, "tests_summary.json"))
    tbase = load(os.path.join(out, "tests_base.json"))
    base = load(os.path.join(out, "base_dump.json"))
    pat = load(os.path.join(out, "patched_dump.json"))
    fx = load("fixtures_report.json")
    for name in ("fixtures_report.json", "fetch_report.json",
                 "setup_report.json"):
        if os.path.isfile(name):
            shutil.copyfile(name, os.path.join(out, name))
    rows = {}

    def put(row, ok, why):
        rows[row] = {"result": ("not run" if ok is None
                                else "held" if ok else "failed"),
                     "why": why}

    # P1
    if patch is None or base is None or pat is None:
        put("P1", None, "missing patch report or dumps")
    else:
        f = patch.get("files", {}).get("pickle_model_scan.py", {})
        ok = (patch.get("ok") is True and f.get("ok") is True
              and base["versions"] == {"model_file_scan": "0.14.0",
                                       "pickle_model_scan": "0.7.0"}
              and pat["versions"] == {"model_file_scan": "0.14.0",
                                      "pickle_model_scan": "0.8.0"})
        put("P1", ok, "patch ok=%s error=%s base=%s patched=%s"
            % (patch.get("ok"), patch.get("error"), base["versions"],
               pat["versions"]))
    # S1
    if tests is None or tbase is None:
        put("S1", None, "missing test summaries")
    else:
        ok = (tests.get("ok") is True and tbase.get("ok") is True
              and (tests.get("ran") or 0) > (tbase.get("ran") or 0))
        put("S1", ok, "patched ran=%s ok=%s failures=%s errors=%s; base "
            "ran=%s ok=%s" % (tests.get("ran"), tests.get("ok"),
                              tests.get("failures"), tests.get("errors"),
                              tbase.get("ran"), tbase.get("ok")))
    bd = (base or {}).get("direct", {})
    pd = (pat or {}).get("direct", {})
    # M1
    if "F4" not in bd:
        put("M1", None, "F4 missing")
    else:
        r = bd["F4"]
        ok = (len(r) == 1 and r[0].get("rule") == "PKL000"
              and r[0].get("severity") == "LOW"
              and str(r[0].get("location")).endswith("!" + NESTED))
        put("M1", ok, json.dumps(r)[:600])
    # M2
    mem = ((fx or {}).get("members") or {}).get("F4", {}).get(NESTED)
    if mem is None:
        put("M2", None, "member not recorded")
    else:
        ok = (mem.get("head") == "504b0304" and mem.get("opens_as_zip") is True
              and (mem.get("torch_load_weights_only") or {}).get("ok") is True)
        put("M2", ok, json.dumps(mem)[:600])
    # N1, N2
    if "F4" not in pd:
        put("N1", None, "F4 missing")
        put("N2", None, "F4 missing")
    else:
        r = pd["F4"]
        put("N1", not any(x.get("rule") in ("PKL000", "PKL098") for x in r),
            json.dumps(r)[:600])
        put("N2", not has_error(r) and top(r) < SEV["MEDIUM"],
            "top=%s rows=%d" % (top(r), len(r)))
    # N3
    bw = ((base or {}).get("walked") or {}).get("F4")
    pw = ((pat or {}).get("walked") or {}).get("F4")
    if bw is None or pw is None:
        put("N3", None, "walk record missing")
    else:
        head = "F4!" + NESTED + "!"
        ok = (("F4!" + NESTED) in bw and any(
            s.startswith(head) and s.endswith("data.pkl") for s in pw)
              and ("F4!" + NESTED) not in pw)
        put("N3", ok, "base=%s patched=%s" % (bw, pw))
    # T3, T4
    same, tops, missing = {}, {}, []
    for k in ("F1", "F2", "F3", "F5"):
        if k not in bd or k not in pd:
            missing.append(k)
            continue
        same[k] = keyset(bd[k]) == keyset(pd[k])
        tops[k] = [top(bd[k]), top(pd[k])]
    if missing:
        put("T3", None, "missing %s" % missing)
        put("T4", None, "missing %s" % missing)
    else:
        put("T3", all(same.values()), json.dumps(same))
        put("T4", all(a == b for a, b in tops.values()), json.dumps(tops))
    # C2
    want = {"F1": 1, "F4": 0, "F5": 0, "dir": 1}
    bc = {k: v.get("exit") for k, v in ((base or {}).get("cli") or {}).items()}
    pc = {k: v.get("exit") for k, v in ((pat or {}).get("cli") or {}).items()}
    if not pc or not bc:
        put("C2", None, "cli missing")
    else:
        put("C2", all(pc.get(k) == v and bc.get(k) == v
                      for k, v in want.items()),
            "base=%s patched=%s" % (bc, pc))
    # L0
    ld = (fx or {}).get("loaders") or {}
    need = ("jit_load_F1", "export_load_F4", "export_load_F6")
    if not ld:
        put("L0", None, "no loader record")
    else:
        put("L0", all((ld.get(n) or {}).get("ok") is True for n in need),
            json.dumps({n: (ld.get(n) or {}).get("ok") for n in need}))
    # D1 (diagnostic)
    if "F6" not in bd:
        put("D1", None, "F6 missing")
    else:
        hits = [r for r in bd["F6"] if r.get("rule") == "PKL000"
                and "!model/data/weights/" in str(r.get("location"))]
        put("D1", bool(hits), json.dumps(hits)[:600])

    held = sorted(k for k, v in rows.items() if v["result"] == "held")
    failed = sorted(k for k, v in rows.items() if v["result"] == "failed")
    not_run = sorted(k for k, v in rows.items() if v["result"] == "not run")
    summary = {
        "rows": rows, "held": held, "failed": failed, "not_run": not_run,
        "release_rows_all_held": all(rows.get(k, {}).get("result") == "held"
                                     for k in RELEASE),
        "recorded": {
            "torch": (fx or {}).get("torch"),
            "F6_base": bd.get("F6"), "F6_patched": pd.get("F6"),
            "F4_patched": pd.get("F4"),
            "walked_base": (base or {}).get("walked"),
            "walked_patched": (pat or {}).get("walked"),
            "members": (fx or {}).get("members"),
            "loaders": ld,
            "tests": {"patched": tests, "base": tbase},
        },
    }
    with open(os.path.join(out, "nest_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"held": held, "failed": failed, "not_run": not_run,
                      "release_rows_all_held":
                      summary["release_rows_all_held"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
