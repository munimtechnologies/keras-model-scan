#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Grade the rows of research/PREREG_PT2_WEIGHTS.md from the job's outputs.

Reads OUT/patch_report.json, OUT/tests_summary.json, OUT/tests_base.json,
OUT/base_dump.json, OUT/patched_dump.json and ./fixtures_report.json; writes
OUT/weights_summary.json. A row whose inputs are missing is "not run".

Locations are matched on "/data/weights/" and "/data/constants/" WITHOUT a
fixed archive prefix: torch.export.save names the top folder after the file
(model_b.pt2 -> model_b/), which pt2-nest-v1's grader missed.

Release rows: P1 S1 W1 L0 L1 B1 N1 N2 N3 T3 T5 C2.
Diagnostic rows (do not decide the release): D2 D3.

Usage: weights_check.py --out OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RELEASE = ("P1", "S1", "W1", "L0", "L1", "B1", "N1", "N2", "N3", "T3", "T5",
           "C2")
WEIGHT_RE = re.compile(r"(^|/)data/weights/weight_\d+$")
VALUE = 1.0000152587890625


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


def on_weight(row):
    loc = str(row.get("location") or "")
    member = loc.rsplit("!", 1)[-1]
    return bool(WEIGHT_RE.search(member))


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

    bd = (base or {}).get("direct", {})
    pd = (pat or {}).get("direct", {})
    # P1
    if patch is None or base is None or pat is None:
        put("P1", None, "missing patch report or dumps")
    else:
        f = patch.get("files", {}).get("pickle_model_scan.py", {})
        ok = (patch.get("ok") is True and f.get("ok") is True
              and len(f.get("changes") or []) == 4
              and base["versions"] == {"model_file_scan": "0.14.0",
                                       "pickle_model_scan": "0.8.0"}
              and pat["versions"] == {"model_file_scan": "0.14.0",
                                      "pickle_model_scan": "0.9.0"})
        put("P1", ok, "patch ok=%s error=%s changes=%s base=%s patched=%s"
            % (patch.get("ok"), patch.get("error"), f.get("changes"),
               base["versions"], pat["versions"]))
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
    # W1: torch's own config declares every F6 weight raw
    mem6 = ((fx or {}).get("members") or {}).get("F6")
    cfg6 = ((fx or {}).get("configs") or {}).get("F6")
    if not mem6 or cfg6 is None:
        put("W1", None, "F6 members or configs not recorded")
    else:
        weights = sorted(n for n in mem6 if WEIGHT_RE.search(n))
        declared = {}
        for cname, c in cfg6.items():
            if not cname.endswith("_weights_config.json"):
                continue
            folder = cname.rsplit("/", 1)[0] + "/"
            for e in c.get("entries") or []:
                declared[folder + str(e.get("path_name"))] = e.get(
                    "use_pickle")
        ok = bool(weights) and all(declared.get(w) is False for w in weights)
        put("W1", ok, json.dumps({"weights": weights,
                                  "declared": declared})[:800])
    # L0, L1
    ld = (fx or {}).get("loaders") or {}
    need = ("jit_load_F1", "export_load_F4", "export_load_F6")
    if not ld:
        put("L0", None, "no loader record")
    else:
        put("L0", all((ld.get(n) or {}).get("ok") is True for n in need),
            json.dumps({n: (ld.get(n) or {}).get("ok") for n in need}))
    firsts = (fx or {}).get("f6_first_values")
    if not firsts:
        put("L1", None, "F6 values not recorded")
    else:
        ok = all(abs(v - VALUE) < 1e-6 or v == 128 for v in firsts.values())
        put("L1", ok, json.dumps(firsts)[:600])
    # B1: base reproduces the gap (pt2-nest-v1's D1, prefix-agnostic)
    if "F6" not in bd:
        put("B1", None, "F6 missing")
    else:
        hits = [r for r in bd["F6"] if r.get("rule") == "PKL000"
                and r.get("severity") == "LOW" and on_weight(r)]
        put("B1", bool(hits), "%d PKL000 LOW on weights" % len(hits))
    # N1, N2
    if "F4" not in pd or "F6" not in pd:
        put("N1", None, "F4/F6 missing")
        put("N2", None, "F4/F6 missing")
    else:
        bad = [r for k in ("F4", "F6") for r in pd[k]
               if r.get("rule") in ("PKL000", "PKL098")]
        put("N1", not bad, json.dumps(bad)[:600])
        ok = all(not has_error(pd[k]) and top(pd[k]) < SEV["MEDIUM"]
                 for k in ("F4", "F6"))
        put("N2", ok, json.dumps({k: top(pd[k]) for k in ("F4", "F6")}))
    # N3
    bw = ((base or {}).get("walked") or {}).get("F6")
    pw = ((pat or {}).get("walked") or {}).get("F6")
    if bw is None or pw is None:
        put("N3", None, "walk record missing")
    else:
        bws = [s for s in bw if WEIGHT_RE.search(s.rsplit("!", 1)[-1])]
        pws = [s for s in pw if WEIGHT_RE.search(s.rsplit("!", 1)[-1])]
        put("N3", bool(bws) and not pws,
            "base weights walked=%d patched=%d" % (len(bws), len(pws)))
    # T3: controls unchanged
    same, missing = {}, []
    for k in ("F1", "F3", "F5"):
        if k not in bd or k not in pd:
            missing.append(k)
            continue
        same[k] = keyset(bd[k]) == keyset(pd[k])
    if missing:
        put("T3", None, "missing %s" % missing)
    else:
        put("T3", all(same.values()), json.dumps(same))
    # T5: on F6 the only change is the removed weight notes
    if "F6" not in bd or "F6" not in pd:
        put("T5", None, "F6 missing")
    else:
        kept = [r for r in bd["F6"]
                if not (r.get("rule") == "PKL000" and on_weight(r))]
        put("T5", keyset(kept) == keyset(pd["F6"]),
            "base-minus-weight-notes=%s patched=%s"
            % (keyset(kept), keyset(pd["F6"])))
    # C2
    want = {"F1": 1, "F4": 0, "F5": 0, "F6": 0, "dir": 1}
    bc = {k: v.get("exit") for k, v in ((base or {}).get("cli") or {}).items()}
    pc = {k: v.get("exit") for k, v in ((pat or {}).get("cli") or {}).items()}
    if not pc or not bc:
        put("C2", None, "cli missing")
    else:
        put("C2", all(pc.get(k) == v and bc.get(k) == v
                      for k, v in want.items()),
            "base=%s patched=%s" % (bc, pc))
    # D2 (diagnostic): lifted tensor constant of F7
    if "F7" not in bd or "F7" not in pd:
        put("D2", None, "F7 missing")
    else:
        def const_notes(rs):
            return [r for r in rs if r.get("rule") == "PKL000"
                    and "/data/constants/" in str(r.get("location"))]
        put("D2", bool(const_notes(bd["F7"])) and not const_notes(pd["F7"]),
            "base=%d patched=%d" % (len(const_notes(bd["F7"])),
                                    len(const_notes(pd["F7"]))))
    # D3 (diagnostic): torch.export.load reads F7
    put("D3", (ld.get("export_load_F7") or {}).get("ok")
        if ld.get("export_load_F7", {}).get("ok") is not None else None,
        json.dumps(ld.get("export_load_F7")))

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
            "F7_base": bd.get("F7"), "F7_patched": pd.get("F7"),
            "F4_base": bd.get("F4"), "F4_patched": pd.get("F4"),
            "walked_base": (base or {}).get("walked"),
            "walked_patched": (pat or {}).get("walked"),
            "configs": (fx or {}).get("configs"),
            "loaders": ld,
            "tests": {"patched": tests, "base": tbase},
        },
    }
    with open(os.path.join(out, "weights_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"held": held, "failed": failed, "not_run": not_run,
                      "release_rows_all_held":
                      summary["release_rows_all_held"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
