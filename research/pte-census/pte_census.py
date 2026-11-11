#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step for job pte-census-v1 (no network): scan the published .pte
programs collected by fetch_hub_pte.py with executorch_pte_scan from the
released v0.59.0 tree, unchanged, and grade the pre-registered rows in
research/PREREG_PTE_CENSUS.md.

Each file is rebuilt as a sparse file: its first bytes (the eh00 header and
the FlatBuffer program) at offset 0 and its true length, the rest zeros. The
scanner reads only those first bytes and compares segment offsets with the
file length, so the scan equals a scan of the whole file; row E1 checks
that on every file that was also downloaded whole.

Writes pte_census_summary.json and pte_census_files.json to --out.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import json
import os
import shutil
import sys

import pte_lib as L

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tree"))
import executorch_pte_scan as P  # noqa: E402

G1_FILES, G1_MODELS, E1_MIN = 100, 30, 10


def quantiles(values):
    v = sorted(values)
    if not v:
        return None
    pick = lambda q: v[min(len(v) - 1, int(q * (len(v) - 1) + 0.5))]
    return {"n": len(v), "min": v[0], "p25": pick(0.25), "median": pick(0.5),
            "p75": pick(0.75), "p90": pick(0.9), "max": v[-1]}


def scan_one(f, tmp):
    with open(os.path.join(HERE, f["prog"]), "rb") as fh:
        head = fh.read()
    path = os.path.join(tmp, "%04d.pte" % f["n"])
    try:
        L.make_sparse(path, head, f["size"])
        return P.scan_file(path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(HERE, "hub", "pte_census_fetch.json"),
              encoding="utf-8") as fh:
        rep = json.load(fh)
    tmp = os.path.join(HERE, "sparse")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)

    rows_out, scanned, equiv = [], [], []
    for f in rep.get("files", []):
        row = {k: f.get(k) for k in ("n", "model", "rfilename", "rank",
                                     "downloads", "library", "pte_in_model",
                                     "size", "plan", "error")}
        info = f.get("info") or {}
        row["identifier"] = info.get("identifier")
        row["has_header"] = info.get("has_header")
        row["program_size"] = info.get("program_size")
        row["segment_data_size"] = info.get("segment_data_size")
        if f.get("prog") and isinstance(f.get("size"), int):
            try:
                findings = scan_one(f, tmp)
                row["findings"] = findings
                scanned.append(row)
            except Exception as exc:
                row["scan_error"] = "%s: %s" % (type(exc).__name__, exc)
            if f.get("whole") and "findings" in row:
                try:
                    full = P.scan_file(os.path.join(HERE, f["whole"]))
                    same = L.normalise(full) == L.normalise(row["findings"])
                    equiv.append({"n": f["n"], "model": f["model"],
                                  "rfilename": f["rfilename"], "same": same,
                                  "plan": f.get("plan"),
                                  "whole_findings": None if same else full})
                except Exception as exc:
                    equiv.append({"n": f["n"], "same": False,
                                  "error": "%s: %s" % (type(exc).__name__, exc)})
        rows_out.append(row)

    n = len(scanned)
    models = {r["model"] for r in scanned}
    has = lambda r, rules: any(x.get("rule") in rules for x in r["findings"])
    integ = [r for r in scanned if has(r, L.INTEGRITY_RULES)]
    pte5 = [r for r in scanned if has(r, ("PTE005",))]
    pte3 = [r for r in scanned if has(r, ("PTE003",))]
    gate = [r for r in scanned if L.gate_fails(r["findings"])]
    clean = [r for r in scanned if not r["findings"]]
    deleg = {}
    for r in scanned:
        for name in sorted(set(L.delegates(r["findings"]))):
            deleg[name] = deleg.get(name, 0) + 1
    probed = [r for r in rows_out if r.get("identifier") is not None]
    et12 = [r for r in probed if r["identifier"] == "ET12"]
    rule_files = {}
    for r in scanned:
        for rule in sorted({x.get("rule") for x in r["findings"]}):
            rule_files[rule] = rule_files.get(rule, 0) + 1
    # One file per model (the first in the fixed order), as a sensitivity view.
    first = {}
    for r in scanned:
        first.setdefault(r["model"], r)
    per_model = list(first.values())

    gate_ok = n >= G1_FILES and len(models) >= G1_MODELS
    res = {}
    res["G1"] = {"result": "held" if gate_ok else "failed",
                 "why": "%d files from %d models" % (n, len(models))}
    e_ok = len(equiv) >= E1_MIN
    res["E1"] = {"result": ("held" if all(e["same"] for e in equiv) else "failed")
                 if e_ok else "untestable",
                 "why": "%d of %d whole files scan the same" % (
                     sum(1 for e in equiv if e["same"]), len(equiv))}

    def grade(key, ok, why):
        if not gate_ok or res["E1"]["result"] == "failed":
            res[key] = {"result": "untestable", "why": why}
        else:
            res[key] = {"result": "held" if ok else "failed", "why": why}

    s = L.share
    grade("R1", s(len(integ), n) is not None and s(len(integ), n) <= 0.02,
          "%d of %d files have PTE001/PTE002/PTE004" % (len(integ), n))
    grade("R2", s(len(pte5), n) is not None and s(len(pte5), n) <= 0.05,
          "%d of %d files have PTE005" % (len(pte5), n))
    grade("R3", s(len(pte3), n) is not None and s(len(pte3), n) >= 0.70,
          "%d of %d files have PTE003" % (len(pte3), n))
    top = sorted(deleg.items(), key=lambda kv: (-kv[1], kv[0]))
    grade("R4", bool(top) and top[0][0] == "XnnpackBackend"
          and (len(top) == 1 or top[1][1] < top[0][1]),
          "delegates by files: %s" % top[:8])
    grade("R5", s(len(gate), n) is not None and s(len(gate), n) >= 0.70,
          "%d of %d files fail the default gate" % (len(gate), n))
    r6_ok = len(probed) >= G1_FILES
    res["R6"] = {"result": ("held" if s(len(et12), len(probed)) >= 0.95
                            else "failed") if r6_ok else "untestable",
                 "why": "%d of %d probed files are ET12" % (len(et12), len(probed))}

    release = {"held": sorted(k for k, v in res.items() if v["result"] == "held"),
               "failed": sorted(k for k, v in res.items() if v["result"] == "failed"),
               "untestable": sorted(k for k, v in res.items()
                                    if v["result"] == "untestable")}
    skipped = {}
    for r in rows_out:
        if r in scanned:
            continue
        why = (r.get("plan") or [None, None])[1] or r.get("error") or r.get(
            "scan_error") or "not fetched"
        why = str(why).split(":")[0]
        skipped[why] = skipped.get(why, 0) + 1
    recorded = {
        "scanner": {"executorch_pte_scan": P.__version__},
        "list": rep.get("list"), "candidates": rep.get("candidates"),
        "probed": len(rows_out), "scanned": n, "models_scanned": len(models),
        "bytes_fetched": rep.get("bytes_fetched"), "skipped": skipped,
        "identifiers": {k: sum(1 for r in probed if r["identifier"] == k)
                        for k in sorted({r["identifier"] for r in probed})},
        "has_header": sum(1 for r in scanned if r.get("has_header")),
        "file_size": quantiles([r["size"] for r in scanned]),
        "program_size": quantiles([r["program_size"] for r in scanned
                                   if isinstance(r.get("program_size"), int)]),
        "files_per_rule": rule_files, "delegates_by_files": dict(top),
        "clean_files": len(clean),
        "per_model_first_file": {
            "models": len(per_model),
            "PTE003": sum(1 for r in per_model if has(r, ("PTE003",))),
            "integrity": sum(1 for r in per_model if has(r, L.INTEGRITY_RULES)),
            "PTE005": sum(1 for r in per_model if has(r, ("PTE005",))),
            "gate_fails": sum(1 for r in per_model if L.gate_fails(r["findings"]))},
        "flagged": [{"model": r["model"], "rfilename": r["rfilename"],
                     "findings": [x for x in r["findings"]
                                  if x.get("rule") != "PTE003"]}
                    for r in scanned if has(r, L.INTEGRITY_RULES + ("PTE005",))],
        "equivalence": equiv,
    }
    summary = {"rows": res, **release, "recorded": recorded}
    with open(os.path.join(args.out, "pte_census_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    with open(os.path.join(args.out, "pte_census_files.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rows_out, fh, indent=1)
    shutil.copy(os.path.join(HERE, "hub", "pte_census_fetch.json"),
                os.path.join(args.out, "pte_census_fetch.json"))
    print(json.dumps({"rows": {k: v["result"] for k, v in res.items()},
                      "scanned": n, "models": len(models)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
