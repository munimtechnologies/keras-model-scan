#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step for job pte-dtype-v1 (no network): scan the published .pte
programs collected by fetch_hub_pte.py with BOTH executorch_pte_scan 0.1.0
(released v0.60.0 tree, ./tree) and the candidate 0.1.1 (./patched), and
grade the rows pre-registered in research/PREREG_PTE_DTYPE_FIX.md.

Each file is rebuilt as a sparse file (its program bytes at offset 0, its
true length, zeros after), as in job pte-census-v1; row E1 checks that on
files also downloaded whole.

Usage: dtype_census.py --out OUT. Reads OUT/patch_report.json,
OUT/tests_patched.json, OUT/tests_base.json and OUT/vendor_check.json.
Writes OUT/dtype_summary.json and OUT/dtype_files.json.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import importlib.util
import json
import os
import shutil
import sys

import pte_lib as L

HERE = os.path.dirname(os.path.abspath(__file__))
G1_FILES, G1_MODELS, E1_MIN, T1_MIN_TESTS = 100, 30, 10, 41
DTYPE_NOTE = "is not an ExecuTorch dtype"
PTE004_PREFIX = "indexes that are out of range: "


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


def dtype_notes(findings):
    """Number of dtype examples in the PTE004 finding (0 if none)."""
    for f in findings:
        if f.get("rule") == "PTE004":
            return sum(1 for part in str(f.get("evidence", "")).split("; ")
                       if DTYPE_NOTE in part)
    return 0


def strip_dtype_only(findings):
    """0.1.0 findings without a PTE004 entry that consists only of dtype
    notes (every example a dtype note and the count equal to the examples).
    Returns (findings, mixed): mixed is True when a PTE004 entry has dtype
    notes together with other notes or more notes than examples."""
    out, mixed = [], False
    for f in findings:
        if f.get("rule") == "PTE004":
            parts = str(f.get("evidence", "")).split("; ")
            n_dtype = sum(1 for p in parts if DTYPE_NOTE in p)
            msg = str(f.get("message", ""))
            try:
                count = int(msg[len(PTE004_PREFIX):]) if msg.startswith(
                    PTE004_PREFIX) else None
            except ValueError:
                count = None
            if n_dtype and n_dtype == len(parts) and count == n_dtype:
                continue
            if n_dtype:
                mixed = True
        out.append(f)
    return out, mixed


def has(findings, rules):
    return any(x.get("rule") in rules for x in findings)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    patch = read_json(os.path.join(out_dir, "patch_report.json"))
    t_new = read_json(os.path.join(out_dir, "tests_patched.json"))
    t_old = read_json(os.path.join(out_dir, "tests_base.json"))
    vendor = read_json(os.path.join(out_dir, "vendor_check.json"))
    rep = read_json(os.path.join(HERE, "hub", "pte_census_fetch.json"))

    old = load(os.path.join(HERE, "tree", "executorch_pte_scan.py"), "pte_old")
    try:
        new = load(os.path.join(HERE, "patched", "executorch_pte_scan.py"),
                   "pte_new")
    except Exception as exc:
        new = None
        new_error = "%s: %s" % (type(exc).__name__, exc)
    else:
        new_error = None

    tmp = os.path.join(HERE, "sparse")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    rows, scanned, equiv = [], [], []
    for f in rep.get("files", []):
        row = {k: f.get(k) for k in ("n", "model", "rfilename", "downloads",
                                     "size", "plan", "error")}
        info = f.get("info") or {}
        row["identifier"] = info.get("identifier")
        row["has_header"] = info.get("has_header")
        if f.get("prog") and isinstance(f.get("size"), int) and new is not None:
            path = os.path.join(tmp, "%04d.pte" % f["n"])
            try:
                with open(os.path.join(HERE, f["prog"]), "rb") as fh:
                    L.make_sparse(path, fh.read(), f["size"])
                row["old"] = old.scan_file(path)
                row["new"] = new.scan_file(path)
                scanned.append(row)
            except Exception as exc:
                row["scan_error"] = "%s: %s" % (type(exc).__name__, exc)
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass
            if f.get("whole") and "new" in row:
                try:
                    full = new.scan_file(os.path.join(HERE, f["whole"]))
                    same = L.normalise(full) == L.normalise(row["new"])
                    equiv.append({"n": f["n"], "model": f["model"],
                                  "rfilename": f["rfilename"], "same": same,
                                  "whole_findings": None if same else full})
                except Exception as exc:
                    equiv.append({"n": f["n"], "same": False,
                                  "error": "%s: %s" % (type(exc).__name__, exc)})
        rows.append(row)

    n = len(scanned)
    models = {r["model"] for r in scanned}
    res = {}

    def put(key, ok, why, testable=True):
        res[key] = {"result": ("held" if ok else "failed") if testable
                    else "untestable", "why": why}

    put("P1", bool(patch.get("ok")) and new is not None,
        "patch ok=%s; edits %s; import %s" % (
            patch.get("ok"), [e.get("matches") for e in patch.get("edits", [])],
            new_error or "ok"))
    put("T1", bool(t_new.get("ok")) and (t_new.get("ran") or 0) >= T1_MIN_TESTS,
        "patched: ran %s, failures %s, errors %s; base: ran %s ok %s" % (
            t_new.get("ran"), t_new.get("failures"), t_new.get("errors"),
            t_old.get("ran"), t_old.get("ok")))
    for key in ("V1", "V2"):
        v = vendor.get(key) or {"result": "untestable",
                                "why": vendor.get("error", "missing")}
        res[key] = {"result": v.get("result"), "why": v.get("why")}

    gate_ok = n >= G1_FILES and len(models) >= G1_MODELS
    put("G1", gate_ok, "%d files from %d models" % (n, len(models)))
    e_ok = len(equiv) >= E1_MIN
    put("E1", all(e["same"] for e in equiv),
        "%d of %d whole files scan the same with 0.1.1" % (
            sum(1 for e in equiv if e["same"]), len(equiv)), testable=e_ok)
    census_ok = gate_ok and res["E1"]["result"] == "held"

    d_new = [r for r in scanned if dtype_notes(r["new"])]
    integ_new = [r for r in scanned if has(r["new"], L.INTEGRITY_RULES)]
    dtype_only_old = []
    for r in scanned:
        stripped, mixed = strip_dtype_only(r["old"])
        r["old_dtype_notes"] = dtype_notes(r["old"])
        r["old_mixed"] = mixed
        if r["old_dtype_notes"] and not mixed and not has(
                stripped, L.INTEGRITY_RULES):
            dtype_only_old.append(r)
    d3_bad = [r for r in dtype_only_old if has(r["new"], L.INTEGRITY_RULES)]
    d4_diff = []
    for r in scanned:
        stripped, mixed = strip_dtype_only(r["old"])
        if mixed or L.normalise(stripped) != L.normalise(r["new"]):
            d4_diff.append(r)

    put("D1", not d_new, "%d of %d files have a dtype PTE004 note under 0.1.1"
        % (len(d_new), n), testable=census_ok)
    s = L.share(len(integ_new), n)
    put("D2", s is not None and s <= 0.02,
        "%d of %d files have PTE001/PTE002/PTE004 under 0.1.1"
        % (len(integ_new), n), testable=census_ok)
    put("D3", not d3_bad, "%d of %d files flagged by 0.1.0 only for dtypes "
        "have an integrity finding under 0.1.1" % (len(d3_bad),
                                                   len(dtype_only_old)),
        testable=census_ok and bool(dtype_only_old))
    put("D4", not d4_diff, "%d of %d files differ beyond dropped dtype-only "
        "PTE004 entries" % (len(d4_diff), n), testable=census_ok)

    needed = ("P1", "T1", "V1", "V2", "G1", "E1", "D1", "D2", "D3", "D4")
    release = all(res[k]["result"] == "held" for k in needed)

    old_integ = [r for r in scanned if has(r["old"], L.INTEGRITY_RULES)]
    recorded = {
        "scanners": {"old": old.__version__,
                     "new": getattr(new, "__version__", None)},
        "list": rep.get("list"), "candidates": rep.get("candidates"),
        "probed": len(rows), "scanned": n, "models": len(models),
        "bytes_fetched": rep.get("bytes_fetched"),
        "old_integrity_files": len(old_integ),
        "old_dtype_files": sum(1 for r in scanned if r["old_dtype_notes"]),
        "old_dtype_only_files": len(dtype_only_old),
        "old_mixed_files": sum(1 for r in scanned if r["old_mixed"]),
        "new_integrity_files": len(integ_new),
        "new_pte005_files": sum(1 for r in scanned if has(r["new"], ("PTE005",))),
        "new_pte003_files": sum(1 for r in scanned if has(r["new"], ("PTE003",))),
        "new_gate_fails": sum(1 for r in scanned if L.gate_fails(r["new"])),
        "new_clean_files": sum(1 for r in scanned if not r["new"]),
        "dtype_files": [{"model": r["model"], "rfilename": r["rfilename"],
                         "old": [x for x in r["old"] if x.get("rule") != "PTE003"],
                         "new": [x for x in r["new"] if x.get("rule") != "PTE003"]}
                        for r in scanned if r["old_dtype_notes"]],
        "new_integrity": [{"model": r["model"], "rfilename": r["rfilename"],
                           "findings": [x for x in r["new"]
                                        if x.get("rule") in L.INTEGRITY_RULES]}
                          for r in integ_new],
        "d4_differences": [{"model": r["model"], "rfilename": r["rfilename"],
                            "old": r["old"], "new": r["new"]}
                           for r in d4_diff[:20]],
        "equivalence_failures": [e for e in equiv if not e["same"]],
        "vendor_unpatched_missing": vendor.get("unpatched_missing"),
        "vendor_commit": (vendor.get("fetch") or {}).get("commit"),
    }
    summary = {"rows": res, "release_rule_met": release,
               "held": sorted(k for k, v in res.items() if v["result"] == "held"),
               "failed": sorted(k for k, v in res.items()
                                if v["result"] == "failed"),
               "untestable": sorted(k for k, v in res.items()
                                    if v["result"] == "untestable"),
               "recorded": recorded}
    with open(os.path.join(out_dir, "dtype_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    with open(os.path.join(out_dir, "dtype_files.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    shutil.copy(os.path.join(HERE, "hub", "pte_census_fetch.json"),
                os.path.join(out_dir, "pte_census_fetch.json"))
    print(json.dumps({"rows": {k: v["result"] for k, v in res.items()},
                      "release_rule_met": release, "scanned": n,
                      "models": len(models)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
