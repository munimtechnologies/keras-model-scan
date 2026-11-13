#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step for job ctr-cal-v1 (pre-registered in
research/PREREG_CTR_CALIBRATION.md). No network.

For every fetched config.json: parse it (census_lib), compute the expected
rules from the pre-registered spec (expect_lib), and run
config_trust_remote_code_scan 0.1.0 (./base, tag v0.60.0) and the calibrated
0.2.0 (./patched). Grades rows G1 C1 C2 P1 P2 P3 and writes
/out/ctr_cal_summary.json, /out/ctr_cal_rows.json and /out/ctr_cal_flagged.json.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import importlib.util
import json
import os
import sys
import time

import census_lib as c
import expect_lib as e

KNOWN = ("chandar-lab/NeoBERT",
         "optimum-intel-internal-testing/tiny-random-codegen2")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def share(n, d):
    return round(n / d, 6) if d else None


def run_scan(mod, path):
    try:
        return [[c.rule_of(f), c.severity_of(f), f.get("cve", "")]
                for f in mod.scan(path)]
    except Exception as exc:
        return [["EXC", type(exc).__name__, ""]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    old = load("ctr_old", os.path.join("base",
                                       "config_trust_remote_code_scan.py"))
    new = load("ctr_new", os.path.join("patched",
                                       "config_trust_remote_code_scan.py"))
    with open(os.path.join("hub", "hfcfg_index.json"), encoding="utf-8") as fh:
        index = json.load(fh)

    rows = []
    for m in index.get("models", []):
        if m.get("fetched") != "ok":
            continue
        with open(m["path"], "rb") as fh:
            data = fh.read()
        doc, err = c.parse(data)
        r = {"model": m["model"], "samples": m["samples"],
             "downloads": m.get("downloads", 0), "parsed": err is None,
             "parse_error": err,
             "old": run_scan(old, m["path"]), "new": run_scan(new, m["path"])}
        if doc is not None:
            r["gt_trc"] = c.count_keys(doc, [c.TRC])[c.TRC]
            r["expected"] = e.expected_rules(doc)
            r["lightglue"] = e.names_lightglue(doc)
            r["trc_values"] = [json.dumps(v)[:40]
                               for v in c.values_of(doc, c.TRC)]
            r["model_types"] = c.model_types(doc)[:12]
        rows.append(r)

    parsed = [r for r in rows if r["parsed"]]
    in_a = [r for r in parsed if "A" in r["samples"]]
    in_b = [r for r in parsed if "B" in r["samples"]]

    def c1_ok(r):
        got = sorted(x[0] for x in r["new"])
        if got != r["expected"]:
            return False
        for rule, level, cve in r["new"]:
            if e.EXPECTED_LEVEL.get(rule) != level:
                return False
            if e.EXPECTED_CVE.get(rule) != cve:
                return False
        return True

    def n_find(lst):
        return sum(1 for x in lst if x[0] in ("CTR001", "CTR002", "CTR003"))

    res = {}
    res["G1"] = {"pred": "distinct parsed >= 1200, A >= 500, B >= 500",
                 "n": len(parsed), "A": len(in_a), "B": len(in_b),
                 "held": len(parsed) >= 1200 and len(in_a) >= 500
                 and len(in_b) >= 500}
    c1_bad = [r["model"] for r in parsed if not c1_ok(r)]
    res["C1"] = {"pred": "0.2.0 rules, levels and CVEs equal the spec on "
                 "every parsed file; no CTR000/EXC",
                 "mismatch": c1_bad[:50], "held": bool(parsed) and not c1_bad}
    c2_bad = [r["model"] for r in parsed
              if n_find(r["new"]) != n_find(r["old"])
              or n_find(r["new"]) != r["gt_trc"]]
    res["C2"] = {"pred": "0.2.0 keeps one finding per key: finding count "
                 "equals 0.1.0's and the key count on every parsed file",
                 "mismatch": c2_bad[:50], "held": bool(parsed) and not c2_bad}
    hi_new = [r["model"] for r in parsed if not r.get("lightglue")
              and any(x[1] in ("HIGH", "CRITICAL") for x in r["new"])]
    hi_old = [r["model"] for r in parsed
              if any(x[1] in ("HIGH", "CRITICAL") for x in r["old"])]
    res["P1"] = {"pred": "0.2.0 HIGH/CRITICAL on 0 configs that do not name "
                 "lightglue", "n_new": len(hi_new), "n_old": len(hi_old),
                 "n_lightglue_files": sum(1 for r in parsed
                                          if r.get("lightglue")),
                 "held": bool(parsed) and not hi_new}
    a_trc = [r for r in in_a if r.get("gt_trc", 0) > 0]
    b_trc = [r for r in in_b if r.get("gt_trc", 0) > 0]
    res["P2"] = {"pred": "trust_remote_code key in <= 1% of A and <= 0.5% "
                 "of B (replication of hfcfg-census-v1 P1/P2)",
                 "A": len(a_trc), "A_share": share(len(a_trc), len(in_a)),
                 "B": len(b_trc), "B_share": share(len(b_trc), len(in_b)),
                 "held": bool(in_a) and bool(in_b)
                 and len(a_trc) <= 0.01 * len(in_a)
                 and len(b_trc) <= 0.005 * len(in_b)}
    known = [r for r in parsed if r["model"] in KNOWN
             and r.get("gt_trc", 0) > 0]
    res["P3"] = {"pred": "the two configs flagged CRITICAL in hfcfg-census-v1 "
                 "now get only CTR003 LOW (each one still present with the "
                 "key)", "present": [r["model"] for r in known],
                 "held": (all(r["new"] and all(x[:2] == ["CTR003", "LOW"]
                                               for x in r["new"])
                              for r in known)) if known else "untestable"}
    release = bool(res["G1"]["held"] and res["C1"]["held"]
                   and res["C2"]["held"])
    flagged = [{k: r.get(k) for k in ("model", "samples", "downloads", "old",
                                      "new", "expected", "lightglue",
                                      "trc_values", "model_types")}
               for r in parsed if r["old"] or r["new"]]
    fetch_status = {}
    for m in index.get("models", []):
        k = str(m.get("fetched")).split(":")[0]
        fetch_status[k] = fetch_status.get(k, 0) + 1
    summary = {"finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "listed": index.get("listed"),
               "list_started": index.get("started"),
               "fetch_status": fetch_status, "fetched_ok": len(rows),
               "parsed": len(parsed),
               "versions": {"old": old.__version__, "new": new.__version__},
               "rows": res, "release_rule_met": release,
               "release_rule": "G1, C1 and C2 hold (and the 0.2.0 unit tests "
                               "passed in an earlier run step)"}
    for name, obj in (("ctr_cal_summary.json", summary),
                      ("ctr_cal_rows.json", rows),
                      ("ctr_cal_flagged.json", flagged)):
        with open(os.path.join(args.out, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1)
    print(json.dumps({k: v.get("held") for k, v in res.items()}))
    print("release_rule_met=%s" % release)
    return 0


if __name__ == "__main__":
    sys.exit(main())
