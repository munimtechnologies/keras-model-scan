#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Graded check for onnx_external_data_scan 0.2.0 and
onnx_external_data_key_scan 0.2.0 (pre-registered in
research/PREREG_OED_FUNCTIONS.md). Rows:

  P1  the patch applied cleanly to all four files
  S1  the whole keras-model-scan suite passes with the patched files
  W1  onnx's writer (convert_attribute=True) stores the function's Constant
      tensor as external data, location "weights.bin"
  L1  onnx.load fills that function tensor (4096 bytes, equal to the written
      values) from weights.bin
  H1  0.2.0 finds nothing on the honest files (function, plain, training,
      272 MB inline); key 0.2.0 finds nothing on the first three
  E1  function Constant "../outside.bin": 0.1.0 none, 0.2.0 {OED001}
  E2  function attribute_proto "/abs/w.bin": 0.1.0 none, 0.2.0 {OED002}
  E3  training_info "..\\t.bin": 0.1.0 none, 0.2.0 {OED001, OED005}
  E4  "../after.bin" past 256 MiB: offset > 256 MiB; 0.1.0 none,
      0.2.0 {OED001}
  K1  function tensor with key "owner": key 0.1.0 no OEK001, 0.2.0 ["owner"]
  C1  graph initializer "../g.bin": {OED001} in both versions
  T1  0.2.0 on the 272 MB file: under 60 s and under 1024 MB peak RSS
  Hb  Hub census: at least 10 .onnx files in (256 MiB, 2 GiB]

Writes OUT/oed_summary.json and OUT/writer_report.json. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OED = "onnx_external_data_scan.py"
OEK = "onnx_external_data_key_scan.py"
CASES = ("honest_func", "honest_plain", "honest_train", "h4_big_honest",
         "e1_func_parent", "e2_func_attrproto_abs", "e3_train_backslash",
         "e4_big_after_cap", "k1_func_key", "c1_graph_parent")
OEK_CASES = ("honest_func", "honest_plain", "honest_train", "k1_func_key")


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def scan(mod, path):
    try:
        proc = subprocess.run([sys.executable, os.path.join(HERE,
                                                            "scan_one.py"),
                               mod, path], capture_output=True, text=True,
                              timeout=900)
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


def row(ok, **kw):
    kw["held"] = bool(ok)
    return kw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--orig", required=True)
    ap.add_argument("--tree", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    summary = {"rows": {}, "reported": {}}
    rows = summary["rows"]
    try:
        patch = load(os.path.join(a.out, "patch_report.json")) or {}
        tests = load(os.path.join(a.out, "tests_summary.json")) or {}
        summary["reported"]["fetch"] = load("fetch_report.json")
        summary["reported"]["setup"] = load("setup_report.json")
        hub = load("hub_sizes.json")
        rows["P1"] = row(patch.get("ok"), files={
            k: {kk: vv for kk, vv in v.items() if kk != "lost"}
            for k, v in (patch.get("files") or {}).items()})
        rows["S1"] = row(tests.get("ok") and not tests.get("failures")
                         and not tests.get("errors"),
                         ran=tests.get("ran"), failures=tests.get("failures"),
                         errors=tests.get("errors"))

        work = os.path.abspath("files")
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)
        proc = subprocess.run([sys.executable,
                               os.path.join(HERE, "write_onnx.py"), work],
                              capture_output=True, text=True, timeout=1800)
        wr = load(os.path.join(work, "writer_report.json")) or {
            "ok": False, "stderr": proc.stderr[-2000:]}
        with open(os.path.join(a.out, "writer_report.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(wr, fh, indent=1)
        w1 = wr.get("W1") or {}
        rows["W1"] = row(w1.get("func_data_location") == 1
                         and (w1.get("func_external") or {}).get("location")
                         == "weights.bin"
                         and (w1.get("init_external") or {}).get("location")
                         == "weights.bin", **w1)
        l1 = wr.get("L1") or {}
        rows["L1"] = row(l1.get("raw_data_bytes") == 4096
                         and l1.get("equal_to_written") is True, **l1)

        if not patch.get("ok") or not wr.get("ok"):
            for r in ("H1", "E1", "E2", "E3", "E4", "K1", "C1", "T1"):
                rows[r] = {"held": False, "not_run": True}
        else:
            res = {}
            for case in CASES:
                f = os.path.join(work, case, "model.onnx")
                res[case] = {"oed_old": scan(os.path.join(a.orig, OED), f),
                             "oed_new": scan(os.path.join(a.tree, OED), f)}
                if case in OEK_CASES:
                    res[case]["oek_old"] = scan(os.path.join(a.orig, OEK), f)
                    res[case]["oek_new"] = scan(os.path.join(a.tree, OEK), f)
            summary["reported"]["scans"] = res

            def rules(case, which):
                return res[case][which].get("rules")

            honest = ("honest_func", "honest_plain", "honest_train",
                      "h4_big_honest")
            rows["H1"] = row(
                all(res[c]["oed_new"].get("n") == 0 for c in honest)
                and all(res[c]["oek_new"].get("n") == 0
                        for c in honest[:3]),
                oed_new={c: rules(c, "oed_new") for c in honest},
                oek_new={c: rules(c, "oek_new") for c in honest[:3]})
            for r, case, want in (("E1", "e1_func_parent", ["OED001"]),
                                  ("E2", "e2_func_attrproto_abs", ["OED002"]),
                                  ("E3", "e3_train_backslash",
                                   ["OED001", "OED005"])):
                rows[r] = row(rules(case, "oed_old") == []
                              and rules(case, "oed_new") == want,
                              old=rules(case, "oed_old"),
                              new=rules(case, "oed_new"))
            pre = wr.get("E4_pre") or {}
            rows["E4"] = row(pre.get("location_offset", -1) > 268435456
                             and rules("e4_big_after_cap", "oed_old") == []
                             and rules("e4_big_after_cap", "oed_new")
                             == ["OED001"], pre=pre,
                             old=rules("e4_big_after_cap", "oed_old"),
                             new=rules("e4_big_after_cap", "oed_new"))
            k_old = res["k1_func_key"]["oek_old"]
            k_new = res["k1_func_key"]["oek_new"]
            rows["K1"] = row("OEK001" not in (k_old.get("rules") or ["?"])
                             and "error" not in k_old
                             and "OEK001" in (k_new.get("rules") or [])
                             and k_new.get("keys") == ["owner"],
                             old=[k_old.get("rules"), k_old.get("keys")],
                             new=[k_new.get("rules"), k_new.get("keys")])
            rows["C1"] = row(rules("c1_graph_parent", "oed_old") == ["OED001"]
                             and rules("c1_graph_parent", "oed_new")
                             == ["OED001"],
                             old=rules("c1_graph_parent", "oed_old"),
                             new=rules("c1_graph_parent", "oed_new"))
            big = res["h4_big_honest"]["oed_new"]
            rows["T1"] = row(isinstance(big.get("seconds"), (int, float))
                             and big["seconds"] < 60
                             and big.get("maxrss_mb", 1e9) < 1024,
                             seconds=big.get("seconds"),
                             maxrss_mb=big.get("maxrss_mb"),
                             old_seconds=res["h4_big_honest"]["oed_old"]
                             .get("seconds"),
                             old_maxrss_mb=res["h4_big_honest"]["oed_old"]
                             .get("maxrss_mb"))
        if hub and hub.get("repos_read"):
            rows["Hb"] = row(hub["bands"]["256MiB-2GiB"] >= 10,
                             bands=hub["bands"],
                             repos_read=hub["repos_read"],
                             unique_blobs=hub.get(
                                 "unique_blobs_256MiB_2GiB"),
                             repos_with_band_file=hub.get(
                                 "repos_with_band_file"))
            summary["reported"]["hub"] = hub
        else:
            rows["Hb"] = {"held": False, "not_run": True}
        shutil.rmtree(work, ignore_errors=True)
    except Exception as exc:
        summary["error"] = "%s: %s" % (type(exc).__name__, exc)
    graded = [k for k in rows if not rows[k].get("not_run")]
    summary["held"] = sum(1 for k in graded if rows[k]["held"])
    summary["graded"] = len(graded)
    summary["held_rows"] = [k for k in rows if rows[k].get("held")]
    with open(os.path.join(a.out, "oed_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({k: summary[k] for k in ("held", "graded",
                                               "held_rows")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
