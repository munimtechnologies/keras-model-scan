#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Graded check for nemo_container_scan 0.2.0 (pre-registered in
research/PREREG_NEMO_BIG.md). Rows:

  P1  the patch applied cleanly (scanner, old test's version pin, doc)
  S1  the whole keras-model-scan suite passes with the patched files
  W1  torch writes model_weights.ckpt as a zip (PK\\x03\\x04) for w_small,
      w_big and w_big_gz; each tar holds ./model_config.yaml and
      ./model_weights.ckpt; w_big's checkpoint is larger than 256 MiB
  R1  both published files downloaded at the pinned size; each has a member
      ending in model_weights.ckpt that starts with PK\\x03\\x04; titanet's is
      at most 256 MiB, parakeet-110m's is larger
  N1  w_small:          0.1.0 {NEMO010}  0.2.0 {NEMO010}
  N2  w_big:            0.1.0 {}         0.2.0 {NEMO010}
  N3  w_big_gz:         0.1.0 {}         0.2.0 {NEMO010}
  N4  titanet_large:    0.1.0 {NEMO010}  0.2.0 {NEMO010}
  N5  parakeet-110m:    0.1.0 {}         0.2.0 {NEMO010}
  M1  0.2.0 on parakeet-110m (459 MB): peak RSS under 200 MB
  T1  0.2.0 on parakeet-110m: under 60 s              (reported, not gating)
  Hb  Hub census: at least 20 .nemo files in the top 100 nemo-tagged repos,
      and at least half of them larger than 256 MiB    (not gating)
  Reported only: w_legacy_big (legacy torch.save): predicted 0.1.0 {},
  0.2.0 {NEMO030}; 0.1.0 peak RSS on parakeet-110m.

Writes OUT/nemo_summary.json and OUT/writer_report.json. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = "nemo_container_scan.py"
CAP = 268435456
ZIP_HEAD = "504b0304"


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
                              timeout=1800)
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
    work = os.path.abspath("files")
    try:
        patch = load(os.path.join(a.out, "patch_report.json")) or {}
        tests = load(os.path.join(a.out, "tests_summary.json")) or {}
        real = load("real_report.json") or {}
        hub = load("hub_nemo.json")
        summary["reported"]["fetch"] = load("fetch_report.json")
        summary["reported"]["setup"] = load("setup_report.json")
        summary["reported"]["real"] = real
        rows["P1"] = row(patch.get("ok"), files=patch.get("files"))
        rows["S1"] = row(tests.get("ok") and not tests.get("failures")
                         and not tests.get("errors"),
                         ran=tests.get("ran"), failures=tests.get("failures"),
                         errors=tests.get("errors"))

        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)
        proc = subprocess.run([sys.executable,
                               os.path.join(HERE, "write_nemo.py"), work],
                              capture_output=True, text=True, timeout=3600)
        wr = load(os.path.join(work, "writer_report.json")) or {
            "ok": False, "stderr": proc.stderr[-2000:]}
        with open(os.path.join(a.out, "writer_report.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(wr, fh, indent=1)
        cases = wr.get("cases") or {}

        def w_ok(c):
            d = cases.get(c) or {}
            names = d.get("members") or []
            return (d.get("weights_head") == ZIP_HEAD
                    and "./model_config.yaml" in names
                    and "./model_weights.ckpt" in names)
        rows["W1"] = row(wr.get("ok") and all(w_ok(c) for c in
                                              ("w_small", "w_big",
                                               "w_big_gz"))
                         and (cases.get("w_big") or {}).get(
                             "weights_bytes", 0) > CAP,
                         torch=wr.get("torch"),
                         cases={c: {k: v for k, v in d.items()
                                    if k != "members"}
                                for c, d in cases.items()})
        ti = real.get("titanet_large") or {}
        pk = real.get("parakeet_tdt_ctc_110m") or {}
        rows["R1"] = row(ti.get("size_ok") and pk.get("size_ok")
                         and ti.get("weights_head") == ZIP_HEAD
                         and pk.get("weights_head") == ZIP_HEAD
                         and 0 < ti.get("weights_bytes", 0) <= CAP
                         and pk.get("weights_bytes", 0) > CAP,
                         titanet={k: ti.get(k) for k in (
                             "bytes", "compression", "weights_member",
                             "weights_bytes", "weights_head", "sha256")},
                         parakeet={k: pk.get(k) for k in (
                             "bytes", "compression", "weights_member",
                             "weights_bytes", "weights_head", "sha256")})

        targets = {"w_small": os.path.join(work, "w_small.nemo"),
                   "w_big": os.path.join(work, "w_big.nemo"),
                   "w_big_gz": os.path.join(work, "w_big_gz.nemo"),
                   "w_legacy_big": os.path.join(work, "w_legacy_big.nemo"),
                   "titanet_large": os.path.abspath(
                       os.path.join("real", "titanet_large.nemo")),
                   "parakeet_tdt_ctc_110m": os.path.abspath(
                       os.path.join("real", "parakeet_tdt_ctc_110m.nemo"))}
        res = {}
        if patch.get("ok"):
            for case, path in targets.items():
                if not os.path.isfile(path):
                    res[case] = {"missing": True}
                    continue
                res[case] = {"old": scan(os.path.join(a.orig, MOD), path),
                             "new": scan(os.path.join(a.tree, MOD), path)}
        summary["reported"]["scans"] = res
        summary["reported"]["scan_errors"] = sorted(
            "%s/%s" % (c, w) for c, d in res.items()
            for w, v in d.items() if isinstance(v, dict) and "error" in v)

        def rules(case, which):
            return ((res.get(case) or {}).get(which) or {}).get("rules")

        for r, case, old, new in (
                ("N1", "w_small", ["NEMO010"], ["NEMO010"]),
                ("N2", "w_big", [], ["NEMO010"]),
                ("N3", "w_big_gz", [], ["NEMO010"]),
                ("N4", "titanet_large", ["NEMO010"], ["NEMO010"]),
                ("N5", "parakeet_tdt_ctc_110m", [], ["NEMO010"])):
            if not patch.get("ok"):
                rows[r] = {"held": False, "not_run": True}
                continue
            rows[r] = row(rules(case, "old") == old
                          and rules(case, "new") == new,
                          old=rules(case, "old"), new=rules(case, "new"))
        pk_new = (res.get("parakeet_tdt_ctc_110m") or {}).get("new") or {}
        pk_old = (res.get("parakeet_tdt_ctc_110m") or {}).get("old") or {}
        if patch.get("ok"):
            rows["M1"] = row(isinstance(pk_new.get("maxrss_mb"), float)
                             and "error" not in pk_new
                             and pk_new["maxrss_mb"] < 200,
                             new_maxrss_mb=pk_new.get("maxrss_mb"),
                             old_maxrss_mb=pk_old.get("maxrss_mb"))
            rows["T1"] = row(isinstance(pk_new.get("seconds"), (int, float))
                             and pk_new["seconds"] < 60,
                             new_seconds=pk_new.get("seconds"),
                             old_seconds=pk_old.get("seconds"))
        else:
            rows["M1"] = {"held": False, "not_run": True}
            rows["T1"] = {"held": False, "not_run": True}
        summary["reported"]["legacy"] = {
            "predicted": {"old": [], "new": ["NEMO030"]},
            "old": rules("w_legacy_big", "old"),
            "new": rules("w_legacy_big", "new"),
            "writer_error": wr.get("legacy_error")}
        if hub and hub.get("repos_read"):
            rows["Hb"] = row(hub.get("nemo_files", 0) >= 20
                             and (hub.get("share_over_256MiB") or 0) >= 0.5,
                             **{k: v for k, v in hub.items() if k != "files"})
            summary["reported"]["hub_files"] = hub.get("files")
        else:
            rows["Hb"] = {"held": False, "not_run": True}
    except Exception as exc:
        summary["error"] = "%s: %s" % (type(exc).__name__, exc)
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree("real", ignore_errors=True)
    graded = [k for k in rows if not rows[k].get("not_run")]
    summary["held"] = sum(1 for k in graded if rows[k]["held"])
    summary["graded"] = len(graded)
    summary["held_rows"] = [k for k in rows if rows[k].get("held")]
    release = ("P1", "S1", "W1", "R1", "N1", "N2", "N3", "N4", "N5", "M1")
    summary["release_rule_holds"] = all(
        (rows.get(k) or {}).get("held") for k in release)
    with open(os.path.join(a.out, "nemo_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({k: summary[k] for k in ("held", "graded", "held_rows",
                                               "release_rule_holds")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
