#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check of safetensors_index_scan and model-file-scan routing.

Pre-registered in research/PREREG_STI_REALFILE.md before job sti-realfile-v1
ran. Writes sharded checkpoints of a tiny seeded GPT-2 with transformers and
huggingface_hub (in a child process), makes edited copies of one index, and
scans those files plus the public Hub index files downloaded in setup with
our live main (./tree). Nothing here uses the network. The check never
raises: an error goes into the summary and the script exits 0.

Usage: sti_check.py --out OUT          (check)
       sti_check.py --write DIR        (child: writers only)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import traceback

CAND = re.compile(r"\.index(\.[A-Za-z0-9_\-]+)?\.json$", re.I)
STD = re.compile(r"\.index\.json$", re.I)
TREE = os.path.abspath("tree")
SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WRITER_CASES = ("tf_st", "tf_bin", "tf_st_fp16", "tf_bin_fp16", "hub_st")
EDITS = [
    ("E1", "../outside.safetensors", "STI002", "HIGH"),
    ("E2", "/tmp/outside.safetensors", "STI001", "HIGH"),
    ("E3", "C:\\outside.safetensors", "STI001", "HIGH"),
    ("E4", "https://example.invalid/x.safetensors", "STI004", "MEDIUM"),
    ("E5", "sub\\x.safetensors", "STI003", "MEDIUM"),
    ("E6", "sub/x.safetensors", "STI005", "LOW"),
    ("E7", 123, "STI007", "LOW"),
    ("E8", "a\x00b.safetensors", "STI006", "MEDIUM"),
]


# ---------------------------------------------------------------- writers
def writer_mode(dst):
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    rep = {"cases": {}}
    os.makedirs(dst, exist_ok=True)
    try:
        import torch
        import transformers
        import huggingface_hub
        rep["versions"] = {"torch": torch.__version__,
                           "transformers": transformers.__version__,
                           "huggingface_hub": huggingface_hub.__version__}
    except Exception as exc:
        rep["import_error"] = "%s: %s" % (type(exc).__name__, exc)
        with open(os.path.join(dst, "writers.json"), "w") as fh:
            json.dump(rep, fh, indent=1)
        return 0

    def make_model():
        torch.manual_seed(0)
        cfg = transformers.GPT2Config(n_layer=2, n_embd=64, n_head=2,
                                      vocab_size=1000, n_positions=64)
        return transformers.GPT2LMHeadModel(cfg)

    cases = {
        "tf_st": lambda d: make_model().save_pretrained(
            d, max_shard_size="100KB"),
        "tf_bin": lambda d: make_model().save_pretrained(
            d, max_shard_size="100KB", safe_serialization=False),
        "tf_st_fp16": lambda d: make_model().save_pretrained(
            d, max_shard_size="100KB", variant="fp16"),
        "tf_bin_fp16": lambda d: make_model().save_pretrained(
            d, max_shard_size="100KB", safe_serialization=False,
            variant="fp16"),
        "hub_st": lambda d: huggingface_hub.save_torch_state_dict(
            make_model().state_dict(), d, max_shard_size="100KB"),
    }
    for name in WRITER_CASES:
        d = os.path.join(dst, name)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        try:
            cases[name](d)
            rep["cases"][name] = {"ok": True, "files": sorted(os.listdir(d))}
        except Exception as exc:
            rep["cases"][name] = {"ok": False, "error": "%s: %s" % (
                type(exc).__name__, str(exc)[:400])}
    with open(os.path.join(dst, "writers.json"), "w") as fh:
        json.dump(rep, fh, indent=1)
    return 0


# ---------------------------------------------------------------- helpers
def fget(f, key):
    if isinstance(f, dict):
        return f.get(key)
    return getattr(f, key, None)


def sti_findings(sti, path):
    out = []
    for f in sti.scan_file(path):
        out.append({"rule": fget(f, "rule"),
                    "severity": str(fget(f, "severity") or "").upper(),
                    "location": str(fget(f, "location") or "")[:200],
                    "detail": str(fget(f, "detail") or "")[:160]})
    return out


def non_info(fs):
    return sorted({(f["rule"], f["severity"]) for f in fs
                   if f["severity"] != "INFO"})


def max_sev(fs):
    return max([SEV.get(f["severity"], -1) for f in fs] or [-1])


def cli(script, path, extra=()):
    try:
        p = subprocess.run([sys.executable, os.path.join(TREE, script), path]
                           + list(extra), capture_output=True, text=True,
                           timeout=600, cwd=TREE)
        return p.returncode, (p.stdout + p.stderr).strip()[-400:]
    except Exception as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)


def safetensors_tensor_bytes(path):
    with open(path, "rb") as fh:
        n = struct.unpack("<Q", fh.read(8))[0]
        hdr = json.loads(fh.read(n))
    return sum(v["data_offsets"][1] - v["data_offsets"][0]
               for k, v in hdr.items() if k != "__metadata__")


def describe_index(path):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    wm = doc.get("weight_map") if isinstance(doc, dict) else None
    d = {"name": os.path.basename(path),
         "keys": sorted(doc) if isinstance(doc, dict) else None,
         "metadata": doc.get("metadata") if isinstance(doc, dict) else None,
         "entries": len(wm) if isinstance(wm, dict) else None,
         "shards": sorted(set(wm.values())) if isinstance(wm, dict) else None}
    folder = os.path.dirname(path)
    if d["shards"] and all(s.endswith(".safetensors") for s in d["shards"]):
        try:
            d["tensor_bytes"] = sum(safetensors_tensor_bytes(
                os.path.join(folder, s)) for s in d["shards"])
        except Exception as exc:
            d["tensor_bytes"] = "error: %s" % exc
    return d


# ---------------------------------------------------------------- check
def run(out):
    sys.path.insert(0, TREE)
    import safetensors_index_scan as sti
    import model_file_scan as mfs
    reported = {"sti_version": getattr(sti, "__version__", None),
                "mfs_version": getattr(mfs, "__version__", None)}
    try:
        with open("setup_report.json", encoding="utf-8") as fh:
            setup = json.load(fh)
        reported["setup"] = {k: v for k, v in setup.items()
                             if not k.endswith("_tail")}
    except Exception as exc:
        reported["setup"] = "missing: %s" % exc

    rows = []

    def add(rid, case, expected, result, got=None, reason=""):
        r = {"id": rid, "case": case, "expected": expected, "result": result}
        if got is not None:
            r["got"] = got
        if reason:
            r["reason"] = reason
        rows.append(r)

    # Writers in a child process.
    wdir = os.path.join(out, "files", "writers")
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--write",
                        wdir], capture_output=True, text=True, timeout=1800)
    reported["writer_exit"] = p.returncode
    reported["writer_tail"] = (p.stdout + p.stderr).strip()[-1200:]
    try:
        with open(os.path.join(wdir, "writers.json")) as fh:
            wrep = json.load(fh)
    except Exception as exc:
        wrep = {"cases": {}, "error": "no writers.json: %s" % exc}
    reported["writers"] = wrep

    idx = {}      # case -> index path
    for case in WRITER_CASES:
        c = wrep.get("cases", {}).get(case)
        if not c or not c.get("ok"):
            continue
        d = os.path.join(wdir, case)
        found = [n for n in os.listdir(d) if CAND.search(n)]
        reported.setdefault("index_names", {})[case] = found
        if len(found) == 1:
            idx[case] = os.path.join(d, found[0])
    descr = {}
    for case, path in idx.items():
        try:
            descr[case] = describe_index(path)
        except Exception as exc:
            descr[case] = {"error": str(exc)}
    reported["index_descr"] = {c: {k: v for k, v in d.items()
                                   if k != "shards"} for c, d in descr.items()}

    def honest_row(rid, case, want_name):
        if case not in idx:
            add(rid, case, "", "NOT RUN", reason="writer failed or no "
                "single index file: %r" % wrep.get("cases", {}).get(case))
            return
        path = idx[case]
        fs = sti_findings(sti, path)
        e_cli, _ = cli("safetensors_index_scan.py", path)
        e_mfs, tail = cli("model_file_scan.py", path)
        got = {"name": os.path.basename(path), "non_info": non_info(fs),
               "rules": sorted({f["rule"] for f in fs}),
               "sti_exit": e_cli, "mfs_exit": e_mfs, "mfs_route":
               mfs.route(path)}
        ok = (os.path.basename(path) == want_name and not got["non_info"]
              and got["rules"] == ["STI000"] and e_cli == 0 and e_mfs == 0)
        add(rid, case, "%s; only STI000 INFO; exits 0/0" % want_name,
            "PASS" if ok else "FAIL", got)

    honest_row("W1", "tf_st", "model.safetensors.index.json")
    honest_row("W2", "tf_bin", "pytorch_model.bin.index.json")
    honest_row("W3", "hub_st", "model.safetensors.index.json")

    # W4 / W5 / G1 on the variant index.
    v = idx.get("tf_st_fp16")
    if v:
        shards = descr.get("tf_st_fp16", {}).get("shards") or []
        pat = re.compile(r"^model\.fp16-\d{5}-of-\d{5}\.safetensors$")
        add("W4", "tf_st_fp16 index name and shard names",
            "model.safetensors.index.fp16.json; model.fp16-0000k-of-0000N",
            "PASS" if (os.path.basename(v) ==
                       "model.safetensors.index.fp16.json" and shards and
                       all(pat.match(s) for s in shards)) else "FAIL",
            {"name": os.path.basename(v), "shards": shards[:4],
             "n_shards": len(shards)})
        fs = sti_findings(sti, v)
        add("W5", "explicit sti.scan_file on the variant index",
            "only STI000 INFO",
            "PASS" if sorted({f["rule"] for f in fs}) == ["STI000"]
            and not non_info(fs) else "FAIL", non_info(fs) or
            sorted({f["rule"] for f in fs}))
        folder = os.path.dirname(v)
        files, _missing = mfs.expand_paths([folder])
        kept = [os.path.basename(f) for f in files]
        sp = [fget(f, "location") for f in sti.scan_path(folder)]
        hit = [str(x) for x in sp if os.path.basename(v) in str(x)]
        route = mfs.route(v)
        try:
            kinds = mfs.route_kinds(v)
        except Exception as exc:
            kinds = "error: %s" % exc
        add("G1", "the variant index is missed by routing and walks",
            "route != sti; not kept by expand_paths; scan_path(dir) silent",
            "PASS" if (route != "sti" and os.path.basename(v) not in kept
                       and not hit) else "FAIL",
            {"route": route, "route_kinds": kinds, "kept": kept,
             "scan_path_hits": hit[:3]})
    else:
        for rid in ("W4", "W5", "G1"):
            add(rid, "tf_st_fp16", "", "NOT RUN",
                reason="variant writer failed: %r"
                % wrep.get("cases", {}).get("tf_st_fp16"))

    # Edited copies of the tf_st index (fallback hub_st).
    base = idx.get("tf_st") or idx.get("hub_st")
    edir = os.path.join(out, "files", "edited")
    edited = {}
    if base:
        with open(base, encoding="utf-8") as fh:
            doc = json.load(fh)
        first = sorted(doc["weight_map"])[0]
        for rid, value, rule, sev in EDITS:
            d = os.path.join(edir, rid)
            os.makedirs(d, exist_ok=True)
            new = json.loads(json.dumps(doc))
            new["weight_map"][first] = value
            path = os.path.join(d, "model.safetensors.index.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(new, fh, indent=2)
            edited[rid] = path
            fs = sti_findings(sti, path)
            got = non_info(fs)
            add(rid, "edited value %r" % (value,), "exactly %s %s"
                % (rule, sev), "PASS" if got == [(rule, sev)] else "FAIL",
                got)
        e1, t1 = cli("model_file_scan.py", edited["E1"])
        e6, t6 = cli("model_file_scan.py", edited["E6"])
        add("E9", "model-file-scan default gate on E1 and E6",
            "exit 1 on E1, exit 0 on E6",
            "PASS" if (e1, e6) == (1, 0) else "FAIL",
            {"E1": e1, "E6": e6, "E1_tail": t1[-200:], "E6_tail": t6[-200:]})
    else:
        for rid, *_ in EDITS:
            add(rid, "edited copy", "", "NOT RUN", reason="no base index")
        add("E9", "edited copy", "", "NOT RUN", reason="no base index")

    # G2: the '..' edit inside a variant-named index.
    if v:
        with open(v, encoding="utf-8") as fh:
            doc = json.load(fh)
        first = sorted(doc["weight_map"])[0]
        doc["weight_map"][first] = "../outside.safetensors"
        d = os.path.join(edir, "G2")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "model.safetensors.index.fp16.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        explicit = non_info(sti_findings(sti, path))
        files, _missing = mfs.expand_paths([d])
        walk = []
        for f in files:
            for x in mfs.scan_path(f):
                walk.append(str(fget(x, "rule")))
        e_dir, t_dir = cli("model_file_scan.py", d)
        sti_walk = [r for r in walk if r.startswith("STI")]
        add("G2", "edited '..' in a variant-named index",
            "explicit scan_file STI002 HIGH; MFS dir walk no STI finding",
            "PASS" if (("STI002", "HIGH") in explicit and not sti_walk)
            else "FAIL", {"explicit": explicit, "walk_files": [
                os.path.basename(f) for f in files], "walk_rules": walk,
                "mfs_dir_exit": e_dir})
    else:
        add("G2", "variant edit", "", "NOT RUN", reason="no variant index")

    # C1: candidate pattern over every writer output.
    if idx:
        matched, holders, missed_or_extra = [], [], []
        for case in WRITER_CASES:
            d = os.path.join(wdir, case)
            if not os.path.isdir(d):
                continue
            for n in sorted(os.listdir(d)):
                path = os.path.join(d, n)
                has_wm = False
                if n.endswith(".json"):
                    try:
                        with open(path, encoding="utf-8") as fh:
                            has_wm = "weight_map" in json.load(fh)
                    except Exception:
                        has_wm = False
                m = bool(CAND.search(n))
                if m:
                    matched.append(case + "/" + n)
                if has_wm:
                    holders.append(case + "/" + n)
                if m != has_wm:
                    missed_or_extra.append(case + "/" + n)
        add("C1", "candidate name pattern on every writer file",
            "matches exactly the files holding a weight_map",
            "PASS" if matched and not missed_or_extra else "FAIL",
            {"matched": matched, "mismatch": missed_or_extra})
    else:
        add("C1", "writer files", "", "NOT RUN", reason="no writer output")

    # Hub sample.
    hub = {}
    try:
        with open(os.path.join("hub", "manifest.json")) as fh:
            man = json.load(fh)
    except Exception as exc:
        man = {"files": [], "error": str(exc)}
    reported["hub_manifest"] = {k: v for k, v in man.items()
                                if k not in ("files", "skipped_gated",
                                             "errors")}
    reported["hub_skipped_gated"] = len(man.get("skipped_gated", []))
    reported["hub_errors"] = man.get("errors", [])[:10]
    oks = [f for f in man.get("files", []) if f.get("status") == "ok"]
    reported["hub_download_errors"] = [
        [f["model"], f["rfilename"], f["status"][:80]]
        for f in man.get("files", []) if f.get("status") != "ok"][:20]
    per = []
    for f in oks:
        path = f["path"]
        try:
            fs = sti_findings(sti, path)
        except Exception as exc:
            fs = [{"rule": "SCAN_ERROR", "severity": "ERROR",
                   "location": "", "detail": str(exc)[:160]}]
        rec = {"model": f["model"], "rfilename": f["rfilename"],
               "bytes": f.get("bytes"),
               "variant": not STD.search(os.path.basename(path)),
               "route": mfs.route(path), "max": max_sev(fs),
               "non_info": non_info(fs),
               "examples": [[x["rule"], x["detail"][:120]] for x in fs
                            if x["severity"] != "INFO"][:3]}
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            wm = doc.get("weight_map") if isinstance(doc, dict) else None
            md = doc.get("metadata") if isinstance(doc, dict) else None
            rec["has_weight_map"] = isinstance(wm, dict)
            rec["entries"] = len(wm) if isinstance(wm, dict) else None
            rec["metadata_keys"] = sorted(md) if isinstance(md, dict) else None
        except Exception as exc:
            rec["parse_error"] = str(exc)[:120]
        per.append(rec)
    hub["files"] = per
    n = len(per)
    reported["hub_n_files"] = n
    reported["hub_n_models"] = len({r["model"] for r in per})
    if n < 50:
        add("H1", "gate: at least 50 Hub files", ">= 50", "NOT RUN",
            {"n": n}, "gate failed")
        for rid in ("H2", "H3", "H4", "H5", "H6"):
            add(rid, "Hub sample", "", "NOT RUN", reason="gate H1 failed")
    else:
        high = [r for r in per if r["max"] >= SEV["HIGH"]]
        med = [r for r in per if r["max"] == SEV["MEDIUM"]]
        s5 = [r for r in per if any(x[0] == "STI005" for x in r["non_info"])]
        var = [r for r in per if r["variant"]]
        bad_route = [r for r in per if (r["route"] == "sti") == r["variant"]]
        brief = lambda rs: [[r["model"], r["rfilename"], r["non_info"]]
                            for r in rs][:15]
        add("H2", "Hub sample: no HIGH finding", "0 files",
            "PASS" if not high else "FAIL",
            {"n": len(high), "files": brief(high)})
        add("H3", "Hub sample: MEDIUM findings", "<= 2% of files",
            "PASS" if len(med) <= 0.02 * n else "FAIL",
            {"n": len(med), "of": n, "files": brief(med)})
        add("H4", "Hub sample: STI005 sub-folder shards", "<= 2% of files",
            "PASS" if len(s5) <= 0.02 * n else "FAIL",
            {"n": len(s5), "of": n, "files": brief(s5)})
        add("H5", "Hub sample: a variant-named index is present", ">= 1",
            "PASS" if var else "FAIL",
            {"n": len(var), "files": [[r["model"], r["rfilename"]]
                                      for r in var][:15]})
        add("H6", "Hub sample: routing by name",
            "*.index.json -> sti; variant names -> not sti",
            "PASS" if not bad_route else "FAIL",
            {"mismatches": [[r["model"], r["rfilename"], r["route"]]
                            for r in bad_route][:15]})
        reported["hub_no_weight_map"] = [
            [r["model"], r["rfilename"]] for r in per
            if not r.get("has_weight_map")][:20]
        reported["hub_no_weight_map_n"] = sum(
            1 for r in per if not r.get("has_weight_map"))
        mk = {}
        for r in per:
            key = ",".join(r.get("metadata_keys") or ["<none>"])
            mk[key] = mk.get(key, 0) + 1
        reported["hub_metadata_keys"] = mk
        rc = {}
        for r in per:
            for rule, sev in r["non_info"]:
                rc[rule + " " + sev] = rc.get(rule + " " + sev, 0) + 1
        reported["hub_rule_counts"] = rc
    return reported, rows, hub


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--write")
    args = ap.parse_args(argv)
    if args.write:
        return writer_mode(args.write)
    os.makedirs(args.out, exist_ok=True)
    for name in ("setup_report.json", os.path.join("hub", "manifest.json")):
        if os.path.exists(name):
            shutil.copyfile(name, os.path.join(
                args.out, os.path.basename(name)))
    try:
        reported, rows, hub = run(args.out)
        error = ""
    except Exception:
        reported, rows, hub = {}, [], {}
        error = traceback.format_exc()[-3000:]
        print(error, file=sys.stderr)
    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    summary = {"check_version": 1, "error": error,
               "held": sum(1 for r in graded if r["result"] == "PASS"),
               "graded": len(graded),
               "not_run": [r["id"] for r in rows if r["result"] == "NOT RUN"],
               "reported": reported, "rows": rows}
    with open(os.path.join(args.out, "sti_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    with open(os.path.join(args.out, "sti_hub_files.json"), "w",
              encoding="utf-8") as fh:
        json.dump(hub, fh, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"], json.dumps(r.get("got", ""),
                                               default=str)[:600],
              r.get("reason", ""))
    print("reported:", json.dumps(reported, default=str)[:3000])
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
