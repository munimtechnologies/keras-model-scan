#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Second real-file check: the variant-index routing fix.

Pre-registered in research/PREREG_STI_VARIANT_FIX.md before job
sti-variant-fix-v1 ran. patch_sti.py has already patched ./tree (live main)
and run_tests.py has run the whole suite. This script writes sharded
checkpoints of a tiny seeded GPT-2 with transformers and huggingface_hub (in
a child process), makes edited copies of one index, and scans those files
plus the public Hub index files downloaded in setup with the PATCHED tree.
Nothing here uses the network. The check never raises: an error goes into
the summary and the script exits 0.

Usage: fix_check.py --out OUT          (check)
       fix_check.py --write DIR        (child: writers only)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import traceback

CAND = re.compile(r"\.index(\.[A-Za-z0-9_\-]+)?\.json$", re.I)
STD = re.compile(r"\.index\.json$", re.I)
TREE = os.path.abspath("tree")
SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WRITER_CASES = ("tf_st", "tf_st_fp16", "tf_st_ema", "hub_st")
VARIANT_CASES = ("tf_st_fp16", "tf_st_ema")
NEW_TEST = "test_safetensors_index_variant"
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
        "tf_st_fp16": lambda d: make_model().save_pretrained(
            d, max_shard_size="100KB", variant="fp16"),
        "tf_st_ema": lambda d: make_model().save_pretrained(
            d, max_shard_size="100KB", variant="ema"),
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


def norm(findings):
    out = []
    for f in findings:
        out.append({"rule": str(fget(f, "rule")),
                    "severity": str(fget(f, "severity") or "").upper(),
                    "detail": str(fget(f, "detail") or
                                  fget(f, "message") or "")[:160]})
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


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"missing": "%s: %s" % (type(exc).__name__, exc)}


def kept_names(mfs, folder):
    files, _missing = mfs.expand_paths([folder])
    return [os.path.basename(f) for f in files]


def walk_rules(mfs, folder):
    files, _missing = mfs.expand_paths([folder])
    rules = []
    for f in files:
        rules.extend(x["rule"] for x in norm(mfs.scan_path(f)))
    return rules


# ---------------------------------------------------------------- check
def run(out):
    rows = []

    def add(rid, case, expected, result, got=None, reason=""):
        r = {"id": rid, "case": case, "expected": expected, "result": result}
        if got is not None:
            r["got"] = got
        if reason:
            r["reason"] = reason
        rows.append(r)

    reported = {}
    patch = load_json(os.path.join(out, "patched", "patch_report.json"))
    tests = load_json(os.path.join(out, "tests_summary.json"))
    reported["setup"] = {k: v for k, v in load_json(
        "setup_report.json").items() if not k.endswith("_tail")}

    # P1: the patch.
    pf = patch.get("files", {}) if isinstance(patch, dict) else {}
    p_ok = bool(patch.get("ok")) and all(
        pf.get(n, {}).get("ok") for n in (
            "model_file_scan.py", "safetensors_index_scan.py",
            "pyproject.toml", "test_attribution.py"))
    add("P1", "patch applies once, second pass no-op, nothing lost, no "
        "quoted .index.json left", "ok", "PASS" if p_ok else "FAIL",
        {"ok": patch.get("ok"), "error": patch.get("error"),
         "files": {n: {k: v for k, v in d.items() if k != "lost" or v}
                   for n, d in pf.items()}})
    if not patch.get("ok"):
        # Without the patch nothing else is about the fix.
        for rid in ("S1", "S2", "V1", "W1", "W3", "R1", "R3", "R4", "R5",
                    "H2", "H3", "H4", "H5", "H6", "H7"):
            add(rid, "", "", "NOT RUN", reason="patch did not apply")
        return reported, rows, {}

    # S1: whole suite (run_tests.py ran it before this script).
    s1 = (tests.get("ok") is True and not tests.get("failures")
          and not tests.get("errors") and (tests.get("ran") or 0) > 0)
    add("S1", "full unit-test suite on the patched tree",
        "ok; 0 failures; 0 errors", "PASS" if s1 else "FAIL",
        {k: tests.get(k) for k in ("ran", "failures", "errors", "skipped",
                                   "ok", "error", "missing")})

    # S2: the new test module on its own.
    try:
        p = subprocess.run([sys.executable, "-m", "unittest", "-v", NEW_TEST],
                           capture_output=True, text=True, timeout=600,
                           cwd=TREE)
        text = p.stdout + p.stderr
        m = re.search(r"Ran (\d+) tests?", text)
        ran = int(m.group(1)) if m else 0
        s2 = p.returncode == 0 and ran >= 9
        add("S2", "new test module alone", "exit 0; at least 9 tests",
            "PASS" if s2 else "FAIL",
            {"exit": p.returncode, "ran": ran, "tail": text[-1500:]})
    except Exception as exc:
        add("S2", "new test module alone", "", "NOT RUN",
            reason="%s: %s" % (type(exc).__name__, exc))

    sys.path.insert(0, TREE)
    import safetensors_index_scan as sti
    import model_file_scan as mfs
    try:
        with open(os.path.join(TREE, "pyproject.toml"), encoding="utf-8") \
                as fh:
            pv = re.search(r'(?m)^version\s*=\s*"([^"]+)"', fh.read())
            pv = pv.group(1) if pv else None
    except OSError as exc:
        pv = "error: %s" % exc
    got = {"mfs": getattr(mfs, "__version__", None),
           "sti": getattr(sti, "__version__", None), "pyproject": pv}
    add("V1", "versions", "mfs 0.12.0, sti 0.2.0, pyproject 0.12.0",
        "PASS" if got == {"mfs": "0.12.0", "sti": "0.2.0",
                          "pyproject": "0.12.0"} else "FAIL", got)

    # Writers in a child process.
    wdir = os.path.join(out, "files", "writers")
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--write",
                        wdir], capture_output=True, text=True, timeout=1800)
    reported["writer_exit"] = p.returncode
    reported["writer_tail"] = (p.stdout + p.stderr).strip()[-800:]
    wrep = load_json(os.path.join(wdir, "writers.json"))
    reported["writers"] = wrep
    idx = {}
    for case in WRITER_CASES:
        c = wrep.get("cases", {}).get(case)
        if not c or not c.get("ok"):
            continue
        d = os.path.join(wdir, case)
        found = [n for n in os.listdir(d) if CAND.search(n)]
        reported.setdefault("index_names", {})[case] = found
        if len(found) == 1:
            idx[case] = os.path.join(d, found[0])

    def honest_row(rid, case, want_name):
        if case not in idx:
            add(rid, case, "", "NOT RUN", reason="writer failed or no "
                "single index file: %r" % wrep.get("cases", {}).get(case))
            return
        path = idx[case]
        fs = norm(sti.scan_file(path))
        e_cli, _ = cli("safetensors_index_scan.py", path)
        e_mfs, _ = cli("model_file_scan.py", path)
        got = {"name": os.path.basename(path), "non_info": non_info(fs),
               "rules": sorted({f["rule"] for f in fs}),
               "sti_exit": e_cli, "mfs_exit": e_mfs,
               "mfs_route": mfs.route(path)}
        ok = (os.path.basename(path) == want_name and not got["non_info"]
              and got["rules"] == ["STI000"] and e_cli == 0 and e_mfs == 0
              and got["mfs_route"] == "sti")
        add(rid, case, "%s; only STI000; exits 0/0; route sti" % want_name,
            "PASS" if ok else "FAIL", got)

    honest_row("W1", "tf_st", "model.safetensors.index.json")
    honest_row("W3", "hub_st", "model.safetensors.index.json")

    # R1: both variant indexes are now routed, kept and walked.
    r1, r1_ok, r1_missing = {}, True, []
    want = {"tf_st_fp16": "model.safetensors.index.fp16.json",
            "tf_st_ema": "model.safetensors.index.ema.json"}
    for case in VARIANT_CASES:
        if case not in idx:
            r1_missing.append(case)
            continue
        v = idx[case]
        folder = os.path.dirname(v)
        alone = os.path.join(out, "files", "alone", case)
        os.makedirs(alone, exist_ok=True)
        shutil.copyfile(v, os.path.join(alone, os.path.basename(v)))
        fs = norm(sti.scan_file(v))
        sp = norm(sti.scan_path(folder))
        e_alone, _ = cli("model_file_scan.py", alone)
        e_folder, t_folder = cli("model_file_scan.py", folder)
        g = {"name": os.path.basename(v), "route": mfs.route(v),
             "kept": os.path.basename(v) in kept_names(mfs, folder),
             "sti_scan_path_rules": sorted({f["rule"] for f in sp}),
             "non_info": non_info(fs), "mfs_exit_alone": e_alone,
             "mfs_exit_writer_folder_reported": e_folder,
             "writer_folder_tail": t_folder[-200:]}
        ok = (g["name"] == want[case] and g["route"] == "sti" and g["kept"]
              and "STI000" in g["sti_scan_path_rules"] and not g["non_info"]
              and e_alone == 0)
        r1[case] = g
        r1_ok = r1_ok and ok
    if r1_missing == list(VARIANT_CASES):
        add("R1", "variant indexes", "", "NOT RUN",
            reason="no variant writer output")
    else:
        add("R1", "variant indexes routed, kept, walked, clean",
            "route sti; kept by expand_paths; scan_path STI000; only "
            "STI000; folder gate exit 0 on the index alone",
            "PASS" if (r1_ok and not r1_missing) else "FAIL",
            dict(r1, missing=r1_missing))

    # R3: '..' edited into the variant index, found by folder walks.
    v = idx.get("tf_st_fp16")
    if v:
        with open(v, encoding="utf-8") as fh:
            doc = json.load(fh)
        first = sorted(doc["weight_map"])[0]
        doc["weight_map"][first] = "../outside.safetensors"
        d = os.path.join(out, "files", "edited", "G2")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "model.safetensors.index.fp16.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        wr = walk_rules(mfs, d)
        sp = sorted({f["rule"] for f in norm(sti.scan_path(d))})
        e_dir, t_dir = cli("model_file_scan.py", d)
        ok = "STI002" in wr and "STI002" in sp and e_dir == 1
        add("R3", "'..' in a variant-named index, folder walks",
            "MFS walk STI002; sti.scan_path STI002; MFS folder exit 1",
            "PASS" if ok else "FAIL",
            {"walk_rules": wr, "sti_scan_path": sp, "mfs_dir_exit": e_dir,
             "tail": t_dir[-200:]})
    else:
        add("R3", "variant edit", "", "NOT RUN", reason="no fp16 index")

    # R4: the edited standard-name copies give the same rules as before.
    base = idx.get("tf_st") or idx.get("hub_st")
    if base:
        with open(base, encoding="utf-8") as fh:
            doc = json.load(fh)
        first = sorted(doc["weight_map"])[0]
        got, bad, paths = {}, [], {}
        for rid, value, rule, sev in EDITS:
            d = os.path.join(out, "files", "edited", rid)
            os.makedirs(d, exist_ok=True)
            new = json.loads(json.dumps(doc))
            new["weight_map"][first] = value
            path = os.path.join(d, "model.safetensors.index.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(new, fh, indent=2)
            paths[rid] = path
            g = non_info(norm(sti.scan_file(path)))
            got[rid] = g
            if g != [(rule, sev)]:
                bad.append(rid)
        e1, _ = cli("model_file_scan.py", paths["E1"])
        e6, _ = cli("model_file_scan.py", paths["E6"])
        got["E9"] = [e1, e6]
        if (e1, e6) != (1, 0):
            bad.append("E9")
        add("R4", "edited copies E1-E9 unchanged",
            "each exactly its one rule; MFS exit 1 on E1, 0 on E6",
            "PASS" if not bad else "FAIL", {"got": got, "bad": bad})
    else:
        add("R4", "edited copies", "", "NOT RUN", reason="no base index")

    # R5: routing over every writer file follows the name pattern.
    if idx:
        mism, holders_mism, n = [], [], 0
        for case in WRITER_CASES:
            d = os.path.join(wdir, case)
            if not os.path.isdir(d):
                continue
            for name in sorted(os.listdir(d)):
                path = os.path.join(d, name)
                n += 1
                cand = bool(CAND.search(name))
                if (mfs.route(path) == "sti") != cand:
                    mism.append([case, name, mfs.route(path)])
                has_wm = False
                if name.endswith(".json"):
                    try:
                        with open(path, encoding="utf-8") as fh:
                            has_wm = "weight_map" in json.load(fh)
                    except Exception:
                        has_wm = False
                if has_wm != cand:
                    holders_mism.append([case, name])
        add("R5", "writer files: route sti exactly for index names",
            "0 mismatches (route and weight_map holders)",
            "PASS" if n and not mism and not holders_mism else "FAIL",
            {"files": n, "route_mismatch": mism,
             "holder_mismatch": holders_mism})
    else:
        add("R5", "writer files", "", "NOT RUN", reason="no writer output")

    # Hub sample.
    hub = {}
    man = load_json(os.path.join("hub", "manifest.json"))
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
            fs = norm(sti.scan_file(path))
        except Exception as exc:
            fs = [{"rule": "SCAN_ERROR", "severity": "ERROR",
                   "detail": str(exc)[:160]}]
        try:
            kept = os.path.basename(path) in kept_names(
                mfs, os.path.dirname(path))
        except Exception as exc:
            kept = "error: %s" % exc
        per.append({"model": f["model"], "rfilename": f["rfilename"],
                    "variant": not STD.search(os.path.basename(path)),
                    "route": mfs.route(path), "kept": kept,
                    "max": max_sev(fs), "non_info": non_info(fs)})
    hub["files"] = per
    n = len(per)
    reported["hub_n_files"] = n
    reported["hub_n_models"] = len({r["model"] for r in per})
    rc = {}
    for r in per:
        for rule, sev in r["non_info"]:
            rc[rule + " " + sev] = rc.get(rule + " " + sev, 0) + 1
    reported["hub_rule_counts"] = rc
    if n < 50:
        add("H1", "gate: at least 50 Hub files", ">= 50", "NOT RUN",
            {"n": n}, "gate failed")
        for rid in ("H2", "H3", "H4", "H5", "H6", "H7"):
            add(rid, "Hub sample", "", "NOT RUN", reason="gate H1 failed")
        return reported, rows, hub
    brief = lambda rs: [[r["model"], r["rfilename"], r["non_info"]]
                        for r in rs][:15]
    high = [r for r in per if r["max"] >= SEV["HIGH"]]
    med = [r for r in per if r["max"] == SEV["MEDIUM"]]
    s5 = [r for r in per if any(x[0] == "STI005" for x in r["non_info"])]
    var = [r for r in per if r["variant"]]
    not_sti = [r for r in per if r["route"] != "sti"]
    not_kept = [r for r in per if r["kept"] is not True]
    add("H2", "Hub: no HIGH finding", "0 files",
        "PASS" if not high else "FAIL", {"n": len(high), "files": brief(high)})
    add("H3", "Hub: MEDIUM findings", "<= 2% of files",
        "PASS" if len(med) <= 0.02 * n else "FAIL",
        {"n": len(med), "of": n, "files": brief(med)})
    add("H4", "Hub: STI005", "<= 2% of files",
        "PASS" if len(s5) <= 0.02 * n else "FAIL",
        {"n": len(s5), "of": n, "files": brief(s5)})
    add("H5", "Hub: a variant-named index is present", ">= 1",
        "PASS" if var else "FAIL",
        {"n": len(var), "files": [[r["model"], r["rfilename"]]
                                  for r in var][:15]})
    add("H6", "Hub: every file routes to sti (standard and variant)",
        "0 files elsewhere", "PASS" if not not_sti else "FAIL",
        {"n": len(not_sti), "files": [[r["model"], r["rfilename"],
                                       r["route"]] for r in not_sti][:15]})
    add("H7", "Hub: every file kept by expand_paths of its folder",
        "0 files left out", "PASS" if not not_kept else "FAIL",
        {"n": len(not_kept), "files": [[r["model"], r["rfilename"],
                                        r["kept"]] for r in not_kept][:15]})
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
    with open(os.path.join(args.out, "fix_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    with open(os.path.join(args.out, "fix_hub_files.json"), "w",
              encoding="utf-8") as fh:
        json.dump(hub, fh, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"], json.dumps(r.get("got", ""),
                                               default=str)[:600],
              r.get("reason", ""))
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
