#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check of job pkl-joblib-v1: pickle_model_scan 0.4.0 walks
joblib.dump files to the end.

Pre-registered in research/PREREG_PKL_JOBLIB.md before the job ran. The
honest files and their ground truth come from write_jl.py (run before this
step). Each scanner version (the unpatched tree, the patched tree) runs in
its own child process. Published Hub files come from setup (fetch_jl.py).
The run step has no network. Nothing is loaded, unpickled or executed by
this script: Hub files are only read as bytes. Never raises: errors go into
the summary and it exits 0.

Usage: jl_check.py --out OUT --orig ORIG_TREE --tree TREE
       jl_check.py --scan TREE IN_JSON OUT_JSON      (child)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import bz2
import collections
import dataclasses
import gzip
import json
import lzma
import os
import pickletools
import re
import subprocess
import sys
import time
import traceback
import zlib

SELF = os.path.abspath(__file__)
SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MARKER = b"NumpyArrayWrapper"
ROW_IDS = ("V1", "S1", "S2", "S3", "W0", "C1", "C2", "N1", "G1", "H1", "H2",
           "H3", "H4", "H5", "D1")
RELEASE_ROWS = ("P1", "V1", "S1", "S2", "S3", "W0", "C1", "C2", "N1", "G1",
                "H1", "H2", "H3", "H4", "D1")


# ---------------------------------------------------------------- helpers
def inflate(data):
    """Undo joblib's stdlib compressors, as pickle_model_scan.scan_blob does."""
    steps = []
    for _ in range(4):
        try:
            if data[:2] == b"\x1f\x8b":
                data, s = gzip.decompress(data), "gzip"
            elif data[:3] == b"BZh":
                data, s = bz2.decompress(data), "bz2"
            elif data[:6] == b"\xfd7zXZ\x00":
                data, s = lzma.decompress(data), "xz"
            elif data[:2] == b"\x5d\x00":
                data, s = lzma.decompress(data, format=lzma.FORMAT_ALONE), \
                    "lzma"
            elif data[:1] == b"\x78":
                data, s = zlib.decompress(data), "zlib"
            else:
                break
        except Exception:
            break
        steps.append(s)
    return data, steps


def baseline_stop(data):
    """Where a plain pickletools walk from byte 0 ends (what 0.2.1 read)."""
    last = None
    try:
        for op, _arg, pos in pickletools.genops(data):
            last = pos
            if op.name == "STOP":
                return {"kind": "STOP", "pos": pos}
    except Exception as exc:
        return {"kind": "error", "pos": last,
                "msg": "%s: %s" % (type(exc).__name__, str(exc)[:120])}
    return {"kind": "end", "pos": last}


def as_dict(f):
    if isinstance(f, dict):
        return f
    if hasattr(f, "as_dict"):
        return f.as_dict()
    if dataclasses.is_dataclass(f):
        return dataclasses.asdict(f)
    return dict(vars(f))


def pairs_of(findings):
    out = set()
    for f in findings or []:
        d = as_dict(f)
        out.add((str(d.get("rule")), str(d.get("severity", "")).upper()))
    return sorted(out)


def worst(pairs):
    if isinstance(pairs, str):
        return 99
    return max([SEV.get(s, 0) for _r, s in pairs] or [0])


def rules(pairs):
    return set() if isinstance(pairs, str) else {r for r, _s in pairs}


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"missing": "%s: %s" % (type(exc).__name__, exc)}


# ---------------------------------------------------------------- child
def child_scan(tree, in_json, out_json):
    res = {"versions": {}, "files": {}, "walk": {}, "base": {}, "secs": {},
           "error": ""}
    try:
        tree = os.path.abspath(tree)
        sys.path.insert(0, tree)
        os.chdir(tree)
        import model_file_scan as mfs
        import pickle_model_scan as pms
        res["versions"] = {"mfs": mfs.__version__, "pms": pms.__version__,
                           "pms_file": os.path.abspath(pms.__file__)}
        pyv = re.search(r'(?m)^version\s*=\s*"([^"]+)"',
                        open(os.path.join(tree, "pyproject.toml"),
                             encoding="utf-8").read())
        res["versions"]["pyproject"] = pyv.group(1) if pyv else None
        has_walk = hasattr(pms, "pickle_walk")
        with open(in_json, encoding="utf-8") as fh:
            paths = json.load(fh)
        for path in paths:
            t0 = time.time()
            try:
                res["files"][path] = pairs_of(mfs.scan_path(path))
            except Exception as exc:
                res["files"][path] = "error: %s: %s" % (type(exc).__name__,
                                                        str(exc)[:200])
            res["secs"][path] = round(time.time() - t0, 3)
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
                data, steps = inflate(raw)
                res["base"][path] = dict(baseline_stop(data), length=len(data),
                                         inflated=steps,
                                         joblib_mode=MARKER in data,
                                         lz4=raw[:4] == b"\x04\x22\x4d\x18")
                if has_walk:
                    res["walk"][path] = pms.pickle_walk(data, path)
            except Exception as exc:
                res["walk"][path] = "error: %s: %s" % (type(exc).__name__,
                                                       str(exc)[:200])
    except Exception:
        res["error"] = traceback.format_exc()[-2000:]
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    return 0


def run_scan(tree, files, tag, work):
    in_json = os.path.join(work, "scan_in_%s.json" % tag)
    out_json = os.path.join(work, "scan_out_%s.json" % tag)
    with open(in_json, "w", encoding="utf-8") as fh:
        json.dump(files, fh)
    p = subprocess.run([sys.executable, SELF, "--scan", tree, in_json,
                        out_json], capture_output=True, text=True,
                       timeout=5400, cwd=work)
    try:
        with open(out_json, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"error": "no output (%s); exit %s; %s" % (
            exc, p.returncode, (p.stdout + p.stderr)[-800:])}


def run_module(tree, module):
    p = subprocess.run([sys.executable, "-m", "unittest", "-v", module],
                       cwd=tree, capture_output=True, text=True, timeout=600)
    m = re.search(r"Ran (\d+) tests?", p.stderr)
    return {"exit": p.returncode, "ran": int(m.group(1)) if m else 0,
            "tail": p.stderr[-900:]}


def walk_complete(w):
    return (isinstance(w, dict) and w.get("stop") is not None
            and w["stop"] == w["length"] - 1)


def walk_brief(w):
    if not isinstance(w, dict):
        return w
    return {k: w.get(k) for k in ("stop", "length", "joblib_arrays",
                                  "nested_pickles", "unresolved",
                                  "symbolic_stack_lost", "joblib_mode",
                                  "rules")}


# ---------------------------------------------------------------- grading
def run(args):
    reported = {"fetch": read_json("fetch_report.json")}
    rows = []

    def add(rid, case, expected, result, got=None, reason=""):
        r = {"id": rid, "case": case, "expected": expected, "result": result}
        if got is not None:
            r["got"] = got
        if reason:
            r["reason"] = reason
        rows.append(r)

    pr = read_json(os.path.join(args.out, "patch_report.json"))
    add("P1", "patch applies once, second pass no-op, nothing lost", "ok",
        "PASS" if pr.get("ok") else "FAIL", pr)
    if not pr.get("ok"):
        for rid in ROW_IDS:
            add(rid, "", "", "NOT RUN", reason="P1 failed")
        return reported, rows

    tree = os.path.abspath(args.tree)
    orig = os.path.abspath(args.orig)
    work = os.path.abspath(os.path.join(args.out, "work"))
    os.makedirs(work, exist_ok=True)

    ts = read_json(os.path.join(args.out, "tests_summary.json"))
    if "missing" in ts:
        add("S1", "full suite", "", "NOT RUN", reason=ts["missing"])
    else:
        add("S1", "full unit-test suite on the patched tree",
            "0 failures, 0 errors", "PASS" if ts.get("ok") else "FAIL",
            {k: ts.get(k) for k in ("ran", "failures", "errors", "skipped",
                                    "error")})
    for rid, module, want in (("S2", "test_pickle_model_scan_joblib", 16),
                              ("S3", "test_pickle_model_scan_memo", 11)):
        try:
            r = run_module(tree, module)
            add(rid, "%s alone" % module, "exit 0; %d tests" % want,
                "PASS" if r["exit"] == 0 and r["ran"] == want else "FAIL", r)
        except Exception as exc:
            add(rid, module, "", "NOT RUN", reason=str(exc))

    # Honest written files and their ground truth.
    gt = read_json(os.path.join(args.out, "work", "ground_truth.json"))
    reported["writers"] = {"versions": gt.get("versions"),
                           "errors": gt.get("errors")}
    planned = gt.get("planned") or []
    gfiles = gt.get("files") or {}
    files_dir = os.path.join(args.out, "files", "written")
    written = {}
    w0 = {}
    for name in planned:
        e = gfiles.get(name) or {"error": "not written"}
        path = os.path.join(files_dir, name)
        ok = ("error" not in e and os.path.isfile(path)
              and len(e.get("distinct_imports") or []) >= 3
              and (e.get("kind") != "joblib" or
                   "joblib.numpy_pickle NumpyArrayWrapper"
                   in (e.get("distinct_imports") or [])))
        w0[name] = {"ok": ok, "kind": e.get("kind"), "bytes": e.get("bytes"),
                    "magic": e.get("magic"),
                    "distinct": len(e.get("distinct_imports") or []),
                    "error": (e.get("error") or "")[-400:]}
        if "error" not in e and os.path.isfile(path):
            written[name] = path
    add("W0", "every planned honest file written; ground truth has >= 3 "
        "distinct imports; every .joblib file uses NumpyArrayWrapper",
        "all %d" % len(planned),
        "PASS" if planned and len(planned) == 18 and all(
            v["ok"] for v in w0.values()) else "FAIL",
        {"planned": len(planned), "files": w0})

    # Hub files.
    man = read_json(os.path.join("hub", "manifest.json"))
    hub_ok = [f for f in man.get("files", []) if f.get("status") == "ok"]
    hub_paths = {"%s/%s" % (f["model"], f["rfilename"]):
                 os.path.abspath(f["path"]) for f in hub_ok}
    pinned = {f["rfilename"].rsplit("/", 1)[-1]: os.path.abspath(f["path"])
              for f in man.get("pinned", []) if f.get("status") == "ok"}
    reported["hub"] = {"list": man.get("list"), "ok": len(hub_ok),
                       "total_bytes": man.get("total_bytes"),
                       "errors": [[f["model"], f["rfilename"], f["status"]]
                                  for f in man.get("files", [])
                                  if f.get("status") != "ok"],
                       "skipped_gated": man.get("skipped_gated"),
                       "pinned": man.get("pinned")}

    all_files = sorted(set(written.values()) | set(hub_paths.values())
                       | set(pinned.values()))
    so = run_scan(orig, all_files, "orig", work)
    sn = run_scan(tree, all_files, "new", work)
    reported["scan_errors"] = {"orig": so.get("error", ""),
                               "new": sn.get("error", "")}
    reported["versions"] = {"orig": so.get("versions"),
                            "new": sn.get("versions")}
    if so.get("error") or sn.get("error"):
        for rid in ("V1", "C1", "C2", "N1", "G1", "H1", "H2", "H3", "H4",
                    "H5", "D1"):
            add(rid, "", "", "NOT RUN", reason="scanner child failed")
        return reported, rows

    vo, vn = so.get("versions", {}), sn.get("versions", {})
    vers = {"orig_pms": vo.get("pms"), "orig_mfs": vo.get("mfs"),
            "new_pms": vn.get("pms"), "new_mfs": vn.get("mfs"),
            "new_pyproject": vn.get("pyproject")}
    add("V1", "versions",
        "orig pms 0.2.1 / mfs 0.12.0; new pms 0.4.0 / mfs 0.12.1 / "
        "pyproject 0.12.1",
        "PASS" if vers == {"orig_pms": "0.2.1", "orig_mfs": "0.12.0",
                           "new_pms": "0.4.0", "new_mfs": "0.12.1",
                           "new_pyproject": "0.12.1"} else "FAIL", vers)

    fo, fn = so.get("files", {}), sn.get("files", {})
    wn, bo = sn.get("walk", {}), sn.get("base", {})
    secs = sn.get("secs", {})
    reported["max_scan_seconds_new"] = max(secs.values() or [0])

    per = {}
    for name, path in written.items():
        truth = gfiles[name].get("imports") or []
        w = wn.get(path)
        imp = w.get("imports") if isinstance(w, dict) else None
        ct, cw = collections.Counter(truth), collections.Counter(imp or [])
        per[name] = {
            "truth_n": len(truth), "walk_n": len(imp or []),
            "missed": sorted((ct - cw).elements())[:20],
            "extra": sorted((cw - ct).elements())[:20],
            "same_order": imp == truth,
            "walk": walk_brief(w), "base": bo.get(path),
            "orig": fo.get(path), "new": fn.get(path),
        }
    reported["written"] = per

    if written:
        c1_bad = {k: {"missed": v["missed"], "extra": v["extra"]}
                  for k, v in per.items() if v["missed"] or v["extra"]
                  or not isinstance(wn.get(written[k]), dict)}
        add("C1", "0.4.0 walk imports equal the ground truth (as multisets) "
            "on every honest written file", "equal on all",
            "PASS" if not c1_bad and len(per) == len(planned) else "FAIL",
            {"n": len(per), "bad": c1_bad,
             "same_order": sum(1 for v in per.values() if v["same_order"])})
        c2_bad = {}
        for k, path in written.items():
            w = wn.get(path)
            if not (walk_complete(w) and w.get("unresolved") == 0
                    and not w.get("symbolic_stack_lost")):
                c2_bad[k] = walk_brief(w)
        add("C2", "0.4.0 walk reaches the last byte, nothing unresolved, "
            "stack tracking never lost, on every honest written file",
            "all", "PASS" if not c2_bad else "FAIL", {"bad": c2_bad})
        n1_bad = {k: v["new"] for k, v in per.items()
                  if isinstance(v["new"], str)
                  or rules(v["new"]) & {"PKL000", "PKL007", "PKL008"}
                  or worst(v["new"]) >= SEV["HIGH"]}
        add("N1", "0.4.0 (model-file-scan) on every honest written file",
            "no PKL000/PKL007/PKL008; nothing HIGH or CRITICAL",
            "PASS" if not n1_bad else "FAIL",
            {"bad": n1_bad, "all": {k: v["new"] for k, v in per.items()}})
        g1 = {}
        for k, path in written.items():
            w = wn.get(path)
            if k.endswith(".joblib") and isinstance(w, dict) \
                    and w.get("joblib_arrays", 0) >= 1:
                b = bo.get(path) or {}
                g1[k] = {"base": b, "before_last_byte":
                         b.get("pos") is not None
                         and b.get("pos") < b.get("length", 0) - 1}
        add("G1", "baseline: on every written .joblib file with a numeric "
            "array, a plain pickletools walk ends before the last byte",
            "all", "PASS" if g1 and all(v["before_last_byte"]
                                        for v in g1.values()) else "FAIL",
            {"n": len(g1), "files": g1})
    else:
        for rid in ("C1", "C2", "N1", "G1"):
            add(rid, "honest files", "", "NOT RUN", reason="writers failed")

    # Hub rows.
    if len(hub_paths) < 10:
        add("H1", "gate: published files downloaded", ">= 10", "FAIL",
            len(hub_paths))
        for rid in ("H2", "H3", "H4", "H5"):
            add(rid, "hub", "", "NOT RUN", reason="fewer than 10 files")
    else:
        add("H1", "gate: published files downloaded", ">= 10", "PASS",
            len(hub_paths))
        ho = {k: fo.get(p) for k, p in hub_paths.items()}
        hn = {k: fn.get(p) for k, p in hub_paths.items()}
        hw = {k: wn.get(p) for k, p in hub_paths.items()}
        hb = {k: bo.get(p) for k, p in hub_paths.items()}
        reported["hub_scans"] = {k: {"orig": ho[k], "new": hn[k],
                                     "walk": walk_brief(hw[k]),
                                     "base": hb[k],
                                     "secs": secs.get(hub_paths[k])}
                                 for k in hub_paths}
        errs = {k: v for k, v in list(ho.items()) + list(hn.items())
                if isinstance(v, str)}
        n7 = sorted(k for k, v in hn.items() if "PKL007" in rules(v))
        add("H2", "0.4.0: published files with PKL007; scan errors",
            "none; none", "PASS" if not n7 and not errs else "FAIL",
            {"pkl007": n7, "scan_errors": errs,
             "orig_pkl007": sorted(k for k, v in ho.items()
                                   if "PKL007" in rules(v))})
        jm = [k for k in hub_paths if isinstance(hw[k], dict)
              and hw[k].get("joblib_mode")]
        silent = {}
        complete = []
        for k in jm:
            flagged = (set(hw[k].get("rules") or []) | rules(hn[k])) \
                & {"PKL000", "PKL008"}
            if walk_complete(hw[k]):
                complete.append(k)
            elif not flagged:
                silent[k] = walk_brief(hw[k])
        add("H3", "fail-closed: every Hub file whose stream uses "
            "NumpyArrayWrapper is walked to its last byte or carries "
            "PKL000/PKL008", "no silent partial walk",
            "PASS" if jm and not silent else "FAIL",
            {"joblib_files": len(jm), "complete": len(complete),
             "silent": silent})
        lost = {}
        for k in hub_paths:
            if isinstance(ho[k], str) or isinstance(hn[k], str):
                continue
            gone = (rules(ho[k]) - {"PKL000", "PKL007"}) - rules(hn[k])
            if gone:
                lost[k] = sorted(gone)
        add("H4", "0.4.0 keeps every 0.2.1 rule except PKL000 and PKL007",
            "no rule lost on any file", "PASS" if not lost else "FAIL",
            {"lost": lost})
        share = len(complete) / len(jm) if jm else 0.0
        add("H5", "descriptive: share of Hub joblib files walked to the "
            "last byte", ">= 0.90", "PASS" if jm and share >= 0.9 else "FAIL",
            {"share": round(share, 4), "complete": len(complete),
             "of": len(jm)})
        added, hi = {}, []
        for k in hub_paths:
            if isinstance(hn[k], str) or isinstance(ho[k], str):
                continue
            a = sorted(rules(hn[k]) - rules(ho[k]))
            if a:
                added[k] = a
            if worst(hn[k]) >= SEV["HIGH"]:
                hi.append(k)
        reported["hub_new_rules"] = added
        reported["hub_new_high_or_critical"] = hi
        reported["hub_lz4"] = sorted(k for k in hub_paths
                                     if (hb[k] or {}).get("lz4"))
        cov = {}
        for k in jm:
            b, w = hb[k] or {}, hw[k]
            ln = max(b.get("length") or 1, 1)
            cov[k] = {"base": round(((b.get("pos") or 0) + 1) / ln, 6),
                      "new": round(((w.get("stop") or -1) + 1) / ln, 6)
                      if w.get("stop") is not None else None}
        reported["hub_coverage"] = cov

    # D1: the three files behind pkl-memo-v1's H3 miss.
    if len(pinned) == 3:
        d = {}
        for name, path in pinned.items():
            d[name] = {"new": fn.get(path), "orig": fo.get(path),
                       "walk": walk_brief(wn.get(path))}
        ok = all(not isinstance(v["new"], str)
                 and "PKL007" not in rules(v["new"])
                 and walk_complete(wn.get(pinned[n]))
                 for n, v in d.items())
        add("D1", "OKTAYBBS churn/mobile/wine: 0.4.0 gives no PKL007 and "
            "walks each to its last byte", "all three",
            "PASS" if ok else "FAIL", d)
    else:
        add("D1", "pinned files", "", "NOT RUN",
            reason="%d of 3 downloaded" % len(pinned))
    return reported, rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--orig")
    ap.add_argument("--tree")
    ap.add_argument("--scan", nargs=3)
    args = ap.parse_args(argv)
    if args.scan:
        return child_scan(*args.scan)
    os.makedirs(args.out, exist_ok=True)
    try:
        reported, rows = run(args)
        error = ""
    except Exception:
        reported, rows = {}, []
        error = traceback.format_exc()[-3000:]
        print(error, file=sys.stderr)
    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    release = [r["id"] for r in rows if r["id"] in RELEASE_ROWS]
    summary = {"check_version": 1, "error": error,
               "held": sum(1 for r in graded if r["result"] == "PASS"),
               "graded": len(graded),
               "not_run": [r["id"] for r in rows if r["result"] == "NOT RUN"],
               "release_rows_all_pass": bool(release) and len(release) ==
               len(RELEASE_ROWS) and all(r["result"] == "PASS" for r in rows
                                         if r["id"] in RELEASE_ROWS),
               "reported": reported, "rows": rows}
    with open(os.path.join(args.out, "jl_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"], json.dumps(r.get("got", ""),
                                               default=str)[:600],
              r.get("reason", ""))
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
