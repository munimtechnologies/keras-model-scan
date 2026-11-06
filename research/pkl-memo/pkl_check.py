#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check: pickle_model_scan 0.3.0 resolves STACK_GLOBAL operands
that Python's pickler fetches from the memo (protocols 4 and 5).

Pre-registered in research/PREREG_PKL_MEMO.md before job pkl-memo-v1 ran.
Writers run in child processes: paddle.save (.pdparams, .pdopt), Python's
pickle at protocols 4 and 5 (collections objects; numpy arrays), torch.save
at pickle protocol 4 and at its default. Planted opcode streams are only
ever disassembled. Each scanner version (the unpatched tree and the patched
tree) runs in its own child process, so the two pickle_model_scan modules
never share an interpreter. Published Hub files come from setup
(fetch_hub_pkl.py). The run step has no network. Nothing is loaded,
unpickled or executed by this script. Never raises: errors go into the
summary and it exits 0.

Usage: pkl_check.py --out OUT --orig ORIG_TREE --tree TREE
       pkl_check.py --write CASE DEST          (child)
       pkl_check.py --scan TREE IN_JSON OUT_JSON   (child)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import contextlib
import dataclasses
import io
import json
import os
import pickle
import re
import struct
import subprocess
import sys
import traceback

SELF = os.path.abspath(__file__)
SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WRITERS = {
    "pd": ["model.pdopt", "model.pdparams"],
    "coll": ["coll_p4.pkl", "coll_p5.pkl"],
    "np": ["np_p4.pkl", "np_p5.pkl"],
    "torch": ["t_p2.pt", "t_p4.pt"],
}
G1_FILES = ("pd/model.pdparams", "pd/model.pdopt", "coll/coll_p4.pkl",
            "coll/coll_p5.pkl")


def su(s):
    b = s.encode("utf-8")
    return pickle.SHORT_BINUNICODE + bytes([len(b)]) + b


def bg(i):
    return pickle.BINGET + bytes([i])


P4 = pickle.PROTO + b"\x04"
PLANTED = {
    # memo slot holds a tuple -> unresolved
    "Fa": P4 + pickle.EMPTY_TUPLE + pickle.MEMOIZE + bg(0) + bg(0)
    + pickle.STACK_GLOBAL + pickle.STOP,
    # memo index never stored -> unresolved
    "Fb": P4 + bg(7) + bg(8) + pickle.STACK_GLOBAL + pickle.STOP,
    # operands are not the last two pushes -> unresolved
    "Fc": P4 + su("os") + su("system") + su("collections")
    + su("OrderedDict") + pickle.POP + pickle.POP + pickle.STACK_GLOBAL
    + pickle.STOP,
    # memoized os / system fetched back, then REDUCE -> code execution
    "Fd": P4 + su("os") + pickle.MEMOIZE + pickle.POP + su("system")
    + pickle.MEMOIZE + pickle.POP + bg(0) + bg(1) + pickle.STACK_GLOBAL
    + pickle.EMPTY_TUPLE + pickle.REDUCE + pickle.STOP,
    # the stream test_attribution uses (protocol 2 GLOBAL + REDUCE)
    "Fe": b"\x80\x02cos\nsystem\n)R.",
}
F1_EXPECT = {"Fa": ("PKL007", "HIGH"), "Fb": ("PKL007", "HIGH"),
             "Fc": ("PKL007", "HIGH"), "Fd": ("PKL001", "CRITICAL"),
             "Fe": ("PKL001", "CRITICAL")}
ROW_IDS = ("V1", "S1", "S2", "G1", "N1", "N2", "F1", "F2", "H1", "H2", "H3",
           "H4")


# ---------------------------------------------------------------- writers
def child_write(case, dest):
    os.makedirs(dest, exist_ok=True)
    try:
        if case == "pd":
            import paddle
            paddle.seed(0)
            layer = paddle.nn.Linear(4, 2)
            opt = paddle.optimizer.Adam(parameters=layer.parameters())
            loss = layer(paddle.randn([3, 4])).mean()
            loss.backward()
            opt.step()
            opt.clear_grad()
            paddle.save(layer.state_dict(),
                        os.path.join(dest, "model.pdparams"))
            paddle.save(opt.state_dict(), os.path.join(dest, "model.pdopt"))
        elif case == "coll":
            import collections
            obj = {"c": collections.Counter(a=1),
                   "m": collections.ChainMap({"x": 1}),
                   "o": collections.OrderedDict(k=2)}
            for p in (4, 5):
                with open(os.path.join(dest, "coll_p%d.pkl" % p), "wb") as fh:
                    pickle.dump(obj, fh, protocol=p)
        elif case == "np":
            import numpy as np
            obj = {"w": np.arange(6, dtype=np.float32).reshape(2, 3),
                   "b": np.zeros(3), "i": np.arange(4, dtype=np.int64)}
            for p in (4, 5):
                with open(os.path.join(dest, "np_p%d.pkl" % p), "wb") as fh:
                    pickle.dump(obj, fh, protocol=p)
        elif case == "torch":
            import torch
            torch.manual_seed(0)
            m = torch.nn.Sequential(torch.nn.Linear(4, 3), torch.nn.ReLU(),
                                    torch.nn.Linear(3, 2))
            sd = m.state_dict()
            torch.save(sd, os.path.join(dest, "t_p2.pt"))
            torch.save(sd, os.path.join(dest, "t_p4.pt"), pickle_protocol=4)
        else:
            print("error unknown case", flush=True)
            return 3
        print("written %s" % sorted(os.listdir(dest)), flush=True)
        return 0
    except Exception as exc:
        print("error %s: %s" % (type(exc).__name__, str(exc)[:300]),
              flush=True)
        return 3


# ---------------------------------------------------------------- scanning
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


def child_scan(tree, in_json, out_json):
    """Scan with the scanners of TREE only (fresh interpreter)."""
    res = {"versions": {}, "files": {}, "cli": {}, "streams": {},
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
        with open(in_json, encoding="utf-8") as fh:
            job = json.load(fh)
        for path in job.get("files", []):
            try:
                res["files"][path] = pairs_of(mfs.scan_path(path))
            except Exception as exc:
                res["files"][path] = "error: %s: %s" % (type(exc).__name__,
                                                        str(exc)[:200])
            out, err = io.StringIO(), io.StringIO()
            try:
                with contextlib.redirect_stdout(out), \
                        contextlib.redirect_stderr(err):
                    rc = mfs.main([path])
            except SystemExit as exc:
                rc = exc.code
            except Exception as exc:
                rc = "error: %s" % type(exc).__name__
            res["cli"][path] = rc
        for name, hx in job.get("streams", {}).items():
            try:
                res["streams"][name] = pairs_of(
                    pms.scan_pickle_bytes(bytes.fromhex(hx), name))
            except Exception as exc:
                res["streams"][name] = "error: %s: %s" % (
                    type(exc).__name__, str(exc)[:200])
    except Exception:
        res["error"] = traceback.format_exc()[-2000:]
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    return 0


def run_scan(tree, files, streams, tag, work):
    in_json = os.path.join(work, "scan_in_%s.json" % tag)
    out_json = os.path.join(work, "scan_out_%s.json" % tag)
    with open(in_json, "w", encoding="utf-8") as fh:
        json.dump({"files": files,
                   "streams": {k: v.hex() for k, v in streams.items()}}, fh)
    p = subprocess.run([sys.executable, SELF, "--scan", tree, in_json,
                        out_json], capture_output=True, text=True,
                       timeout=3600, cwd=work)
    try:
        with open(out_json, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"error": "no output (%s); exit %s; %s" % (
            exc, p.returncode, (p.stdout + p.stderr)[-800:])}


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


# ---------------------------------------------------------------- grading
def run(args):
    reported = {"setup": read_json("setup_report.json"),
                "fetch": read_json("fetch_report.json")}
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
    try:
        p = subprocess.run([sys.executable, "-m", "unittest", "-v",
                            "test_pickle_model_scan_memo"], cwd=tree,
                           capture_output=True, text=True, timeout=300)
        m = re.search(r"Ran (\d+) tests?", p.stderr)
        ran = int(m.group(1)) if m else 0
        add("S2", "new test module alone", "exit 0; at least 10 tests",
            "PASS" if p.returncode == 0 and ran >= 10 else "FAIL",
            {"exit": p.returncode, "ran": ran, "tail": p.stderr[-900:]})
    except Exception as exc:
        add("S2", "new test module alone", "", "NOT RUN", reason=str(exc))

    # Writers.
    files_dir = os.path.join(args.out, "files")
    wlog, written = {}, {}
    for case, names in WRITERS.items():
        dest = os.path.join(files_dir, "writers", case)
        try:
            p = subprocess.run([sys.executable, SELF, "--write", case, dest],
                               capture_output=True, text=True, timeout=900)
            rc, tail = p.returncode, (p.stdout + p.stderr).strip()[-400:]
        except Exception as exc:
            rc, tail = None, str(exc)
        got = sorted(os.listdir(dest)) if os.path.isdir(dest) else []
        wlog[case] = {"exit": rc, "files": got, "tail": tail}
        if rc == 0 and got == sorted(names):
            for n in names:
                written["%s/%s" % (case, n)] = os.path.join(dest, n)
    reported["writers"] = wlog
    magic = {}
    for key, path in written.items():
        with open(path, "rb") as fh:
            magic[key] = fh.read(4).hex()
    reported["magic"] = magic

    # Planted streams, also kept as files for the record.
    pdir = os.path.join(files_dir, "planted")
    os.makedirs(pdir, exist_ok=True)
    for name, data in PLANTED.items():
        with open(os.path.join(pdir, name + ".pkl"), "wb") as fh:
            fh.write(data)

    # Hub files.
    man = read_json(os.path.join("hub", "manifest.json"))
    hub_ok = [f for f in man.get("files", []) if f.get("status") == "ok"]
    hub_paths = {"%s/%s" % (f["model"], f["rfilename"]):
                 os.path.abspath(f["path"]) for f in hub_ok}
    reported["hub"] = {"lists": man.get("lists"), "ok": len(hub_ok),
                       "errors": [[f["model"], f["rfilename"], f["status"]]
                                  for f in man.get("files", [])
                                  if f.get("status") != "ok"],
                       "skipped_gated": man.get("skipped_gated")}

    all_files = sorted(set(written.values()) | set(hub_paths.values()))
    so = run_scan(orig, all_files, PLANTED, "orig", work)
    sn = run_scan(tree, all_files, PLANTED, "new", work)
    reported["scan_errors"] = {"orig": so.get("error", ""),
                               "new": sn.get("error", "")}
    reported["versions"] = {"orig": so.get("versions"),
                            "new": sn.get("versions")}
    if so.get("error") or sn.get("error"):
        for rid in ("V1", "G1", "N1", "N2", "F1", "F2", "H1", "H2", "H3",
                    "H4"):
            add(rid, "", "", "NOT RUN", reason="scanner child failed")
        return reported, rows

    vo, vn = so.get("versions", {}), sn.get("versions", {})
    vers = {"orig_pms": vo.get("pms"), "orig_mfs": vo.get("mfs"),
            "new_pms": vn.get("pms"), "new_mfs": vn.get("mfs"),
            "new_pyproject": vn.get("pyproject")}
    add("V1", "versions",
        "orig pms 0.2.1 / mfs 0.12.0; new pms 0.3.0 / mfs 0.12.1 / "
        "pyproject 0.12.1",
        "PASS" if vers == {"orig_pms": "0.2.1", "orig_mfs": "0.12.0",
                           "new_pms": "0.3.0", "new_mfs": "0.12.1",
                           "new_pyproject": "0.12.1"} else "FAIL", vers)

    fo, fn = so.get("files", {}), sn.get("files", {})
    co, cn = so.get("cli", {}), sn.get("cli", {})
    w = {k: {"orig": fo.get(p), "new": fn.get(p), "orig_cli": co.get(p),
             "new_cli": cn.get(p)} for k, p in written.items()}
    reported["written_scans"] = w

    # G1: the gap on files Python's pickler and paddle wrote.
    g1_have = [k for k in G1_FILES if k in written]
    if len(g1_have) < len(G1_FILES):
        reported["g1_missing_writers"] = sorted(set(G1_FILES) - set(g1_have))
    if g1_have:
        g1 = {k: w[k]["orig"] for k in g1_have}
        add("G1", "0.2.1 on paddle .pdparams/.pdopt and protocol 4/5 "
            "collections pickles", "PKL007 HIGH on each",
            "PASS" if all(("PKL007", "HIGH") in [tuple(x) for x in v]
                          for v in g1.values()
                          if not isinstance(v, str)) and
            not any(isinstance(v, str) for v in g1.values()) else "FAIL", g1)
    else:
        add("G1", "gap", "", "NOT RUN", reason="writers failed")

    if written:
        n1 = {k: w[k]["new"] for k in written}
        bad = {k: v for k, v in n1.items()
               if "PKL007" in rules(v) or worst(v) >= SEV["HIGH"]}
        add("N1", "0.3.0 on every honest written file",
            "no PKL007; nothing HIGH or CRITICAL",
            "PASS" if not bad else "FAIL", {"n": len(n1), "bad": bad,
                                            "all": n1})
    else:
        add("N1", "honest files", "", "NOT RUN", reason="writers failed")
    coll = [k for k in ("coll/coll_p4.pkl", "coll/coll_p5.pkl")
            if k in written]
    if coll:
        n2 = {k: w[k]["new"] for k in coll}
        add("N2", "0.3.0 on the collections pickles",
            "nothing above LOW",
            "PASS" if all(worst(v) <= SEV["LOW"] for v in n2.values())
            else "FAIL", n2)
    else:
        add("N2", "collections", "", "NOT RUN", reason="writer failed")

    sto, stn = so.get("streams", {}), sn.get("streams", {})
    f1 = {k: stn.get(k) for k in PLANTED}
    ok1 = all(not isinstance(f1[k], str) and
              list(F1_EXPECT[k]) in [list(x) for x in f1[k]]
              for k in PLANTED)
    add("F1", "0.3.0 on planted streams",
        "Fa/Fb/Fc PKL007 HIGH; Fd/Fe PKL001 CRITICAL",
        "PASS" if ok1 else "FAIL", f1)
    fd, fc = sto.get("Fd"), sto.get("Fc")
    ok2 = (not isinstance(fd, str) and "PKL007" in rules(fd)
           and "PKL001" not in rules(fd) and not isinstance(fc, str)
           and worst(fc) <= SEV["LOW"])
    add("F2", "0.2.1 on planted Fd and Fc",
        "Fd: PKL007 but no PKL001; Fc: nothing above LOW",
        "PASS" if ok2 else "FAIL", {"Fd": fd, "Fc": fc,
                                    "all_orig": sto})

    # Hub rows.
    if len(hub_paths) < 10:
        add("H1", "gate: published files downloaded", ">= 10", "FAIL",
            len(hub_paths))
        for rid in ("H2", "H3", "H4"):
            add(rid, "hub", "", "NOT RUN", reason="fewer than 10 files")
    else:
        add("H1", "gate: published files downloaded", ">= 10", "PASS",
            len(hub_paths))
        ho = {k: fo.get(p) for k, p in hub_paths.items()}
        hn = {k: fn.get(p) for k, p in hub_paths.items()}
        reported["hub_scans"] = {k: {"orig": ho[k], "new": hn[k]}
                                 for k in hub_paths}
        errs = {k: v for k, v in list(ho.items()) + list(hn.items())
                if isinstance(v, str)}
        if errs:
            reported["hub_scan_errors"] = errs
        o7 = sorted(k for k, v in ho.items() if "PKL007" in rules(v))
        add("H2", "0.2.1: published files with PKL007", ">= 5",
            "PASS" if len(o7) >= 5 else "FAIL", {"n": len(o7),
                                                 "files": o7})
        n7 = sorted(k for k, v in hn.items() if "PKL007" in rules(v))
        add("H3", "0.3.0: published files with PKL007", "none",
            "PASS" if not n7 and not errs else "FAIL",
            {"n": len(n7), "files": n7, "scan_errors": len(errs)})
        lost = {}
        for k in hub_paths:
            if isinstance(ho[k], str) or isinstance(hn[k], str):
                continue
            gone = (rules(ho[k]) - {"PKL007"}) - rules(hn[k])
            if gone:
                lost[k] = sorted(gone)
        add("H4", "0.3.0 keeps every 0.2.1 rule except PKL007",
            "no rule lost on any file", "PASS" if not lost else "FAIL",
            {"lost": lost})
        new_rules = {}
        hi = []
        for k in hub_paths:
            if isinstance(hn[k], str) or isinstance(ho[k], str):
                continue
            added = sorted(rules(hn[k]) - rules(ho[k]))
            if added:
                new_rules[k] = added
            if worst(hn[k]) >= SEV["HIGH"]:
                hi.append(k)
        reported["hub_new_rules"] = new_rules
        reported["hub_new_high_or_critical"] = hi
        reported["hub_pkl007_only_high_orig"] = sorted(
            k for k, v in ho.items() if not isinstance(v, str)
            and [s for r, s in v if SEV.get(s, 0) >= SEV["HIGH"]]
            and all(r == "PKL007" for r, s in v
                    if SEV.get(s, 0) >= SEV["HIGH"]))
    return reported, rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--orig")
    ap.add_argument("--tree")
    ap.add_argument("--write", nargs=2)
    ap.add_argument("--scan", nargs=3)
    args = ap.parse_args(argv)
    if args.write:
        return child_write(*args.write)
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
    summary = {"check_version": 1, "error": error,
               "held": sum(1 for r in graded if r["result"] == "PASS"),
               "graded": len(graded),
               "not_run": [r["id"] for r in rows if r["result"] == "NOT RUN"],
               "reported": reported, "rows": rows}
    with open(os.path.join(args.out, "pkl_summary.json"), "w",
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
