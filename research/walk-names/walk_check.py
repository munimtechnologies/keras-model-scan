#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check: pickle-bearing names that model-file-scan's directory
walk skipped (0.12.0) and keeps after the walk-names fix (0.13.0).

Pre-registered in research/PREREG_WALK_NAMES.md before job walk-names-v1 ran.
Writers run in child processes: torch.save as checkpoint.pth.tar and
model_best.pth.tar (pytorch/examples imagenet naming, ZIP and legacy
formats), paddle.save as model.pdparams / model.pdopt, and, reported only,
PyTorch Mobile .ptl and torch.export .pt2. Planted copies hold the opcode
stream test_attribution uses (GLOBAL os.system + REDUCE), only ever
disassembled by the scanner. A Hub name census and published files come from
setup (fetch_hub_names.py). The run step has no network. Nothing is loaded,
unpickled or executed by this script. Never raises: errors go into the
summary and it exits 0.

Usage: walk_check.py --out OUT --orig ORIG_DIR --tree TREE
       walk_check.py --write CASE DEST     (child)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import contextlib
import dataclasses
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import traceback
from collections import Counter

SELF = os.path.abspath(__file__)
FIXTURE = b"\x80\x02cos\nsystem\n)R."
PICKLE_NAME = re.compile(r"\.(?:pt|pth|ckpt)\.tar$|\.(?:pdparams|pdopt)$",
                         re.I)
SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WRITERS = {
    "tv_pth_tar": ["checkpoint.pth.tar", "model_best.pth.tar"],
    "legacy_pth_tar": ["checkpoint.pth.tar"],
    "pd_params": ["model.pdopt", "model.pdparams"],
    "ptl": ["model.ptl"],
    "pt2": ["model.pt2"],
}
GRADED = ("tv_pth_tar", "legacy_pth_tar", "pd_params")
EDITED = {"E1": "evil.pdparams", "E2": "checkpoint.pth.tar",
          "E3": "model.pdopt", "E4": "weights.pt.tar"}
ROW_IDS = ("V1", "S1", "S2", "R0", "G1", "G2", "F1", "F2", "F3", "C1",
           "H1", "H2", "H3", "H4")


def child_write(case, dest):
    os.makedirs(dest, exist_ok=True)
    try:
        if case in ("tv_pth_tar", "legacy_pth_tar", "ptl", "pt2"):
            import torch
            torch.manual_seed(0)
            m = torch.nn.Sequential(torch.nn.Linear(4, 3), torch.nn.ReLU(),
                                    torch.nn.Linear(3, 2))
            opt = torch.optim.SGD(m.parameters(), lr=0.1, momentum=0.9)
            m(torch.randn(5, 4)).sum().backward()
            opt.step()
            state = {"epoch": 1, "arch": "tiny", "state_dict": m.state_dict(),
                     "best_acc1": torch.tensor(0.5),
                     "optimizer": opt.state_dict()}
            if case == "tv_pth_tar":
                p = os.path.join(dest, "checkpoint.pth.tar")
                torch.save(state, p)
                shutil.copyfile(p, os.path.join(dest, "model_best.pth.tar"))
            elif case == "legacy_pth_tar":
                torch.save(state, os.path.join(dest, "checkpoint.pth.tar"),
                           _use_new_zipfile_serialization=False)
            elif case == "ptl":
                torch.jit.script(m)._save_for_lite_interpreter(
                    os.path.join(dest, "model.ptl"))
            else:
                ep = torch.export.export(m, (torch.randn(1, 4),))
                torch.export.save(ep, os.path.join(dest, "model.pt2"))
        elif case == "pd_params":
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
        else:
            print("error unknown case", flush=True)
            return 3
        print("written %s" % sorted(os.listdir(dest)), flush=True)
        return 0
    except Exception as exc:
        print("error %s: %s" % (type(exc).__name__, str(exc)[:300]),
              flush=True)
        return 3


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def as_dict(f):
    if isinstance(f, dict):
        return f
    if hasattr(f, "as_dict"):
        return f.as_dict()
    if dataclasses.is_dataclass(f):
        return dataclasses.asdict(f)
    return dict(vars(f))


def scan(mod, path):
    """(rule, SEVERITY) pairs from model_file_scan.scan_path."""
    out = set()
    for f in mod.scan_path(path) or []:
        d = as_dict(f)
        out.add((str(d.get("rule")), str(d.get("severity", "")).upper()))
    return sorted(out)


def worst(pairs):
    return max([SEV.get(s, 0) for _r, s in pairs] or [0])


def cli(mod, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = mod.main(list(args))
        except SystemExit as exc:
            rc = exc.code
    return rc, (out.getvalue() + err.getvalue())[-500:]


def kept(mod, folder):
    files, _missing = mod.expand_paths([folder])
    return sorted(os.path.relpath(f, folder) for f in files)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"missing": "%s: %s" % (type(exc).__name__, exc)}


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
    sys.path.insert(0, tree)
    orig = load("mfs_orig", os.path.join(args.orig, "model_file_scan.py"))
    new = load("mfs_new", os.path.join(tree, "model_file_scan.py"))
    pyv = re.search(r'(?m)^version\s*=\s*"([^"]+)"',
                    open(os.path.join(tree, "pyproject.toml"),
                         encoding="utf-8").read())
    vers = {"orig": orig.__version__, "new": new.__version__,
            "pyproject": pyv.group(1) if pyv else None}
    add("V1", "versions", "orig 0.12.0, new 0.13.0, pyproject 0.13.0",
        "PASS" if vers == {"orig": "0.12.0", "new": "0.13.0",
                           "pyproject": "0.13.0"} else "FAIL", vers)

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
                            "test_model_file_scan_walk_names"], cwd=tree,
                           capture_output=True, text=True, timeout=300)
        m = re.search(r"Ran (\d+) tests?", p.stderr)
        ran = int(m.group(1)) if m else 0
        add("S2", "new test module alone", "exit 0; at least 9 tests",
            "PASS" if p.returncode == 0 and ran >= 9 else "FAIL",
            {"exit": p.returncode, "ran": ran, "tail": p.stderr[-600:]})
    except Exception as exc:
        add("S2", "new test module alone", "", "NOT RUN", reason=str(exc))

    files = os.path.join(args.out, "files")
    # Writers.
    wdirs, wlog = {}, {}
    for case in WRITERS:
        dest = os.path.join(files, "writers", case)
        try:
            p = subprocess.run([sys.executable, SELF, "--write", case, dest],
                               capture_output=True, text=True, timeout=900)
            rc, tail = p.returncode, (p.stdout + p.stderr).strip()[-400:]
        except Exception as exc:
            rc, tail = None, str(exc)
        got = sorted(os.listdir(dest)) if os.path.isdir(dest) else []
        wlog[case] = {"exit": rc, "files": got, "tail": tail}
        if rc == 0:
            wdirs[case] = dest
    reported["writers"] = wlog
    magic = {}
    for case, d in wdirs.items():
        for n in sorted(os.listdir(d)):
            with open(os.path.join(d, n), "rb") as fh:
                magic["%s/%s" % (case, n)] = fh.read(4).hex()
    reported["magic"] = magic
    graded = [c for c in GRADED if c in wdirs
              and wlog[c]["files"] == sorted(WRITERS[c])]
    bad_writers = {c: wlog[c] for c in GRADED if c not in graded}
    if bad_writers:
        reported["writer_problems"] = bad_writers

    # Edited (planted) folders and controls.
    edirs = {}
    for eid, name in EDITED.items():
        d = os.path.join(files, "edited", eid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "wb") as fh:
            fh.write(FIXTURE)
        edirs[eid] = d
    cdir = os.path.join(files, "controls")
    os.makedirs(cdir, exist_ok=True)
    note = os.path.join(cdir, "a.txt")
    with open(note, "w", encoding="utf-8") as fh:
        fh.write("hello\n")
    with tarfile.open(os.path.join(cdir, "data.tar"), "w") as tf:
        tf.add(note, arcname="a.txt")
    with tarfile.open(os.path.join(cdir, "logs.tar.gz"), "w:gz") as tf:
        tf.add(note, arcname="a.txt")
    os.remove(note)

    # R0: route of every name is the pickle scanner in both versions.
    names = sorted({n for c in WRITERS for n in WRITERS[c]}
                   | set(EDITED.values()))
    rg = {n: [orig.route(n), new.route(n)] for n in names}
    add("R0", "route() of every written and planted name, both versions",
        "pickle / pickle",
        "PASS" if all(v == ["pickle", "pickle"] for v in rg.values())
        else "FAIL", rg)

    # G1 / F1: walks of the honest writer folders.
    if graded:
        g1 = {c: kept(orig, wdirs[c]) for c in graded}
        add("G1", "0.12.0 walk of the writer folders", "keeps nothing",
            "PASS" if all(v == [] for v in g1.values()) else "FAIL", g1)
        f1 = {c: kept(new, wdirs[c]) for c in graded}
        add("F1", "0.13.0 walk of the writer folders",
            "keeps exactly the written files",
            "PASS" if all(f1[c] == sorted(WRITERS[c]) for c in graded)
            else "FAIL", f1)
        f3 = {}
        for c in graded:
            per = {n: scan(new, os.path.join(wdirs[c], n))
                   for n in WRITERS[c]}
            rc, _tail = cli(new, wdirs[c])
            f3[c] = {"scan": per, "folder_exit": rc}
        ok3 = all(v["folder_exit"] == 0 and
                  all(worst(p) <= SEV["LOW"] for p in v["scan"].values())
                  for v in f3.values())
        add("F3", "0.13.0 on honest writer files", "nothing above LOW; "
            "folder exit 0", "PASS" if ok3 else "FAIL", f3)
    else:
        for rid in ("G1", "F1", "F3"):
            add(rid, "writer folders", "", "NOT RUN",
                reason="no graded writer wrote its files")
    if bad_writers and graded:
        rows[-1].setdefault("note", "writers not graded: %s"
                            % sorted(bad_writers))

    # G2 / F2: planted folders.
    g2 = {e: cli(orig, d) for e, d in edirs.items()}
    add("G2", "0.12.0 CLI on the planted folders",
        "exit 0, 'no model files found'",
        "PASS" if all(rc == 0 and "no model files found" in t
                      for rc, t in g2.values()) else "FAIL",
        {e: rc for e, (rc, _t) in g2.items()})
    f2 = {}
    for e, d in edirs.items():
        rc, _t = cli(new, d)
        rules = scan(new, os.path.join(d, EDITED[e]))
        f2[e] = {"exit": rc, "rules": rules}
    add("F2", "0.13.0 CLI on the planted folders",
        "exit 1; PKL001 in the planted file",
        "PASS" if all(v["exit"] == 1 and any(r == "PKL001"
                                             for r, _s in v["rules"])
                      for v in f2.values()) else "FAIL", f2)

    # C1: controls.
    c1 = {"orig": kept(orig, cdir), "new": kept(new, cdir),
          "new_exit": cli(new, cdir)[0]}
    add("C1", "plain data.tar and logs.tar.gz", "neither version keeps "
        "them; 0.13.0 exits 0",
        "PASS" if c1["orig"] == [] and c1["new"] == [] and
        c1["new_exit"] == 0 else "FAIL", c1)

    # Reported: .ptl and .pt2 (not part of the fix).
    rep = {}
    for case in ("ptl", "pt2"):
        if case in wdirs:
            n = WRITERS[case][0]
            pth = os.path.join(wdirs[case], n)
            if os.path.isfile(pth):
                rep[case] = {"scan": scan(new, pth),
                             "kept_orig": kept(orig, wdirs[case]),
                             "kept_new": kept(new, wdirs[case]),
                             "file_exit": cli(new, pth)[0]}
    reported["ptl_pt2"] = rep

    # Hub.
    hub_names = read_json(os.path.join("hub", "names.json"))
    man = read_json(os.path.join("hub", "manifest.json"))
    reported["hub_lists"] = man.get("lists")
    if "missing" in hub_names or len(hub_names) < 100:
        for rid in ("H1", "H2", "H3", "H4"):
            add(rid, "hub", "", "NOT RUN",
                reason="fewer than 100 models listed")
    else:
        add("H1", "gate: models listed", ">= 100", "PASS", len(hub_names))
        cls = Counter()
        skipped_ext = Counter()
        for mid, info in hub_names.items():
            for rf in info.get("files", []):
                base = rf.rsplit("/", 1)[-1]
                low = base.lower()
                if PICKLE_NAME.search(low):
                    m = PICKLE_NAME.search(low).group(0)
                    cls[m] += 1
                for suf in (".ptl", ".pt2"):
                    if low.endswith(suf):
                        cls[suf] += 1
                ext = os.path.splitext(low)[1]
                content = ext in (".xml", ".json", ".txt", ".lgb",
                                  ".lightgbm")
                by_name = (ext in new._MODEL_EXTS or low == "config.json"
                           or new._is_shard_index(low)
                           or new._is_pickle_name(low))
                if not by_name and not content:
                    skipped_ext[ext or "(none)"] += 1
        reported["hub_name_classes"] = dict(cls)
        reported["hub_skipped_ext_top30"] = skipped_ext.most_common(30)
        add("H2", "census: a .pdparams file among the listed models", ">= 1",
            "PASS" if cls.get(".pdparams", 0) >= 1 else "FAIL",
            cls.get(".pdparams", 0))
        ok_files = [f for f in man.get("files", [])
                    if f.get("status") == "ok"]
        reported["hub_download"] = {"ok": len(ok_files),
                                    "errors": [[f["model"], f["rfilename"],
                                                f["status"]]
                                               for f in man.get("files", [])
                                               if f.get("status") != "ok"],
                                    "skipped_gated": man.get("skipped_gated")}
        if len(ok_files) < 5:
            for rid in ("H3", "H4"):
                add(rid, "published files", "", "NOT RUN",
                    reason="fewer than 5 downloaded (%d)" % len(ok_files))
        else:
            h3, h4, med = {}, {}, []
            for f in ok_files:
                path = f["path"]
                key = "%s/%s" % (f["model"], f["rfilename"])
                pairs = scan(new, path)
                h3[key] = pairs
                if worst(pairs) == SEV["MEDIUM"]:
                    med.append(key)
                folder = os.path.dirname(path)
                h4[key] = [kept(orig, folder), kept(new, folder)]
            bad3 = {k: v for k, v in h3.items() if worst(v) >= SEV["HIGH"]}
            add("H3", "0.13.0 on published files of these names",
                "no HIGH or CRITICAL finding", "PASS" if not bad3 else "FAIL",
                {"n": len(h3), "high_or_critical": bad3, "medium": med})
            bad4 = {k: v for k, v in h4.items()
                    if v[0] != [] or len(v[1]) != 1}
            add("H4", "walks of published files' folders",
                "0.12.0 keeps none; 0.13.0 keeps each",
                "PASS" if not bad4 else "FAIL",
                {"n": len(h4), "bad": bad4})
            reported["hub_scans"] = h3
    return reported, rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--orig")
    ap.add_argument("--tree")
    ap.add_argument("--write", nargs=2)
    args = ap.parse_args(argv)
    if args.write:
        return child_write(*args.write)
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
    with open(os.path.join(args.out, "walk_summary.json"), "w",
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
