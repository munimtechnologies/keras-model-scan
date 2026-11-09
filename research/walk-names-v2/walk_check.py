#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Graded check for job walk-names-v2 (pre-registered in
research/PREREG_WALK_NAMES_V2.md). Compares model-file-scan 0.12.1 (./base,
tag v0.54.0 as published) with the patched 0.13.0 (./tree) on HONEST files
written by torch, paddle and joblib under their usual names, on negative
controls, and on published Hugging Face files. Each scanner version runs in
its own process. Writes OUT/walk_summary.json. Always exits 0.

Usage: walk_check.py --out OUT --tree TREE --base BASE

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import subprocess
import sys
import traceback

SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WRITERS = ("tv_pth_tar", "legacy_pth_tar", "pd_params", "joblib_c")
EXPECT_FILES = {"tv_pth_tar": 2, "legacy_pth_tar": 1, "pd_params": 2,
                "joblib_c": 6}
NEEDS = {"tv_pth_tar": "torch", "legacy_pth_tar": "torch",
         "pd_params": "paddlepaddle", "joblib_c": "joblib",
         "limits": "joblib", "controls": None}
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"([0-9.]+)"')
PYP_RE = re.compile(r'(?m)^version\s*=\s*"([0-9.]+)"')


def arg(name):
    return sys.argv[sys.argv.index(name) + 1]


def jload(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def regex_file(path, rx):
    try:
        with open(path, encoding="utf-8") as fh:
            m = rx.search(fh.read())
        return m.group(1) if m else None
    except OSError:
        return None


def scan(ver_dir, target):
    cmd = [sys.executable, os.path.join(ver_dir, "model_file_scan.py"),
           target, "--json"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except Exception as exc:
        return {"exit": None, "files": {}, "err": str(exc)}
    files = {}
    try:
        doc = json.loads(p.stdout)
        for f in doc.get("files", []):
            files[os.path.basename(f["path"])] = [
                [x.get("rule"), str(x.get("severity", "")).upper(),
                 str(x.get("title", ""))[:120]] for x in f.get("findings", [])]
    except Exception:
        files = None
    return {"exit": p.returncode, "files": files, "err": p.stderr[-800:]}


def worst(findings):
    return max([SEV.get(f[1], 0) for f in findings] or [-1])


def rules(findings):
    return sorted(set("%s %s" % (f[0], f[1]) for f in findings))


def main():
    out, tree, base = arg("--out"), arg("--tree"), arg("--base")
    os.makedirs(out, exist_ok=True)
    rows = []
    rep = {}

    def row(rid, case, expected, ok, got):
        res = "NOT_RUN" if ok is None else ("PASS" if ok else "FAIL")
        rows.append({"id": rid, "case": case, "expected": expected,
                     "result": res, "got": got})

    try:
        rep["fetch"] = jload("fetch_report.json", {})
        setup = jload("setup_report.json", {})
        rep["setup"] = {k: v for k, v in setup.items() if not k.endswith("_tail")}
        versions = setup.get("versions") if isinstance(setup.get("versions"), dict) else {}

        def have(pkg):
            if pkg is None:
                return True
            v = versions.get(pkg, "missing")
            return not str(v).startswith("missing")

        patch = jload(os.path.join(out, "patch_report.json"), {})
        row("P1", "patch applies once, second pass no-op, nothing lost",
            "ok", bool(patch.get("ok")), patch)

        vb = regex_file(os.path.join(base, "model_file_scan.py"), VER_RE)
        vp = regex_file(os.path.join(base, "pickle_model_scan.py"), VER_RE)
        vt = regex_file(os.path.join(tree, "model_file_scan.py"), VER_RE)
        vy = regex_file(os.path.join(tree, "pyproject.toml"), PYP_RE)
        row("V1", "versions", "base mfs 0.12.1 + pms 0.4.0; patched 0.13.0; pyproject 0.13.0",
            vb == "0.12.1" and vp == "0.4.0" and vt == "0.13.0" and vy == "0.13.0",
            {"base_mfs": vb, "base_pms": vp, "tree_mfs": vt, "tree_pyproject": vy})

        ts = jload(os.path.join(out, "tests_summary.json"), {})
        row("S1", "full unit-test suite on the patched tree",
            "0 failures, 0 errors, ran >= 1390",
            bool(ts) and not ts.get("failures") and not ts.get("errors")
            and ts.get("error") is None and (ts.get("ran") or 0) >= 1390, ts)

        p = subprocess.run([sys.executable, "-m", "unittest", "-v",
                            "test_model_file_scan_walk_names"], cwd=tree,
                           capture_output=True, text=True, timeout=600)
        m = re.search(r"Ran (\d+) tests?", p.stderr)
        ran = int(m.group(1)) if m else 0
        row("S2", "new test module alone", "exit 0; exactly 9 tests",
            p.returncode == 0 and ran == 9,
            {"exit": p.returncode, "ran": ran, "tail": p.stderr[-600:]})

        # ---- writers (honest files, real libraries) ----
        wdir = os.path.abspath("w")
        written = {}
        for kind in WRITERS + ("limits", "controls"):
            if not have(NEEDS[kind]):
                written[kind] = {"not_run": "missing " + str(NEEDS[kind])}
                continue
            d = os.path.join(wdir, kind)
            try:
                q = subprocess.run([sys.executable, "writers.py", kind, d],
                                   capture_output=True, text=True, timeout=1200)
                info = json.loads(q.stdout.strip().splitlines()[-1])
                info["exit"] = q.returncode
            except Exception as exc:
                info = {"error": "%s: %s" % (type(exc).__name__, exc),
                        "files": [], "loaded": {}}
            info["dir"] = d
            written[kind] = info
        rep["writers"] = written
        lz4_extra = 1 if "model.joblib.lz4" in written.get("joblib_c", {}).get("files", []) else 0

        def ran_ok(kind):
            w = written.get(kind, {})
            return "not_run" not in w and not w.get("error")

        got = {}
        ok_all = True
        any_run = False
        for kind in WRITERS:
            w = written[kind]
            if "not_run" in w:
                got[kind] = w
                continue
            any_run = True
            want = EXPECT_FILES[kind] + (lz4_extra if kind == "joblib_c" else 0)
            ok = (not w.get("error") and len(w.get("files", [])) == want
                  and len(w.get("loaded", {})) == want)
            ok_all = ok_all and ok
            got[kind] = {"files": w.get("files"), "loaded": len(w.get("loaded", {})),
                         "error": w.get("error"), "ok": ok}
        row("W0", "writers wrote and re-loaded every file", "all ok",
            ok_all if any_run else None, got)

        g1, f1, f2, f3 = {}, {}, {}, {}
        g1_ok = f1_ok = f2_ok = True
        f3_ok = None
        for kind in WRITERS:
            if not ran_ok(kind):
                continue
            d = written[kind]["dir"]
            files = sorted(written[kind]["files"])
            b = scan(base, d)
            t = scan(tree, d)
            g1[kind] = sorted(b["files"] or {}) if b["files"] is not None else "bad json"
            f1[kind] = sorted(t["files"] or {}) if t["files"] is not None else "bad json"
            g1_ok = g1_ok and g1[kind] == []
            f1_ok = f1_ok and f1[kind] == files
            scans = t["files"] or {}
            if kind == "pd_params":
                hi = {n: rules(fs) for n, fs in scans.items()}
                f3_ok = bool(scans) and all(
                    worst(fs) < 3 and not any(x[0] == "PKL007" for x in fs)
                    for fs in scans.values())
                f3 = {"scan": hi, "folder_exit": t["exit"]}
            else:
                f2[kind] = {"scan": {n: rules(fs) for n, fs in scans.items()},
                            "folder_exit": t["exit"]}
                f2_ok = f2_ok and t["exit"] == 0 and all(
                    worst(fs) < 2 for fs in scans.values()) and bool(scans)
        row("G1", "0.12.1 folder walk of the writer folders", "keeps nothing",
            g1_ok if g1 else None, g1)
        row("F1", "0.13.0 folder walk of the writer folders",
            "keeps exactly the written files", f1_ok if f1 else None, f1)
        row("F2", "0.13.0 on honest torch and joblib files",
            "nothing at or above MEDIUM; folder exit 0", f2_ok if f2 else None, f2)
        row("F3", "0.13.0 on honest paddle.save files",
            "no HIGH or CRITICAL; no PKL007 (MEDIUM recorded)", f3_ok, f3)

        # ---- negative controls and documented limit ----
        if ran_ok("controls"):
            d = written["controls"]["dir"]
            b, t = scan(base, d), scan(tree, d)
            c_ok = (b["files"] == {} and t["files"] == {} and t["exit"] == 0)
            row("C1", "plain tar / tar.gz / txt.gz / tar.xz",
                "neither version keeps them; 0.13.0 exits 0", c_ok,
                {"base": b["files"], "tree": t["files"], "tree_exit": t["exit"]})
        else:
            row("C1", "plain tar / tar.gz / txt.gz / tar.xz",
                "neither version keeps them; 0.13.0 exits 0", None,
                written.get("controls"))
        if ran_ok("limits"):
            d = written["limits"]["dir"]
            b, t = scan(base, d), scan(tree, d)
            e = scan(tree, os.path.join(d, "model.gz"))
            rep["L1_bare_gz_limit"] = {
                "base_walk": sorted(b["files"] or {}),
                "tree_walk": sorted(t["files"] or {}),
                "explicit_file": {"exit": e["exit"],
                                  "rules": {n: rules(fs) for n, fs in (e["files"] or {}).items()}}}

        # ---- Hugging Face published files ----
        man = jload(os.path.join("hub", "manifest.json"), {})
        lists = man.get("lists", {})
        n_listed = sum(v for v in lists.values() if isinstance(v, int))
        row("H1", "gate: models listed", ">= 1000", n_listed >= 1000,
            {"lists": lists, "models": man.get("models_listed")})
        counts = man.get("name_counts", {})
        row("H2", "census: a .pdparams/.pdopt name among the listed models",
            ">= 1", (counts.get("paddle") or 0) >= 1 if counts else False,
            {"name_counts": counts, "ok_by_class": man.get("ok_by_class"),
             "skipped_gated": len(man.get("skipped_gated", []))})
        hub_files = [f for f in man.get("files", []) if f.get("status") == "ok"]
        h3, h3_med, h4_bad = {}, {}, {}
        h3_ok = True
        hub_scans = {}
        for f in hub_files:
            path = f["path"]
            folder = os.path.dirname(path)
            key = "%s/%s" % (f["model"], f["rfilename"])
            b, t = scan(base, folder), scan(tree, folder)
            name = os.path.basename(path)
            bk = sorted(b["files"] or {})
            tk = sorted(t["files"] or {})
            if bk != [] or tk != [name]:
                h4_bad[key] = {"base": bk, "tree": tk}
            fs = (t["files"] or {}).get(name)
            if fs is None:
                h3_ok = False
                h3[key] = "not scanned (exit %s): %s" % (t["exit"], t["err"][-200:])
                continue
            hub_scans[key] = {"class": f.get("class"), "rules": rules(fs)}
            if worst(fs) >= 3:
                h3_ok = False
                h3[key] = rules(fs)
            elif worst(fs) == 2:
                h3_med[key] = rules(fs)
        rep["hub_scans"] = hub_scans
        row("H3", "0.13.0 on published files of these names",
            "no HIGH or CRITICAL (n >= 5)",
            (h3_ok if len(hub_files) >= 5 else None),
            {"n": len(hub_files), "high_or_critical": h3, "medium": h3_med})
        row("H4", "folder walks of published files",
            "0.12.1 keeps none; 0.13.0 keeps each",
            (not h4_bad) if hub_files else None,
            {"n": len(hub_files), "bad": h4_bad})

        # ---- explicit-file results unchanged (the patch touches only walks) ----
        diffs = {}
        n_e = 0
        targets = []
        for kind in WRITERS + ("limits",):
            if ran_ok(kind):
                d = written[kind]["dir"]
                targets += [os.path.join(d, n) for n in written[kind]["files"]]
        targets += [f["path"] for f in hub_files]
        for path in targets:
            b, t = scan(base, path), scan(tree, path)
            n_e += 1
            if b["files"] != t["files"] or b["exit"] != t["exit"]:
                diffs[path] = {"base": b, "tree": t}
        row("E1", "explicit-file scans identical in 0.12.1 and 0.13.0",
            "no difference", (not diffs) if n_e else None,
            {"n": n_e, "diffs": diffs})
    except Exception:
        rep["error"] = traceback.format_exc()[-3000:]

    graded = [r for r in rows if r["result"] != "NOT_RUN"]
    summary = {"check_version": 2,
               "held": sum(1 for r in graded if r["result"] == "PASS"),
               "graded": len(graded),
               "not_run": [r["id"] for r in rows if r["result"] == "NOT_RUN"],
               "release_rows_all_pass": all(
                   r["result"] == "PASS" for r in rows
                   if r["id"] in ("P1", "V1", "S1", "S2", "F1", "C1", "E1")),
               "rows": rows, "reported": rep}
    with open(os.path.join(out, "walk_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"held": summary["held"], "graded": summary["graded"],
                      "not_run": summary["not_run"],
                      "release_rows_all_pass": summary["release_rows_all_pass"],
                      "rows": [[r["id"], r["result"]] for r in rows]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
