#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Pre-registered check (research/PREREG_LEGACY_TORCH.md): does
pickle_model_scan read every pickle the loader reads?

1. Writes honest files with the real writers: four legacy-format torch.save
   files (_use_new_zipfile_serialization=False), one default zip torch.save
   (control), two files of three pickle.dump calls, one single pickle
   (control) and one joblib.dump (control).
2. Ground truth from the loaders themselves, on these files only: torch.load
   (weights_only=False, our own files, sealed container, no network) and a
   pickle.load loop, both through a recording pickle module that logs every
   find_class call and the file offset where each pickle the loader reads
   ends. Hub files are never loaded.
3. Runs pickle_model_scan 0.4.0 (BASE) and the patched 0.5.0 (TREE), each in
   its own process, on every file, and model-file-scan's CLI from TREE.
4. Grades the rows; writes OUT/legacy_summary.json. Always exits 0.

Usage: legacy_check.py --out OUT --tree TREE --base BASE

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import collections
import datetime
import decimal
import json
import os
import pickle
import re
import subprocess
import sys
import types
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER_P2 = bytes.fromhex("80028a0a6cfc9c46f9206aa850192e")
LEGACY = ("T1", "T2", "T3", "T4")
PLAIN_MULTI = ("M1", "M2")
NAMES = {"T1": "pytorch_model.bin", "T2": "checkpoint.pth",
         "T3": "model_p4.pt", "T4": "tensors.pt", "Z1": "zip_model.bin",
         "M1": "records.pkl", "M2": "records_p2.pkl", "S1": "single.pkl",
         "J1": "arrays.joblib"}
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RELEASE_ROWS = ("P1", "V1", "S1", "S2", "W1", "G1", "F1", "F2", "F3", "F4",
                "C1", "E1")


# -- writers ------------------------------------------------------------------

def write_cases(fdir):
    rep = {}
    for c, n in NAMES.items():
        os.makedirs(os.path.join(fdir, c), exist_ok=True)
    path = lambda c: os.path.join(fdir, c, NAMES[c])  # noqa: E731
    try:
        import torch
        rep["torch"] = torch.__version__
        torch.manual_seed(0)
        net = torch.nn.Sequential(torch.nn.Linear(4, 3), torch.nn.ReLU(),
                                  torch.nn.Linear(3, 2))
        legacy = {"_use_new_zipfile_serialization": False}
        jobs = {
            "T1": lambda: torch.save(net.state_dict(), path("T1"), **legacy),
            "T3": lambda: torch.save(net.state_dict(), path("T3"),
                                     pickle_protocol=4, **legacy),
            "Z1": lambda: torch.save(net.state_dict(), path("Z1")),
        }

        def t2():
            opt = torch.optim.SGD(net.parameters(), lr=0.1, momentum=0.9)
            net(torch.randn(5, 4)).sum().backward()
            opt.step()
            torch.save({"epoch": 3, "arch": "tiny-mlp",
                        "state_dict": net.state_dict(),
                        "best_acc1": torch.tensor(0.5),
                        "optimizer": opt.state_dict()}, path("T2"), **legacy)

        def t4():
            base = torch.arange(12, dtype=torch.float32)
            torch.save({"f16": torch.ones(3, dtype=torch.float16),
                        "bf16": torch.zeros(2, dtype=torch.bfloat16),
                        "i64": torch.arange(4), "b": torch.tensor([True, False]),
                        "u8": torch.tensor([1, 2], dtype=torch.uint8),
                        "base": base, "view": base[2:6]}, path("T4"), **legacy)
        jobs["T2"] = t2
        jobs["T4"] = t4
        for c, fn in jobs.items():
            try:
                fn()
                rep[c] = "ok"
            except Exception as exc:
                rep[c] = "error: %s: %s" % (type(exc).__name__, exc)
    except Exception as exc:
        rep["torch"] = "error: %s: %s" % (type(exc).__name__, exc)
    for c, proto in (("M1", 4), ("M2", 2)):
        try:
            with open(path(c), "wb") as fh:
                pickle.dump({"format": "records", "n": 2}, fh, protocol=proto)
                pickle.dump(collections.OrderedDict(a=1, b=[1.5]), fh,
                            protocol=proto)
                pickle.dump([datetime.date(2026, 11, 9),
                             decimal.Decimal("1.25")], fh, protocol=proto)
            rep[c] = "ok"
        except Exception as exc:
            rep[c] = "error: %s: %s" % (type(exc).__name__, exc)
    try:
        with open(path("S1"), "wb") as fh:
            pickle.dump({"w": [1.0, 2.0],
                         "when": datetime.datetime(2026, 11, 9, 3, 0)}, fh,
                        protocol=4)
        rep["S1"] = "ok"
    except Exception as exc:
        rep["S1"] = "error: %s: %s" % (type(exc).__name__, exc)
    try:
        import joblib
        import numpy
        rep["joblib"], rep["numpy"] = joblib.__version__, numpy.__version__
        joblib.dump({"w": numpy.arange(10.0),
                     "labels": numpy.array(["a", "b"], dtype=object)},
                    path("J1"))
        rep["J1"] = "ok"
    except Exception as exc:
        rep["J1"] = "error: %s: %s" % (type(exc).__name__, exc)
    return rep, {c: path(c) for c in NAMES if rep.get(c) == "ok"}


# -- loader ground truth (our own files only) -----------------------------------

def recording_module(rec):
    class RecordingUnpickler(pickle.Unpickler):
        def __init__(self, file, *a, **kw):
            super().__init__(file, *a, **kw)
            self._mv2_file = file

        def find_class(self, module, name):
            rec["finds"].append("%s %s" % (module, name))
            return super().find_class(module, name)

        def load(self):
            out = super().load()
            try:
                rec["ends"].append(self._mv2_file.tell())
            except Exception:
                rec["ends"].append(None)
            return out

    mod = types.ModuleType("mv2_recording_pickle")
    mod.Unpickler = RecordingUnpickler
    mod.load = lambda f, **kw: RecordingUnpickler(f, **kw).load()
    return mod


def ground_truth(case, path):
    rec = {"finds": [], "ends": [], "error": None}
    try:
        if case in LEGACY or case == "Z1":
            import torch
            torch.load(path, weights_only=False,
                       pickle_module=recording_module(rec))
        elif case in PLAIN_MULTI or case == "S1":
            mod = recording_module(rec)
            with open(path, "rb") as fh:
                while True:
                    try:
                        mod.Unpickler(fh).load()
                    except EOFError:
                        break
        else:
            return None
    except Exception as exc:
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
    return rec


# -- scanners -------------------------------------------------------------------

def probe(vdir, files, out_json):
    try:
        subprocess.run([sys.executable, os.path.join(HERE, "probe.py"), vdir,
                        out_json] + list(files), timeout=1800,
                       capture_output=True, text=True)
        with open(out_json, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc), "files": {}}


def mfs_cli(tree, args):
    try:
        p = subprocess.run([sys.executable,
                            os.path.join(tree, "model_file_scan.py")] + args,
                           capture_output=True, text=True, timeout=1800)
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            doc = None
        return {"exit": p.returncode, "json": doc,
                "stderr": p.stderr.strip()[-300:]}
    except Exception as exc:
        return {"exit": None, "error": "%s: %s" % (type(exc).__name__, exc)}


def worst(findings):
    return max([SEV.get(str(f.get("severity", "")).lower(), 0)
                for f in findings] or [-1])


def walk_of(res, path):
    return (res.get("files", {}).get(path) or {}).get("walk") or {}


def findings_of(res, path):
    return (res.get("files", {}).get(path) or {}).get("findings")


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def row(ok, detail):
    return {"pass": ok, "detail": detail}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tree", required=True)
    ap.add_argument("--base", required=True)
    a = ap.parse_args()
    out, tree, base = (os.path.abspath(a.out), os.path.abspath(a.tree),
                       os.path.abspath(a.base))
    os.makedirs(out, exist_ok=True)
    rows, summary = {}, {}

    patch = read_json(os.path.join(out, "patch_report.json")) or {}
    rows["P1"] = row(bool(patch.get("ok")), patch.get("files"))

    ver_re = re.compile(r'(?m)^__version__\s*=\s*"([0-9.]+)"')

    def ver(d, name):
        try:
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                return ver_re.search(fh.read()).group(1)
        except Exception:
            return None
    v = {"base_pms": ver(base, "pickle_model_scan.py"),
         "tree_pms": ver(tree, "pickle_model_scan.py"),
         "base_mfs": ver(base, "model_file_scan.py"),
         "tree_mfs": ver(tree, "model_file_scan.py")}
    rows["V1"] = row(v == {"base_pms": "0.4.0", "tree_pms": "0.5.0",
                           "base_mfs": "0.12.1", "tree_mfs": "0.12.1"}, v)

    tests = read_json(os.path.join(out, "tests_summary.json")) or {}
    rows["S1"] = row(bool(tests.get("ok")) and (tests.get("ran") or 0) >= 1350,
                     {k: tests.get(k) for k in ("ran", "failures", "errors",
                                                "skipped", "error")})
    summary["S0_base_suite"] = read_json(os.path.join(out, "tests_base.json"))
    try:
        p = subprocess.run([sys.executable, "-m", "unittest", "-v",
                            "test_pickle_model_scan_streams"], cwd=tree,
                           capture_output=True, text=True, timeout=900)
        m = re.search(r"Ran (\d+) tests?", p.stderr)
        ran = int(m.group(1)) if m else None
        rows["S2"] = row(p.returncode == 0 and ran == 15,
                         {"exit": p.returncode, "ran": ran,
                          "tail": p.stderr.strip()[-600:]})
    except Exception as exc:
        rows["S2"] = row(False, "%s: %s" % (type(exc).__name__, exc))

    fdir = os.path.join(out, "files")
    written, files = write_cases(fdir)
    summary["writers"] = written
    rows["W1"] = row(sorted(files) == sorted(NAMES), written)

    gt = {c: ground_truth(c, p) for c, p in files.items()}
    summary["ground_truth"] = gt
    heads = {}
    for c, p in files.items():
        with open(p, "rb") as fh:
            heads[c] = fh.read(32)
    summary["heads_hex"] = {c: h[:16].hex() for c, h in heads.items()}

    g1 = {}
    for c in LEGACY:
        r = gt.get(c)
        if not r:
            g1[c] = "not written"
            continue
        first_ok = (heads[c][:15] == HEADER_P2 if c != "T3"
                    else b"\x8a\x0a" + HEADER_P2[4:14] in heads[c])
        g1[c] = {"error": r["error"], "pickles_read": len(r["ends"]),
                 "header": first_ok,
                 "rebuild": "torch._utils _rebuild_tensor_v2" in r["finds"],
                 "ordered_dict": "collections OrderedDict" in r["finds"]}
    rows["G1"] = row(all(isinstance(x, dict) and not x["error"]
                         and x["pickles_read"] == 5 and x["header"]
                         and x["rebuild"] and x["ordered_dict"]
                         for x in g1.values()) and len(g1) == 4, g1)

    plist = list(files.values())
    old = probe(base, plist, os.path.join(out, "probe_base.json"))
    new = probe(tree, plist, os.path.join(out, "probe_tree.json"))
    summary["probe_versions"] = [old.get("version"), new.get("version")]

    cov = {}
    b1, b2, f1, f2, f3, f4 = {}, {}, {}, {}, {}, {}
    for c, p in files.items():
        r = gt.get(c)
        wo, wn = walk_of(old, p), walk_of(new, p)
        fo, fn = findings_of(old, p), findings_of(new, p)
        if r and r["ends"] and wo:
            end = r["ends"][-1]
            cov[c] = {"loader_pickle_bytes": end, "file_bytes": wo.get("length"),
                      "old_read": (wo.get("stop") or -1) + 1,
                      "new_read": (wn.get("stop") or -1) + 1,
                      "old_pct": round(100.0 * ((wo.get("stop") or -1) + 1)
                                       / end, 2) if end else None,
                      "loader_imports": len(r["finds"]),
                      "old_imports_resolved": len(set(r["finds"])
                                                  & set(wo.get("imports", []))),
                      "new_imports_resolved": len(set(r["finds"])
                                                  & set(wn.get("imports", [])))}
        if c in LEGACY and r:
            b1[c] = {"old_read_is_first_pickle":
                     (wo.get("stop") or -1) + 1 == (r["ends"] or [None])[0],
                     "old_resolves_none": not (set(r["finds"])
                                               & set(wo.get("imports", []))),
                     "old_clean": fo == []}
            f1[c] = {"torch_legacy": wn.get("torch_legacy"),
                     "streams": wn.get("streams"),
                     "reaches_loader_end":
                     (wn.get("stop") or -1) + 1 == (r["ends"] or [None])[-1]}
        if c in PLAIN_MULTI and r:
            later = set(r["finds"]) - set(wo.get("imports", []))
            b2[c] = {"old_read_is_first_pickle":
                     (wo.get("stop") or -1) + 1 == (r["ends"] or [None])[0],
                     "missed_imports": sorted(later)}
            f3[c] = {"streams": wn.get("streams"),
                     "reaches_loader_end":
                     (wn.get("stop") or -1) + 1 == (r["ends"] or [None])[-1]}
        if r and not r["error"]:
            if c == "Z1":
                members = ((new.get("files", {}).get(p) or {}).get("members")
                           or {})
                have = set()
                for w in members.values():
                    have |= set(w.get("imports", []))
            else:
                have = set(wn.get("imports", []))
            f2[c] = {"missing": sorted(set(r["finds"]) - have),
                     "loader_imports": sorted(set(r["finds"]))}
        f4[c] = {"worst_new": worst(fn or []) if fn is not None else None,
                 "rules_new": sorted({x.get("rule") for x in (fn or [])})}
    summary["coverage"] = cov
    rows["B1"] = row(len(b1) == 4 and all(all(x.values()) for x in b1.values()),
                     b1)
    rows["B2"] = row(len(b2) == 2 and all(x["old_read_is_first_pickle"]
                                          and x["missed_imports"]
                                          for x in b2.values()), b2)
    rows["F1"] = row(len(f1) == 4 and all(
        x["torch_legacy"] is True and x["streams"] == 5
        and x["reaches_loader_end"] for x in f1.values()), f1)
    rows["F2"] = row(len(f2) == 8 and all(not x["missing"]
                                          for x in f2.values()), f2)
    rows["F3"] = row(len(f3) == 2 and all(
        x["streams"] == 3 and x["reaches_loader_end"] for x in f3.values()), f3)
    mfs = {c: mfs_cli(tree, ["--json", p]) for c, p in files.items()}
    for c in f4:
        f4[c]["mfs_exit"] = mfs[c].get("exit")
    rows["F4"] = row(len(f4) == 9 and all(
        x["worst_new"] is not None and x["worst_new"] <= 1
        and x["mfs_exit"] == 0 for x in f4.values()), f4)

    c1 = {}
    for c in ("Z1", "S1", "J1"):
        p = files.get(c)
        if not p:
            c1[c] = "not written"
            continue
        so = old.get("files", {}).get(p) or {}
        sn = new.get("files", {}).get(p) or {}
        same_walk = True
        for key in ("imports", "stop", "unresolved", "joblib_arrays",
                    "nested_pickles", "rules"):
            if (so.get("walk") or {}).get(key) != (sn.get("walk") or {}).get(key):
                same_walk = False
        for mname, w in (so.get("members") or {}).items():
            wn2 = (sn.get("members") or {}).get(mname) or {}
            if w.get("imports") != wn2.get("imports") or w.get("stop") != wn2.get("stop"):
                same_walk = False
        c1[c] = {"same_findings": so.get("findings") == sn.get("findings"),
                 "same_walk": same_walk}
    rows["C1"] = row(len(c1) == 3 and all(isinstance(x, dict) and all(x.values())
                                          for x in c1.values()), c1)

    folder = mfs_cli(tree, ["--json", fdir])
    nfiles = len(((folder.get("json") or {}).get("files")) or [])
    rows["E1"] = row(folder.get("exit") == 0 and nfiles == len(files),
                     {"exit": folder.get("exit"), "files": nfiles,
                      "stderr": folder.get("stderr")})

    # -- Hub (static only; never loaded) --------------------------------------
    census = read_json(os.path.join(HERE, "hub", "legacy_census.json")) or {}
    hdrs = census.get("headers") or []
    pmb = [h for h in hdrs if h.get("group") == "pytorch_model.bin"
           and h.get("kind")]
    kinds = collections.Counter(h["kind"] for h in pmb)
    summary["hub"] = {"list": census.get("list"),
                      "open_models": census.get("open_models"),
                      "with_pytorch_model_bin":
                      census.get("with_pytorch_model_bin"),
                      "kinds": census.get("kinds"),
                      "pytorch_model_bin_kinds": dict(kinds),
                      "errors": sum(1 for h in hdrs if not h.get("kind"))}
    rows["H1"] = row(len(pmb) >= 100, {"pytorch_model_bin_headers": len(pmb)})
    share = (100.0 * kinds.get("legacy", 0) / len(pmb)) if pmb else None
    rows["H2"] = row(share is not None and share >= 5.0,
                     {"legacy_pct": round(share, 1) if share is not None
                      else None, "legacy": kinds.get("legacy", 0),
                      "of": len(pmb)})
    legacy_rows = [h for h in hdrs if h.get("kind") == "legacy"]
    summary["hub"]["legacy_files"] = [
        {k: h.get(k) for k in ("rank", "model", "rfilename", "size",
                               "last_modified", "downloads")}
        for h in legacy_rows]
    hub_files = [os.path.join(HERE, d["path"]) for d in census.get("downloads", [])
                 if d.get("status") == "ok"]
    if hub_files:
        ho = probe(base, hub_files, os.path.join(out, "probe_hub_base.json"))
        hn = probe(tree, hub_files, os.path.join(out, "probe_hub_tree.json"))
        h3, h4, h5 = {}, {}, {}
        for p in hub_files:
            key = os.path.relpath(p, HERE)
            wo, wn = walk_of(ho, p), walk_of(hn, p)
            fo, fn = findings_of(ho, p) or [], findings_of(hn, p) or []
            h3[key] = {"torch_legacy": wn.get("torch_legacy"),
                       "streams": wn.get("streams"),
                       "pkl000": "PKL000" in {x.get("rule") for x in fn},
                       "old_read": (wo.get("stop") or -1) + 1,
                       "new_read": (wn.get("stop") or -1) + 1,
                       "length": wn.get("length")}
            h4[key] = {"old_imports": len(wo.get("imports", [])),
                       "old_clean": fo == [],
                       "new_imports": len(set(wn.get("imports", [])))}
            h5[key] = {"worst_new": worst(fn),
                       "rules_new": sorted({x.get("rule") for x in fn})}
        rows["H3"] = row(all(x["torch_legacy"] is True and x["streams"] == 5
                             and not x["pkl000"] for x in h3.values()), h3)
        rows["H4"] = row(all(x["old_imports"] == 0 and x["old_clean"]
                             and x["new_imports"] >= 2 for x in h4.values()), h4)
        rows["H5"] = row(all(x["worst_new"] <= 2 for x in h5.values()), h5)
    else:
        for r in ("H3", "H4", "H5"):
            rows[r] = row(None, "not run: no legacy Hub file of 25 MB or less")

    graded = {k: r["pass"] for k, r in rows.items()}
    result = {"rows": rows, "graded": graded,
              "held": sorted(k for k, x in graded.items() if x is True),
              "failed": sorted(k for k, x in graded.items() if x is False),
              "not_run": sorted(k for k, x in graded.items() if x is None),
              "release_rows": list(RELEASE_ROWS),
              "release_rows_all_pass": all(graded.get(k) is True
                                           for k in RELEASE_ROWS),
              "summary": summary}
    with open(os.path.join(out, "legacy_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, default=str)
    print(json.dumps({"held": result["held"], "failed": result["failed"],
                      "not_run": result["not_run"],
                      "release_rows_all_pass": result["release_rows_all_pass"]},
                     indent=1))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("legacy_check crashed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
