#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Pre-registered check (research/PREREG_NEMO_LEGACY.md): does
nemo_container_scan read every pickle torch.load reads from the checkpoint
inside a .nemo?

1. Writes honest files with the real writers: torch.save checkpoints in the
   legacy format (_use_new_zipfile_serialization=False) and in the default
   zip format, each put in a tar the way NeMo's save_to does it
   (tarfile "w:", tar.add(folder, arcname=".")), plus a gzip tar (older NeMo
   releases) and a config-only tar.
2. Ground truth from the loader itself, on these checkpoints only: torch.load
   (weights_only=False, our own files, sealed container, no network) through
   a recording pickle module that logs every find_class call and where each
   pickle the loader reads ends. Hub files are never loaded.
3. Runs nemo_container_scan 0.2.0 (BASE) and the patched 0.3.0 (TREE), each
   in its own process, and model-file-scan's CLI from both.
4. Grades the rows; writes OUT/nemo_legacy_summary.json. Always exits 0.

Usage: nemo_check.py --out OUT --tree TREE --base BASE

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import collections
import json
import os
import pickle
import re
import shutil
import subprocess
import sys
import tarfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
YAML = ("name: tiny-mlp\ntarget: mv2.check.TinyMLP\n"
        "model:\n  in_features: 4\n  hidden: 3\n  out_features: 2\n")
LEGACY = ("L1", "L2", "L3", "L4")
ZIPPED = ("Z1", "Z2")
CASES = LEGACY + ZIPPED + ("C1",)
NEW_TESTS = 16
RELEASE_ROWS = ("P1", "V1", "S1", "S2", "W1", "G1", "B1", "F1", "F2", "F3",
                "F4", "E1")
MAGIC_LE = bytes.fromhex("6cfc9c46f9206aa85019")


# -- writers ------------------------------------------------------------------

def write_cases(root):
    """Returns (report, {case: .nemo path}, {case: checkpoint path})."""
    rep, nemos, ckpts = {}, {}, {}
    ndir = os.path.join(root, "nemo")
    for d in (ndir, os.path.join(root, "ckpt"), os.path.join(root, "stage")):
        os.makedirs(d, exist_ok=True)
    saves = {}
    try:
        import torch
        rep["torch"] = torch.__version__
        torch.manual_seed(0)
        net = torch.nn.Sequential(torch.nn.Linear(4, 3), torch.nn.ReLU(),
                                  torch.nn.Linear(3, 2))
        legacy = {"_use_new_zipfile_serialization": False}

        def l3(path):
            opt = torch.optim.SGD(net.parameters(), lr=0.1, momentum=0.9)
            net(torch.randn(5, 4)).sum().backward()
            opt.step()
            torch.save({"epoch": 3, "state_dict": net.state_dict(),
                        "optimizer": opt.state_dict()}, path, **legacy)
        saves = {
            "L1": lambda p: torch.save(net.state_dict(), p, **legacy),
            "L2": lambda p: torch.save(net.state_dict(), p, pickle_protocol=4,
                                       **legacy),
            "L3": l3,
            "L4": lambda p: torch.save(net.state_dict(), p, **legacy),
            "Z1": lambda p: torch.save(net.state_dict(), p),
            "Z2": lambda p: torch.save(net.state_dict(), p, pickle_protocol=4),
        }
    except Exception as exc:
        rep["torch"] = "error: %s: %s" % (type(exc).__name__, exc)
    for case in CASES:
        stage = os.path.join(root, "stage", case)
        try:
            os.makedirs(stage, exist_ok=True)
            with open(os.path.join(stage, "model_config.yaml"), "w",
                      encoding="utf-8") as fh:
                fh.write(YAML)
            if case != "C1":
                if case not in saves:
                    raise RuntimeError("torch not available")
                ck = os.path.join(stage, "model_weights.ckpt")
                saves[case](ck)
                keep = os.path.join(root, "ckpt", case + ".ckpt")
                shutil.copyfile(ck, keep)
                ckpts[case] = keep
            path = os.path.join(ndir, case.lower() + ".nemo")
            mode = "w:gz" if case == "L4" else "w:"
            with tarfile.open(path, mode) as tar:  # as NeMo's save_to does
                tar.add(stage, arcname=".")
            nemos[case] = path
            rep[case] = "ok"
        except Exception as exc:
            rep[case] = "error: %s: %s" % (type(exc).__name__, exc)
    return rep, nemos, ckpts


# -- loader ground truth (our own files only) ------------------------------------

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


def ground_truth(path):
    rec = {"finds": [], "ends": [], "error": None}
    try:
        import torch
        torch.load(path, weights_only=False, pickle_module=recording_module(rec))
    except Exception as exc:
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
    rec["finds"] = sorted(set(rec["finds"]))
    return rec


# -- scanners -------------------------------------------------------------------

def probe(vdir, files, out_json):
    try:
        subprocess.run([sys.executable, os.path.join(HERE, "probe_nemo.py"),
                        vdir, out_json] + list(files), timeout=1800,
                       capture_output=True, text=True)
        with open(out_json, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc), "files": {}}


def mfs_cli(tree, args):
    try:
        p = subprocess.run([sys.executable,
                            os.path.join(tree, "model_file_scan.py")] + args,
                           capture_output=True, text=True, timeout=1800,
                           cwd=tree)
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            doc = None
        return {"exit": p.returncode, "json": doc,
                "stderr": p.stderr.strip()[-300:]}
    except Exception as exc:
        return {"exit": None, "error": "%s: %s" % (type(exc).__name__, exc)}


def findings_of(res, path):
    return (res.get("files", {}).get(path) or {}).get("findings")


def weights_member(res, path):
    members = (res.get("files", {}).get(path) or {}).get("members") or {}
    for name, m in members.items():
        if name.rsplit("/", 1)[-1] == "model_weights.ckpt":
            return m
    return None


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
    v = {"base_nemo": ver(base, "nemo_container_scan.py"),
         "tree_nemo": ver(tree, "nemo_container_scan.py"),
         "base_mfs": ver(base, "model_file_scan.py"),
         "tree_mfs": ver(tree, "model_file_scan.py")}
    rows["V1"] = row(v == {"base_nemo": "0.2.0", "tree_nemo": "0.3.0",
                           "base_mfs": "0.12.1", "tree_mfs": "0.12.1"}, v)

    tests = read_json(os.path.join(out, "tests_summary.json")) or {}
    btests = read_json(os.path.join(out, "tests_base.json")) or {}
    summary["S0_base_suite"] = btests
    rows["S1"] = row(bool(tests.get("ok")) and isinstance(btests.get("ran"), int)
                     and tests.get("ran") == btests["ran"] + NEW_TESTS,
                     {"tree": {k: tests.get(k) for k in
                               ("ran", "failures", "errors", "skipped", "error")},
                      "base_ran": btests.get("ran"),
                      "base_ok": btests.get("ok")})
    try:
        p = subprocess.run([sys.executable, "-m", "unittest", "-v",
                            "test_nemo_container_scan_streams"], cwd=tree,
                           capture_output=True, text=True, timeout=900)
        m = re.search(r"Ran (\d+) tests?", p.stderr)
        ran = int(m.group(1)) if m else None
        rows["S2"] = row(p.returncode == 0 and ran == NEW_TESTS,
                         {"exit": p.returncode, "ran": ran,
                          "tail": p.stderr.strip()[-900:]})
    except Exception as exc:
        rows["S2"] = row(False, "%s: %s" % (type(exc).__name__, exc))

    root = os.path.join(out, "files")
    written, nemos, ckpts = write_cases(root)
    summary["writers"] = written
    heads = {}
    for c, p in ckpts.items():
        with open(p, "rb") as fh:
            heads[c] = fh.read(32)
    summary["ckpt_heads_hex"] = {c: h[:16].hex() for c, h in heads.items()}
    w_ok = sorted(nemos) == sorted(CASES) and all(
        (b"\x8a\x0a" + MAGIC_LE in heads.get(c, b"")) for c in LEGACY) and all(
        heads.get(c, b"")[:4] == b"PK\x03\x04" for c in ZIPPED)
    rows["W1"] = row(w_ok, written)

    gt = {c: ground_truth(p) for c, p in ckpts.items()}
    summary["ground_truth"] = gt
    g1 = {}
    for c in LEGACY + ZIPPED:
        r = gt.get(c)
        if not r:
            g1[c] = "not written"
            continue
        g1[c] = {"error": r["error"], "pickles_read": len(r["ends"]),
                 "ordered_dict": "collections OrderedDict" in r["finds"],
                 "rebuild": "torch._utils _rebuild_tensor_v2" in r["finds"]}
    rows["G1"] = row(len(g1) == 6 and all(
        isinstance(x, dict) and not x["error"] and x["ordered_dict"]
        and x["rebuild"] and (x["pickles_read"] == 5 if c in LEGACY else True)
        for c, x in g1.items()), g1)

    plist = [nemos[c] for c in CASES if c in nemos]
    old = probe(base, plist, os.path.join(out, "probe_base.json"))
    new = probe(tree, plist, os.path.join(out, "probe_tree.json"))
    summary["probe_versions"] = [old.get("version"), new.get("version")]

    b1, f1, f2, f3 = {}, {}, {}, {}
    for c in CASES:
        p = nemos.get(c)
        if not p:
            continue
        fo, fn = findings_of(old, p), findings_of(new, p)
        if c in LEGACY:
            b1[c] = {"base_findings": fo}
            f1[c] = {"rules": sorted({x.get("rule") for x in (fn or [])}),
                     "evidence": [x.get("evidence") for x in (fn or [])]}
        if c in gt:
            wm = weights_member(new, p) or {}
            have = set()
            for pk in wm.get("pickles", []):
                have |= set(pk.get("imports", []))
            wo = weights_member(old, p) or {}
            had = set()
            for pk in wo.get("pickles", []):
                had |= set(pk.get("imports", []))
            f2[c] = {"loader": gt[c]["finds"],
                     "missing_new": sorted(set(gt[c]["finds"]) - have),
                     "missing_old": sorted(set(gt[c]["finds"]) - had)}
        if c in ("Z1", "Z2", "C1"):
            f3[c] = {"identical": fo == fn,
                     "same_rules": (sorted(x.get("rule") for x in (fo or []))
                                    == sorted(x.get("rule") for x in (fn or []))),
                     "base": fo, "tree": fn}
    rows["B1"] = row(len(b1) == 4 and all(x["base_findings"] == []
                                          for x in b1.values()), b1)
    rows["F1"] = row(len(f1) == 4 and all(
        x["rules"] == ["NEMO010"] and len(x["evidence"]) == 1
        and "legacy torch.save, 5 of 5 pickles" in (x["evidence"][0] or "")
        for x in f1.values()), f1)
    rows["F2"] = row(len(f2) == 6 and all(not x["missing_new"]
                                          for x in f2.values()), f2)
    rows["F3"] = row(len(f3) == 3 and f3["Z1"]["identical"]
                     and f3["C1"]["identical"] and f3["C1"]["tree"] == []
                     and f3["Z2"]["same_rules"], f3)

    f4 = {}
    for c in CASES:
        p = nemos.get(c)
        if not p:
            continue
        f4[c] = {"tree_exit": mfs_cli(tree, ["--json", p]).get("exit"),
                 "base_exit": mfs_cli(base, ["--json", p]).get("exit")}
    want = {c: (0 if c == "C1" else 1) for c in CASES}
    rows["F4"] = row(len(f4) == 7 and all(f4[c]["tree_exit"] == want[c]
                                          for c in f4), f4)

    folder = mfs_cli(tree, ["--json", os.path.join(root, "nemo")])
    nfiles = len(((folder.get("json") or {}).get("files")) or [])
    rows["E1"] = row(folder.get("exit") == 1 and nfiles == len(CASES),
                     {"exit": folder.get("exit"), "files": nfiles,
                      "stderr": folder.get("stderr")})

    # -- Hub (headers only; never loaded) -------------------------------------
    census = read_json(os.path.join(HERE, "hub", "nemo_census.json")) or {}
    files = census.get("files") or []
    conts = collections.Counter(e.get("container") or "error" for e in files)
    walked = [e for e in files if e.get("container") == "plain"
              and e.get("weights")]
    wkinds = collections.Counter()
    for e in walked:
        for w in e["weights"]:
            wkinds[w["kind"]] += 1
    mkinds = collections.Counter()
    pickle_members = collections.Counter()
    for e in files:
        for m in e.get("members") or []:
            mkinds[m["kind"]] += 1
            if m["kind"] in ("legacy", "pickle", "zip"):
                pickle_members[m["name"].rsplit("/", 1)[-1]] += 1
    summary["hub"] = {
        "list": census.get("list"), "planned": census.get("planned"),
        "files": len(files), "requests": census.get("requests"),
        "containers": dict(conts),
        "walked_with_weights": len(walked),
        "weights_kinds": dict(wkinds), "member_kinds": dict(mkinds),
        "pickle_or_zip_member_names": dict(pickle_members.most_common(25)),
        "capped": sum(1 for e in files if e.get("capped")),
        "walk_errors": sum(1 for e in files if e.get("walk_error")),
        "errors": sum(1 for e in files if e.get("error")),
        "legacy_files": [{k: e.get(k) for k in ("rank", "model", "rfilename",
                                                 "size", "last_modified")}
                         for e in walked
                         if any(w["kind"] == "legacy" for w in e["weights"])]}
    rows["H1"] = row(len(walked) >= 60, {"walked_with_weights": len(walked)})
    nweights = sum(wkinds.values())
    share = 100.0 * wkinds.get("legacy", 0) / nweights if nweights else None
    rows["H2"] = row(share is not None and share <= 1.0,
                     {"legacy_pct": round(share, 2) if share is not None
                      else None, "legacy": wkinds.get("legacy", 0),
                      "of": nweights})
    hub_files = [os.path.join(HERE, d["path"]) for d in census.get("downloads", [])
                 if d.get("status") == "ok"]
    if hub_files:
        ho = probe(base, hub_files, os.path.join(out, "probe_hub_base.json"))
        hn = probe(tree, hub_files, os.path.join(out, "probe_hub_tree.json"))
        h3 = {}
        for p in hub_files:
            h3[os.path.relpath(p, HERE)] = {
                "base_rules": sorted({x.get("rule") for x in
                                      (findings_of(ho, p) or [])}),
                "tree_rules": sorted({x.get("rule") for x in
                                      (findings_of(hn, p) or [])})}
        rows["H3"] = row(all(x["base_rules"] == [] and "NEMO010" in x["tree_rules"]
                             for x in h3.values()), h3)
    else:
        rows["H3"] = row(None, "not run: no legacy .nemo of 100 MB or less")

    graded = {k: r["pass"] for k, r in rows.items()}
    result = {"rows": rows, "graded": graded,
              "held": sorted(k for k, x in graded.items() if x is True),
              "failed": sorted(k for k, x in graded.items() if x is False),
              "not_run": sorted(k for k, x in graded.items() if x is None),
              "release_rows": list(RELEASE_ROWS),
              "release_rows_all_pass": all(graded.get(k) is True
                                           for k in RELEASE_ROWS),
              "summary": summary}
    with open(os.path.join(out, "nemo_legacy_summary.json"), "w",
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
        print("nemo_check crashed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
