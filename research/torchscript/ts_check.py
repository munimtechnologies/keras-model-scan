#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step: grade the pre-registered rows of research/PREREG_TORCHSCRIPT.md
against model-file-scan v0.57.0 (./tree, unchanged) on the honest files
make_fixtures.py wrote into ./fx.

Static only for the scanner: it reads bytes and disassembles opcodes; it never
unpickles. The global census below also only disassembles (pickletools).

Usage: ts_check.py --out OUT
Writes OUT/torchscript_summary.json and prints held/failed/not_run.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import json
import os
import pickletools
import subprocess
import sys
import zipfile

TREE = os.path.abspath("tree")
FX = os.path.abspath("fx")
NAMES = {"F1": "model.pt", "F2": "model.torchscript", "F3": "model.ptl",
         "F4": "model.pt2", "F5": "weights.pth"}
STRINGS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
           "SHORT_BINSTRING", "BINSTRING", "STRING"}


def globals_in(data):
    """(module, name) pairs a pickle stream names, by disassembly only."""
    out, recent = [], []
    try:
        for op, arg, _pos in pickletools.genops(data):
            if op.name == "GLOBAL":
                mod, _, name = str(arg).partition(" ")
                out.append((mod, name))
            elif op.name == "STACK_GLOBAL" and len(recent) >= 2:
                out.append((recent[-2], recent[-1]))
            if op.name in STRINGS:
                recent = (recent + [str(arg)])[-2:]
    except Exception as exc:  # truncated or not a pickle
        out.append(("<error>", "%s" % type(exc).__name__))
    return out


def zip_globals(path):
    res = {}
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.filename.endswith(".pkl"):
                res[info.filename] = globals_in(zf.read(info.filename))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    sys.path.insert(0, TREE)
    import model_file_scan as mfs
    import pickle_model_scan as pms

    fx_rep = {}
    if os.path.isfile("fixtures_report.json"):
        with open("fixtures_report.json", encoding="utf-8") as fh:
            fx_rep = json.load(fh)
    have = {k: os.path.isfile(os.path.join(FX, n)) for k, n in NAMES.items()}
    path = {k: os.path.join(FX, n) for k, n in NAMES.items()}
    summary = {"versions": {"model_file_scan": mfs.__version__,
                            "pickle_model_scan": pms.__version__,
                            "torch": fx_rep.get("torch")},
               "have": have, "rows": {}, "detail": {}}
    rows = summary["rows"]

    def row(key, ok, why=""):
        rows[key] = {"result": ("not_run" if ok is None else
                                "held" if ok else "failed"), "why": why}

    # P1: torch wrote the four predicted fixtures (F4 is exploratory).
    need = ["F1", "F2", "F3", "F5"]
    row("P1", all(have[k] for k in need),
        "written: %s" % sorted(k for k, v in have.items() if v))

    # W1 / W2: the folder walk.
    kept, _missing = mfs.expand_paths([FX])
    kept_names = sorted(os.path.basename(p) for p in kept)
    summary["detail"]["walk_kept"] = kept_names
    row("W1", "model.pt" in kept_names and "weights.pth" in kept_names
        if have["F1"] and have["F5"] else None, "kept=%s" % kept_names)
    skip_set = [NAMES[k] for k in ("F2", "F3", "F4") if have[k]]
    row("W2", (all(n not in kept_names for n in skip_set)
               if have["F2"] and have["F3"] else None),
        "predicted skipped=%s" % skip_set)

    # D rows: direct scans.
    direct = {}
    for k in NAMES:
        if not have[k]:
            continue
        try:
            found = mfs.scan_path(path[k])
            rows_k = []
            for f in found:
                d = f.as_dict() if hasattr(f, "as_dict") else dict(f)
                rows_k.append({
                    "rule": d.get("rule"),
                    "severity": str(d.get("severity", "")).upper(),
                    "title": d.get("title") or d.get("message"),
                    "detail": str(d.get("detail") or d.get("evidence")
                                  or "")[:240],
                    "location": d.get("location")})
            direct[k] = rows_k
        except Exception as exc:
            direct[k] = [{"error": "%s: %s" % (type(exc).__name__, exc)}]
    summary["detail"]["direct"] = direct
    counts = {k: {} for k in direct}
    for k, fs in direct.items():
        for f in fs:
            sev = f.get("severity", "ERROR")
            counts[k][f.get("rule", "ERR") + ":" + sev] = (
                counts[k].get(f.get("rule", "ERR") + ":" + sev, 0) + 1)
    summary["detail"]["direct_counts"] = counts

    def pkl003(k):
        return [f for f in direct.get(k, []) if f.get("rule") == "PKL003"]

    ts = [k for k in ("F1", "F2", "F3") if have[k]]
    d1 = (all(pkl003(k) and all(f.get("severity") == "MEDIUM" and
                                "__torch__." in f.get("detail", "")
                                for f in pkl003(k)) for k in ts)
          if len(ts) == 3 else None)
    row("D1", d1, "PKL003 per file=%s" % {k: len(pkl003(k)) for k in ts})
    hi = {k: [f.get("rule") for f in fs
              if f.get("severity") in ("CRITICAL", "HIGH") or "error" in f]
          for k, fs in direct.items()}
    row("D2", not any(hi.values()) if direct else None, "high+=%s" % hi)
    if have["F5"]:
        med = [f.get("rule") for f in direct.get("F5", [])
               if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
               or "error" in f]
        row("D3", not med, "F5 medium+=%s" % med)
    else:
        row("D3", None, "F5 missing")

    # G1: global census of the TorchScript pickles, by disassembly only.
    census = {}
    unknown_non_torch = []
    unknown_total = 0
    for k in ts:
        try:
            g = zip_globals(path[k])
        except Exception as exc:
            g = {"<zip error>": [("<error>", type(exc).__name__)]}
        census[k] = {m: sorted(set("%s.%s" % p for p in v))
                     for m, v in g.items()}
        for _member, pairs in g.items():
            for mod, name in pairs:
                if pms._classify(mod, name) == "unknown":
                    unknown_total += 1
                    if not mod.startswith("__torch__"):
                        unknown_non_torch.append("%s.%s" % (mod, name))
    summary["detail"]["global_census"] = census
    row("G1", (unknown_total > 0 and not unknown_non_torch)
        if len(ts) == 3 else None,
        "unknown=%d non-__torch__=%s" % (unknown_total,
                                         sorted(set(unknown_non_torch))))

    # L rows: the loaders' own behaviour (recorded by make_fixtures.py).
    ld = fx_rep.get("loaders", {})
    summary["detail"]["loaders"] = ld

    def ok(label):
        return (ld.get(label) or {}).get("ok")

    l1 = [ok("jit_load_F1"), ok("jit_load_F2"),
          ok("torch_load_F1_weights_only_true"),
          ok("torch_load_F1_weights_only_false")]
    if None in l1:
        row("L1", None, "loader rows missing: %s" % l1)
    else:
        t = (ld.get("torch_load_F1_weights_only_false") or {}).get("type", "")
        row("L1", l1[0] and l1[1] and (l1[2] is False) and l1[3]
            and "Script" in t, "rows=%s type=%s" % (l1, t))
    row("L2", ok("lite_load_F3"), json.dumps(ld.get("lite_load_F3"))[:200])

    # C1: the CLI's default gate (--fail-on medium) on F1 alone.
    cli = {}
    for label, target in (("F1", path["F1"]), ("dir", FX)):
        if label == "F1" and not have["F1"]:
            continue
        try:
            p = subprocess.run([sys.executable,
                                os.path.join(TREE, "model_file_scan.py"),
                                "--json", target], capture_output=True,
                               text=True, timeout=600, cwd=TREE)
            cli[label] = {"exit": p.returncode,
                          "stderr_tail": p.stderr.strip()[-300:]}
        except Exception as exc:
            cli[label] = {"exit": None, "error": str(exc)[:200]}
    summary["detail"]["cli"] = cli
    c1 = (cli.get("F1") or {}).get("exit")
    row("C1", (c1 not in (0, None)) if c1 is not None else None,
        "exit=%s" % c1)

    held = sorted(k for k, v in rows.items() if v["result"] == "held")
    failed = sorted(k for k, v in rows.items() if v["result"] == "failed")
    not_run = sorted(k for k, v in rows.items() if v["result"] == "not_run")
    summary.update({"held": held, "failed": failed, "not_run": not_run})
    with open(os.path.join(args.out, "torchscript_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    for name in ("fixtures_report.json", "setup_report.json",
                 "fetch_report.json"):
        if os.path.isfile(name):
            with open(name, encoding="utf-8") as src, \
                    open(os.path.join(args.out, name), "w",
                         encoding="utf-8") as dst:
                dst.write(src.read())
    print(json.dumps({"held": held, "failed": failed, "not_run": not_run},
                     indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
