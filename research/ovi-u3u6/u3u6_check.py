#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check: openvino_ir_scan 0.1.1 vs 0.1.2 on u3/u6 Consts.

Pre-registered in research/PREREG_OVI_U3U6.md before job ovi-u3u6-v1 ran.
Writes one Const-only model per element type and element count with
openvino.save_model (each in a child process), reads the declared Const
size back from the .xml, and scans honest and edited copies with the
original scanner (ORIG) and the patched one (TREE). Asks the OpenVINO
runtime, in a child process, only to read the honest files. No network.
Never raises: errors go into the summary and the script exits 0.

Usage: u3u6_check.py --out OUT --orig ORIG_DIR --tree TREE
       u3u6_check.py --build ET N DEST     (child)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import importlib.util
import json
import math
import os
import re
import shutil
import subprocess
import sys
import traceback

SELF = os.path.abspath(__file__)
TYPES = {"u1": 1, "u2": 2, "u3": 3, "u4": 4, "u6": 6, "i4": 4, "nf4": 4,
         "u8": 8}
COUNTS = (8, 10, 12, 16)
CONST_RE = re.compile(
    r'<layer\b[^>]*\btype="Const"[^>]*>\s*<data\b([^>]*?)/?>')
READ = ("import sys\nimport openvino as ov\n"
        "try:\n    ov.Core().read_model(sys.argv[1])\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__, str(exc)[:200]); sys.exit(3)\n"
        "print('loaded')\n")


def child_build(et, n, dest):
    try:
        import numpy as np
        import openvino as ov
        t = getattr(ov.Type, et)
        hi = 2 ** TYPES[et] - 1 if et.startswith("u") else 1
        vals = [(i * 5) % (hi + 1) for i in range(n)]
        errors = []
        const = None
        for how in ("list", "tensor"):
            try:
                if how == "list":
                    const = ov.op.Constant(t, ov.Shape([n]), vals)
                else:
                    tensor = ov.Tensor(t, ov.Shape([n]))
                    const = ov.op.Constant(tensor)
                print("constructor %s" % how, flush=True)
                break
            except Exception as exc:
                errors.append("%s: %s: %s" % (how, type(exc).__name__,
                                              str(exc)[:160]))
        if const is None:
            print("error " + " | ".join(errors), flush=True)
            return 3
        const.set_friendly_name("c_%s_%d" % (et, n))
        model = ov.Model([const.output(0)], [], "m_%s_%d" % (et, n))
        os.makedirs(dest, exist_ok=True)
        ov.save_model(model, os.path.join(dest, "model.xml"),
                      compress_to_fp16=False)
        print("saved", flush=True)
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


def rules(mod, xml):
    return sorted({f["rule"] for f in mod.scan_file(xml)})


def const_attrs(xml):
    with open(xml, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    out = []
    for m in CONST_RE.finditer(text):
        a = m.group(1)
        get = lambda k: (re.search(r'\b%s="([^"]*)"' % k, a) or [None,
                                                                 None])[1]
        out.append({"element_type": get("element_type"),
                    "shape": get("shape"), "size": get("size"),
                    "offset": get("offset"), "span": (m.start(1), m.end(1))})
    return text, out


def run(args):
    reported = {}
    try:
        with open("setup_report.json", encoding="utf-8") as fh:
            reported["setup"] = json.load(fh)
    except Exception as exc:
        reported["setup"] = "missing: %s" % exc
    orig = load("ovi_orig", os.path.join(args.orig, "openvino_ir_scan.py"))
    new = load("ovi_new", os.path.join(args.tree, "openvino_ir_scan.py"))
    reported["versions"] = [orig.__version__, new.__version__]
    rows = []

    def add(rid, case, expected, result, got=None, reason=""):
        r = {"id": rid, "case": case, "expected": expected, "result": result}
        if got is not None:
            r["got"] = got
        if reason:
            r["reason"] = reason
        rows.append(r)

    files = os.path.join(args.out, "files")
    honest = {}
    builds = {}
    for et in TYPES:
        for n in COUNTS:
            dest = os.path.join(files, "honest", "%s_%d" % (et, n))
            try:
                p = subprocess.run([sys.executable, SELF, "--build", et,
                                    str(n), dest], capture_output=True,
                                   text=True, timeout=300)
                rc, tail = p.returncode, (p.stdout + p.stderr).strip()[-300:]
            except Exception as exc:
                rc, tail = None, str(exc)
            builds["%s_%d" % (et, n)] = [rc, tail]
            xml = os.path.join(dest, "model.xml")
            if rc == 0 and os.path.isfile(xml):
                honest[(et, n)] = xml
    reported["builds"] = builds
    declared = {}
    for (et, n), xml in honest.items():
        _text, cs = const_attrs(xml)
        mine = [c for c in cs if (c["element_type"] or "").lower() == et]
        if len(mine) == 1 and mine[0]["size"] is not None:
            declared[(et, n)] = int(mine[0]["size"])
    reported["declared_sizes"] = {"%s_%d" % k: v for k, v in
                                  sorted(declared.items())}

    def tight(et, n):
        return math.ceil(n * TYPES[et] / 8)

    def split(et, n):
        per = {"u3": 8, "u6": 4}[et]
        return 3 * math.ceil(n / per)

    # L1: the 2026.4.1 layout of u3/u6 (split, 3-byte units).
    g = {"%s_%d" % k: [v, split(*k), tight(*k)] for k, v in
         sorted(declared.items()) if k[0] in ("u3", "u6")}
    if g:
        add("L1", "declared size of u3/u6 Consts written by save_model",
            "3 * ceil(n / per) (split layout)",
            "PASS" if all(v[0] == v[1] for v in g.values()) else "FAIL", g)
        add("L2", "declared size of u3/u6 Consts vs the tight size",
            "never below ceil(n * bits / 8)",
            "PASS" if all(v[0] >= v[2] for v in g.values()) else "FAIL", g)
    else:
        for rid in ("L1", "L2"):
            add(rid, "u3/u6 Consts", "", "NOT RUN",
                reason="no u3/u6 model written: %r" % {
                    k: v for k, v in builds.items() if k[:2] in ("u3", "u6")})

    def scan_all(mod, keys):
        return {"%s_%d" % k: rules(mod, honest[k]) for k in keys}

    if honest:
        g0 = scan_all(orig, sorted(honest))
        add("H1", "0.1.1 on every honest file", "no finding",
            "PASS" if all(v == [] for v in g0.values()) else "FAIL",
            {k: v for k, v in g0.items() if v} or len(g0))
        g1 = scan_all(new, sorted(honest))
        add("H2", "0.1.2 on every honest file", "no finding",
            "PASS" if all(v == [] for v in g1.values()) else "FAIL",
            {k: v for k, v in g1.items() if v} or len(g1))
    else:
        for rid in ("H1", "H2"):
            add(rid, "honest files", "", "NOT RUN", reason="none written")

    # Edited copies: declared size one byte below the tight size; and
    # shape [2^62, 16].
    edited = {}
    for (et, n), xml in sorted(honest.items()):
        if n != 10 or (et, n) not in declared:
            continue
        text, cs = const_attrs(xml)
        mine = [c for c in cs if (c["element_type"] or "").lower() == et]
        a0, a1 = mine[0]["span"]
        attrs = text[a0:a1]
        for kind in ("short", "huge"):
            if kind == "short":
                na = re.sub(r'\bsize="\d+"', 'size="%d"' % (tight(et, n) - 1),
                            attrs, count=1)
            else:
                na = re.sub(r'\bshape="[^"]*"',
                            'shape="4611686018427387904, 16"', attrs, count=1)
            d = os.path.join(files, "edited", "%s_%s" % (et, kind))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "model.xml"), "w",
                      encoding="utf-8") as fh:
                fh.write(text[:a0] + na + text[a1:])
            shutil.copyfile(xml[:-4] + ".bin", os.path.join(d, "model.bin"))
            edited[(et, kind)] = os.path.join(d, "model.xml")
    reported["edited"] = sorted("%s_%s" % k for k in edited)

    def edit_rows(rid, kind, rule):
        have = {et for (et, k) in edited if k == kind}
        if not {"u3", "u6"} <= have:
            for r in (rid + "a", rid + "b"):
                add(r, kind, "", "NOT RUN",
                    reason="u3/u6 %s copies not written" % kind)
            return
        g0 = {et: rules(orig, edited[(et, kind)]) for et in sorted(have)}
        g1 = {et: rules(new, edited[(et, kind)]) for et in sorted(have)}
        others = [et for et in have if et not in ("u3", "u6")]
        if kind == "short":
            others = [et for et in others if tight(et, 10) >= 2]
        add(rid + "a", "0.1.1 on %s copies" % kind,
            "u3/u6: no finding (the gap); every other type: %s" % rule,
            "PASS" if (g0["u3"] == [] and g0["u6"] == [] and others and
                       all(g0[et] == [rule] for et in others)) else "FAIL",
            g0)
        add(rid + "b", "0.1.2 on %s copies" % kind, "every type: %s" % rule,
            "PASS" if all(v == [rule] for v in g1.values()) else "FAIL", g1)

    edit_rows("T", "short", "OVI005")
    edit_rows("O", "huge", "OVI004")

    # R0: the runtime reads every honest u3/u6 file.
    targets = {k: v for k, v in honest.items() if k[0] in ("u3", "u6")}
    if targets:
        got = {}
        for k, xml in sorted(targets.items()):
            try:
                p = subprocess.run([sys.executable, "-c", READ, xml],
                                   capture_output=True, text=True,
                                   timeout=180)
                got["%s_%d" % k] = ("loaded" if p.returncode == 0 else
                                    "rc %d %s" % (p.returncode,
                                                  p.stdout.strip()[-120:]))
            except Exception as exc:
                got["%s_%d" % k] = "error %s" % exc
        add("R0", "OpenVINO read_model on honest u3/u6 files", "loaded",
            "PASS" if all(v == "loaded" for v in got.values()) else "FAIL",
            got)
    else:
        add("R0", "runtime read", "", "NOT RUN", reason="no u3/u6 files")

    # S1: the full suite on the patched tree (written by run_tests.py).
    try:
        with open(os.path.join(args.out, "tests_summary.json")) as fh:
            ts = json.load(fh)
        add("S1", "full unit-test suite with 0.1.2", "no failure or error",
            "PASS" if ts.get("ok") else "FAIL",
            {"ran": ts.get("ran"), "failures": ts.get("failures"),
             "errors": ts.get("errors"), "skipped": ts.get("skipped")})
    except Exception as exc:
        add("S1", "full suite", "", "NOT RUN", reason="no tests_summary: %s"
            % exc)
    return reported, rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--orig")
    ap.add_argument("--tree")
    ap.add_argument("--build", nargs=3)
    args = ap.parse_args(argv)
    if args.build:
        et, n, dest = args.build
        return child_build(et, int(n), dest)
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
    with open(os.path.join(args.out, "u3u6_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"], json.dumps(r.get("got", ""),
                                               default=str)[:600],
              r.get("reason", ""))
    print("reported:", json.dumps(reported, default=str)[:3000])
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
