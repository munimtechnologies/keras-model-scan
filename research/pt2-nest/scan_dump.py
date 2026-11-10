#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step: scan the fixtures in FX with the keras-model-scan copy in TREE
and dump what it reports (direct findings per file, CLI exits), plus which
archive members the pickle walker was handed for F4 and F6 (row N3).
Run once for ./base (v0.58.0, unchanged) and once for ./tree (patched), each
in its own process so the two copies never mix.

Static only: the scanner reads bytes and disassembles opcodes; nothing is
unpickled or loaded here.

Usage: scan_dump.py TREE FX OUT_JSON

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import subprocess
import sys

NAMES = {"F1": "model.pt", "F2": "model.torchscript", "F3": "model.ptl",
         "F4": "model.pt2", "F5": "weights.pth", "F6": "model_b.pt2"}


def rows_of(findings, fx):
    rows = []
    for f in findings:
        d = f.as_dict() if hasattr(f, "as_dict") else dict(f)
        rows.append({
            "rule": d.get("rule"),
            "severity": str(d.get("severity", "")).upper(),
            "title": d.get("title"),
            "detail": str(d.get("detail") or "")[:600],
            "location": str(d.get("location") or "").replace(fx, "FX")})
    return rows


def main():
    tree, fx, out = (os.path.abspath(a) for a in sys.argv[1:4])
    sys.path.insert(0, tree)
    import model_file_scan as mfs
    import pickle_model_scan as pms
    rep = {"tree": tree, "versions": {"model_file_scan": mfs.__version__,
                                      "pickle_model_scan": pms.__version__},
           "direct": {}, "walked": {}, "cli": {}}
    for key, name in NAMES.items():
        path = os.path.join(fx, name)
        if not os.path.isfile(path):
            continue
        try:
            rep["direct"][key] = rows_of(mfs.scan_path(path), fx)
        except Exception as exc:
            rep["direct"][key] = [{"error": "%s: %s"
                                   % (type(exc).__name__, exc)}]
    # Which members reach the pickle walker (scan_zip looks the function up
    # in its module at call time, so a recording wrapper sees every call).
    real = pms.scan_pickle_bytes
    for key in ("F4", "F6"):
        path = os.path.join(fx, NAMES[key])
        if not os.path.isfile(path):
            continue
        seen = []

        def spy(data, source, _seen=seen):
            _seen.append(source)
            return real(data, source)

        pms.scan_pickle_bytes = spy
        try:
            with open(path, "rb") as fh:
                pms.scan_zip(fh.read(), key)
            rep["walked"][key] = seen
        except Exception as exc:
            rep["walked"][key] = ["<error %s: %s>" % (type(exc).__name__, exc)]
        finally:
            pms.scan_pickle_bytes = real
    targets = [("F1", os.path.join(fx, NAMES["F1"])),
               ("F4", os.path.join(fx, NAMES["F4"])),
               ("F5", os.path.join(fx, NAMES["F5"])), ("dir", fx)]
    for label, target in targets:
        if not os.path.exists(target):
            continue
        try:
            p = subprocess.run([sys.executable,
                                os.path.join(tree, "model_file_scan.py"),
                                "--json", target], capture_output=True,
                               text=True, timeout=600, cwd=tree)
            rep["cli"][label] = {"exit": p.returncode,
                                 "stderr_tail": p.stderr.strip()[-300:]}
        except Exception as exc:
            rep["cli"][label] = {"exit": None, "error": str(exc)[:200]}
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"versions": rep["versions"],
                      "walked": rep["walked"],
                      "cli": {k: v.get("exit") for k, v in rep["cli"].items()}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
