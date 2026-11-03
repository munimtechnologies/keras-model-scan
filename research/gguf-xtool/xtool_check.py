#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Cross-tool check: ModelAudit on GGUF files of the newest ggml tensor types.

Pre-registered in research/PREREG_GGUF_XTOOL.md before this job ran. Writes
the same small GGUF files as job gguf-types-v2 with llama.cpp's own gguf-py
(tag b12034): one per tensor type, one holding every type, and an edited
NVFP4 copy whose type id is 44 (GGML_TYPE_COUNT). Then scans each with
promptfoo's ModelAudit:

  rel      modelaudit 0.2.54 (newest PyPI release)
  main     promptfoo/modelaudit main at 415819f, installed with --no-deps
           over 0.2.54's dependencies
  overlay  0.2.54 with only main's gguf_scanner.py copied in (fallback;
           used for grading only if "main" is not valid)

Nothing here uses the network. Telemetry is switched off with the variables
ModelAudit documents. The check never raises: an error is written to the
summary and the script exits 0.

Usage: xtool_check.py --out OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import traceback

import numpy as np
import gguf

TYPES = [
    ("f32", "F32"), ("f16", "F16"), ("q4_0", "Q4_0"), ("q8_0", "Q8_0"),
    ("q4_k", "Q4_K"), ("q6_k", "Q6_K"), ("iq4_xs", "IQ4_XS"),
    ("bf16", "BF16"), ("tq2_0", "TQ2_0"), ("mxfp4", "MXFP4"),
    ("nvfp4", "NVFP4"), ("q1_0", "Q1_0"), ("q2_0", "Q2_0"),
    ("f8_e4m3", "F8_E4M3"),
]
REL_KNOWN = ["f32", "f16", "q4_0", "q8_0", "q4_k", "q6_k", "iq4_xs", "bf16"]
REL_UNKNOWN = ["tq2_0", "mxfp4", "nvfp4", "q1_0", "q2_0", "f8_e4m3"]
NE0 = 256
ROWS = 2
UNKNOWN_RE = re.compile(r"unknown GGML type\D{0,30}?(\d+)")
ENV = dict(os.environ, PROMPTFOO_DISABLE_TELEMETRY="1", NO_ANALYTICS="1",
           CI="true", HOME="/tmp/mahome", NO_COLOR="1")
PROBE = (
    "import json, importlib.metadata as m\n"
    "import modelaudit.scanners.gguf_scanner as g\n"
    "t = getattr(g, '_GGML_TYPE_INFO', None)\n"
    "print(json.dumps({'version': m.version('modelaudit'),"
    " 'file': g.__file__,"
    " 'ids': sorted(int(k) for k in t) if t is not None else None}))\n"
)


def qtype(member):
    return getattr(gguf.GGMLQuantizationType, member, None)


def tensor_data(member, seed):
    rng = np.random.default_rng(seed)
    if member == "F32":
        return rng.standard_normal((ROWS, NE0)).astype(np.float32), None
    if member == "F16":
        return rng.standard_normal((ROWS, NE0)).astype(np.float16), None
    qt = qtype(member)
    block, size = gguf.GGML_QUANT_SIZES[qt]
    if NE0 % block:
        raise ValueError("%s block %d does not divide %d" % (member, block,
                                                              NE0))
    return rng.integers(0, 256, size=(ROWS, NE0 // block * size),
                        dtype=np.uint8), qt


def write_gguf(path, entries):
    w = gguf.GGUFWriter(path, "llama")
    w.add_block_count(1)
    for i, (tname, member) in enumerate(entries):
        arr, raw = tensor_data(member, i)
        if raw is None:
            w.add_tensor(tname, arr)
        else:
            w.add_tensor(tname, arr, raw_dtype=raw)
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file()
    w.close()


def probe(venv):
    py = os.path.join(venv, "bin", "python")
    if not os.path.exists(py):
        return {"error": "no venv"}
    p = subprocess.run([py, "-c", PROBE], capture_output=True, text=True,
                       timeout=300, env=ENV)
    if p.returncode != 0:
        return {"error": (p.stderr or p.stdout).strip()[-800:]}
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as exc:
        return {"error": "probe output: %s %r" % (exc, p.stdout[-300:])}


def walk_findings(obj, acc):
    if isinstance(obj, dict):
        sev = obj.get("severity")
        msg = obj.get("message")
        if isinstance(sev, str) and isinstance(msg, str):
            acc.append((sev.lower(), msg[:200]))
        for v in obj.values():
            walk_findings(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            walk_findings(v, acc)


def scan(venv, path, raw_dir, label):
    exe = os.path.join(venv, "bin", "modelaudit")
    os.makedirs(raw_dir, exist_ok=True)
    out_json = os.path.join(raw_dir, label + ".json")
    res = {}
    for cmd in ([exe, path, "--format", "json", "--output", out_json],
                [exe, "scan", path, "--format", "json", "--output",
                 out_json]):
        if os.path.exists(out_json):
            os.remove(out_json)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=600, env=ENV)
            res = {"exit": p.returncode, "stdout": p.stdout,
                   "stderr": p.stderr}
        except Exception as exc:  # recorded as exit None
            res = {"exit": None, "stdout": "",
                   "stderr": "%s: %s" % (type(exc).__name__, exc)}
        if os.path.exists(out_json):
            break
    text = res["stdout"] + "\n" + res["stderr"]
    if os.path.exists(out_json):
        with open(out_json, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        text += "\n" + body
        try:
            found = []
            walk_findings(json.loads(body), found)
        except Exception:
            found = []
    else:
        found = []
    unknown = sorted(set(int(m) for m in UNKNOWN_RE.findall(text)))
    loud = sorted(set("%s: %s" % f for f in found
                      if f[0] in ("warning", "critical", "error")))
    return {"exit": res["exit"], "json_written": os.path.exists(out_json),
            "unknown_types": unknown,
            "type_validation_mentions": text.count("Tensor Type Validation"),
            "inconclusive_mentions": text.lower().count("inconclusive"),
            "loud": loud[:6],
            "stderr_tail": res["stderr"].strip().splitlines()[-3:]}


def run(args):
    out = args.out
    os.makedirs(ENV["HOME"], exist_ok=True)
    files = os.path.join(out, "files")
    shutil.rmtree(files, ignore_errors=True)
    honest = os.path.join(files, "honest")
    os.makedirs(honest)
    reported = {"type_ids": {}, "write_errors": {}}
    try:
        with open("setup_report.json", encoding="utf-8") as fh:
            setup = json.load(fh)
        reported["setup"] = {k: v for k, v in setup.items()
                             if not isinstance(v, dict)}
    except Exception as exc:
        reported["setup"] = "missing: %s" % exc

    written = {}
    for label, member in TYPES:
        qt = qtype(member)
        if qt is None:
            reported["write_errors"][label] = "gguf-py has no %s" % member
            continue
        reported["type_ids"][label] = int(qt)
        path = os.path.join(honest, label + ".gguf")
        try:
            write_gguf(path, [("w." + label, member)])
        except Exception as exc:
            reported["write_errors"][label] = "%s: %s" % (
                type(exc).__name__, str(exc)[:200])
            continue
        written[label] = (path, int(qt))
    mixed = os.path.join(files, "mixed", "all-types.gguf")
    os.makedirs(os.path.dirname(mixed))
    try:
        write_gguf(mixed, [("w." + lb, dict(TYPES)[lb]) for lb, _ in
                           sorted(written.items(), key=lambda kv: kv[1][1])])
    except Exception as exc:
        reported["write_errors"]["mixed"] = str(exc)[:200]
        mixed = None
    edited = None
    if "nvfp4" in written:
        with open(written["nvfp4"][0], "rb") as fh:
            raw = bytearray(fh.read())
        anchor = struct.pack("<Q", 7) + b"w.nvfp4"
        if raw.count(anchor) == 1:
            p = raw.find(anchor) + len(anchor)
            nd = struct.unpack_from("<I", raw, p)[0]
            p += 4 + 8 * nd
            if raw[p:p + 4] == struct.pack("<I", 40):
                raw[p:p + 4] = struct.pack("<I", 44)
                edited = os.path.join(files, "edited", "nvfp4-type44.gguf")
                os.makedirs(os.path.dirname(edited))
                with open(edited, "wb") as fh:
                    fh.write(bytes(raw))

    targets = dict((lb, v[0]) for lb, v in written.items())
    if mixed:
        targets["mixed"] = mixed
    if edited:
        targets["type44"] = edited

    rows = []

    def add(rid, case, expected, result, got=None, reason=""):
        r = {"id": rid, "case": case, "expected": expected, "result": result}
        if got is not None:
            r["got"] = got
        if reason:
            r["reason"] = reason
        rows.append(r)

    ok = bool(written)
    got = {}
    for lb, (path, tid) in sorted(written.items()):
        try:
            back = {t.name: int(t.tensor_type)
                    for t in gguf.GGUFReader(path).tensors}
        except Exception as exc:
            back = "%s: %s" % (type(exc).__name__, exc)
        got[lb] = back
        ok = ok and back == {"w." + lb: tid}
    add("R0", "GGUFReader reads every honest file with the type written",
        "all read, types match", "PASS" if ok else "FAIL", got)

    results = {}
    probes = {}
    main_installed = isinstance(reported["setup"], dict) and bool(
        reported["setup"].get("ma_main_main_ok"))
    for variant, venv in (("rel", "ma_rel"), ("main", "ma_main")):
        if variant == "main" and not main_installed:
            probes[variant] = {"error": "main was not installed in setup"}
            continue
        probes[variant] = probe(venv)
        if "error" in probes[variant]:
            continue
        results[variant] = {lb: scan(venv, p, os.path.join(
            out, "raw", variant), lb) for lb, p in sorted(targets.items())}
    # Fallback overlay: main's gguf_scanner.py over ma_rel's copy.
    if "rel" in results and os.path.exists("main_gguf_scanner.py"):
        dst = probes["rel"].get("file")
        if dst and os.path.exists(dst):
            shutil.copyfile("main_gguf_scanner.py", dst)
            for pyc in ("__pycache__",):
                shutil.rmtree(os.path.join(os.path.dirname(dst), pyc),
                              ignore_errors=True)
            probes["overlay"] = probe("ma_rel")
            if "error" not in probes["overlay"]:
                results["overlay"] = {lb: scan("ma_rel", p, os.path.join(
                    out, "raw", "overlay"), lb)
                    for lb, p in sorted(targets.items())}
    reported["probes"] = probes

    def unknown_of(variant, labels):
        return {lb: results[variant][lb]["unknown_types"] for lb in labels
                if lb in results[variant]}

    # Released 0.2.54.
    if "rel" in results:
        g = unknown_of("rel", REL_KNOWN)
        add("A1", "0.2.54 on F32/F16/Q4_0/Q8_0/Q4_K/Q6_K/IQ4_XS/BF16 files",
            "no unknown-type report",
            "PASS" if g and all(v == [] for v in g.values()) else "FAIL", g)
        g = {lb: [results["rel"][lb]["unknown_types"],
                  results["rel"][lb]["exit"]]
             for lb in REL_UNKNOWN if lb in results["rel"]}
        add("A2", "0.2.54 on TQ2_0/MXFP4/NVFP4/Q1_0/Q2_0/F8_E4M3 files",
            "unknown type id reported, exit 2",
            "PASS" if g and all(v[0] == [written[lb][1]] and v[1] == 2
                                for lb, v in g.items()) else "FAIL", g)
    else:
        for rid in ("A1", "A2"):
            add(rid, "modelaudit 0.2.54", "", "NOT RUN",
                reason="0.2.54 not installed or probe failed")

    graded = None
    pm = probes.get("main", {})
    if "main" in results and pm.get("ids") is not None:
        graded = "main"
    elif "overlay" in results and probes.get("overlay", {}).get("ids"):
        graded = "overlay"
    reported["main_graded_on"] = graded
    if graded:
        ids = probes[graded]["ids"]
        add("V0", "main's type table (%s)" % graded,
            "has 40, 41, 42; not 43",
            "PASS" if all(i in ids for i in (40, 41, 42)) and 43 not in ids
            else "FAIL", {"max": max(ids), "n": len(ids)})
        others = [lb for lb in written if lb != "f8_e4m3"]
        g = unknown_of(graded, others)
        add("M1", "main on every honest file except F8_E4M3",
            "no unknown-type report",
            "PASS" if g and all(v == [] for v in g.values()) else "FAIL", g)
        r = results[graded].get("f8_e4m3")
        add("M2", "main on the F8_E4M3 file", "unknown type 43, exit 2",
            ("PASS" if r["unknown_types"] == [43] and r["exit"] == 2
             else "FAIL") if r else "NOT RUN",
            [r["unknown_types"], r["exit"]] if r else None,
            "" if r else "F8_E4M3 file not written")
        r = results[graded].get("mixed")
        add("M3", "main on the file holding every type", "unknown: [43]",
            ("PASS" if r["unknown_types"] == [43] else "FAIL") if r
            else "NOT RUN", r["unknown_types"] if r else None,
            "" if r else "mixed file not written")
        r = results[graded].get("type44")
        add("M4", "main on the NVFP4 copy with type id 44",
            "unknown type 44 reported",
            ("PASS" if 44 in r["unknown_types"] else "FAIL") if r
            else "NOT RUN", r["unknown_types"] if r else None,
            "" if r else "edited copy not written")
    else:
        for rid in ("V0", "M1", "M2", "M3", "M4"):
            add(rid, "modelaudit main", "", "NOT RUN",
                reason="neither the main install nor the overlay was valid")
    reported["exits"] = {v: {lb: r["exit"] for lb, r in res.items()}
                         for v, res in results.items()}
    reported["loud"] = {v: {lb: r["loud"] for lb, r in res.items()
                            if r["loud"]} for v, res in results.items()}
    return reported, rows, results


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    if os.path.exists("setup_report.json"):
        shutil.copyfile("setup_report.json",
                        os.path.join(args.out, "setup_report.json"))
    try:
        reported, rows, results = run(args)
        error = ""
    except Exception:
        reported, rows, results = {}, [], {}
        error = traceback.format_exc()[-3000:]
        print(error, file=sys.stderr)
    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    summary = {"check_version": 1, "error": error,
               "held": sum(1 for r in graded if r["result"] == "PASS"),
               "graded": len(graded),
               "not_run": [r["id"] for r in rows
                           if r["result"] == "NOT RUN"],
               "reported": reported, "rows": rows}
    with open(os.path.join(args.out, "xtool_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    with open(os.path.join(args.out, "xtool_results.json"), "w",
              encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"], json.dumps(r.get("got", ""),
                                               default=str)[:700],
              r.get("reason", ""))
    print("reported:", json.dumps(reported, default=str)[:3000])
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
