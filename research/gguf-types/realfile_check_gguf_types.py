#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check: gguf_scan tensor type ids (research/PREREG_GGUF_TYPES.md).

Writes small GGUF files with llama.cpp's own gguf-py (tag b12034), one per
tensor type plus one file holding every type, and scans them with
gguf_scan 0.1.0 (keras-model-scan v0.50.0) and the patched 0.2.0. Also runs
both versions of the one-command model-file-scan, scans one edited copy whose
type id is set to 44 (one past GGML_TYPE_COUNT - 1), and reads every honest
file back with gguf-py's GGUFReader. No network is used.

Usage: realfile_check_gguf_types.py --old KMS --new KMS_NEW --out OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys

import numpy as np
import gguf

LOUD = ("MEDIUM", "HIGH", "CRITICAL")
# (label, GGMLQuantizationType member name)
TYPES = [
    ("f32", "F32"), ("f16", "F16"), ("q4_0", "Q4_0"), ("q8_0", "Q8_0"),
    ("q4_k", "Q4_K"), ("q6_k", "Q6_K"), ("iq4_xs", "IQ4_XS"),
    ("bf16", "BF16"), ("tq2_0", "TQ2_0"), ("mxfp4", "MXFP4"),
    ("nvfp4", "NVFP4"), ("q1_0", "Q1_0"), ("q2_0", "Q2_0"),
    ("f8_e4m3", "F8_E4M3"),
]
NE0 = 256
ROWS = 2


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def qtype(member):
    return getattr(gguf.GGMLQuantizationType, member, None)


def tensor_data(member, seed):
    """(array, raw_dtype) for one 2 x 256 tensor of the given type."""
    rng = np.random.default_rng(seed)
    if member == "F32":
        return rng.standard_normal((ROWS, NE0)).astype(np.float32), None
    if member == "F16":
        return rng.standard_normal((ROWS, NE0)).astype(np.float16), None
    qt = qtype(member)
    block, size = gguf.GGML_QUANT_SIZES[qt]
    if NE0 % block:
        raise ValueError("%s block size %d does not divide %d"
                         % (member, block, NE0))
    nbytes = NE0 // block * size
    return rng.integers(0, 256, size=(ROWS, nbytes), dtype=np.uint8), qt


def write_gguf(path, entries):
    """entries: list of (tensor name, member). Returns nothing."""
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


def read_back(path):
    r = gguf.GGUFReader(path)
    return {t.name: int(t.tensor_type) for t in r.tensors}


def scan(mod, path):
    with open(path, "rb") as fh:
        raw = fh.read()
    findings = mod.scan_bytes(raw, len(raw), os.path.basename(path))
    rules = sorted(set(f.rule for f in findings))
    loud = sorted(set("%s %s" % (f.rule, str(f.severity).upper())
                      for f in findings
                      if str(f.severity).upper() in LOUD))
    return {"rules": rules, "loud": loud,
            "gg010": [f.detail for f in findings if f.rule == "GG010"][:3]}


def mfs(kms, target):
    proc = subprocess.run([sys.executable,
                           os.path.join(kms, "model_file_scan.py"), target],
                          capture_output=True, text=True, timeout=600)
    return {"exit": proc.returncode,
            "tail": (proc.stdout.strip().splitlines() or [""])[-3:]}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    old = load_module(os.path.join(args.old, "gguf_scan.py"), "gguf_scan_old")
    new = load_module(os.path.join(args.new, "gguf_scan.py"), "gguf_scan_new")
    files = os.path.join(args.out, "files")
    shutil.rmtree(files, ignore_errors=True)
    honest_dir = os.path.join(files, "honest")
    os.makedirs(honest_dir)
    reported = {"gguf_py": getattr(gguf, "__version__", "") or "unknown",
                "old_scanner": old.__version__,
                "new_scanner": new.__version__,
                "type_ids": {}, "write_errors": {}, "quant_sizes": {}}

    written = {}  # label -> (path, member, type id)
    for label, member in TYPES:
        qt = qtype(member)
        if qt is None:
            reported["write_errors"][label] = "gguf-py has no %s" % member
            continue
        reported["type_ids"][label] = int(qt)
        if member not in ("F32", "F16"):
            try:
                reported["quant_sizes"][label] = list(
                    gguf.GGML_QUANT_SIZES[qt])
            except KeyError:
                reported["write_errors"][label] = \
                    "GGML_QUANT_SIZES has no %s" % member
                continue
        path = os.path.join(honest_dir, "%s.gguf" % label)
        try:
            write_gguf(path, [("w.%s" % label, member)])
        except Exception as exc:  # pre-registered: writer error = not run
            reported["write_errors"][label] = "%s: %s" % (
                type(exc).__name__, str(exc)[:200])
            if os.path.exists(path):
                os.remove(path)
            continue
        written[label] = (path, member, int(qt))

    mixed = os.path.join(files, "mixed", "all-types.gguf")
    os.makedirs(os.path.dirname(mixed))
    mixed_ok = False
    try:
        write_gguf(mixed, [("w.%s" % lb, m) for lb, (p, m, t)
                           in sorted(written.items(), key=lambda kv: kv[1][2])])
        mixed_ok = True
    except Exception as exc:
        reported["write_errors"]["mixed"] = "%s: %s" % (
            type(exc).__name__, str(exc)[:200])

    rows = []

    def add(rid, case, expected, result, got=None, reason=""):
        row = {"id": rid, "case": case, "expected": expected,
               "result": result}
        if got is not None:
            row["got"] = got
        if reason:
            row["reason"] = reason
        rows.append(row)

    # R0: gguf-py reads every honest file back with the type it wrote.
    got = {}
    ok = bool(written)
    for label, (path, member, tid) in sorted(written.items()):
        try:
            back = read_back(path)
            got[label] = back
            ok = ok and back == {"w.%s" % label: tid}
        except Exception as exc:
            got[label] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
            ok = False
    add("R0", "GGUFReader reads every honest file; types as written",
        "all read, types match", "PASS" if ok else "FAIL", got)

    def per_file(rid, case, labels, mod, want_gg010):
        if not labels:
            add(rid, case, "", "NOT RUN", reason="no file of these types "
                "was written")
            return
        got = {}
        ok = True
        for label in labels:
            res = scan(mod, written[label][0])
            got[label] = res
            if want_gg010:
                ok = ok and "GG010" in res["rules"]
            else:
                ok = ok and "GG010" not in res["rules"] and not res["loud"]
        add(rid, case, "GG010 on each" if want_gg010 else
            "no GG010, nothing at MEDIUM or above", "PASS" if ok else "FAIL",
            got)

    low = [lb for lb in written if written[lb][2] <= 39]
    high = [lb for lb in written if 40 <= written[lb][2] <= 43]
    reported["types_39_or_below"] = sorted(low)
    reported["types_40_to_43"] = sorted(high)
    per_file("O1", "gguf_scan 0.1.0 on files of types <= 39", sorted(low),
             old, False)
    per_file("O2", "gguf_scan 0.1.0 on files of types 40-43", sorted(high),
             old, True)
    if "nvfp4" in written:
        res = mfs(args.old, written["nvfp4"][0])
        add("O3", "model-file-scan v0.50.0 on the NVFP4 file", "exit 1",
            "PASS" if res["exit"] == 1 else "FAIL", res)
    else:
        add("O3", "model-file-scan v0.50.0 on the NVFP4 file", "exit 1",
            "NOT RUN", reason="NVFP4 file not written")
    per_file("N1", "gguf_scan 0.2.0 on every honest file",
             sorted(written), new, False)
    if written:
        res = mfs(args.new, honest_dir)
        add("N2", "patched model-file-scan on the folder of honest files",
            "exit 0", "PASS" if res["exit"] == 0 else "FAIL", res)
    else:
        add("N2", "patched model-file-scan on the folder of honest files",
            "exit 0", "NOT RUN", reason="no honest file written")

    # N3: edited NVFP4 copy with type id 44.
    if "nvfp4" in written:
        with open(written["nvfp4"][0], "rb") as fh:
            raw = bytearray(fh.read())
        name = b"w.nvfp4"
        anchor = struct.pack("<Q", len(name)) + name
        hits = []
        start = 0
        while True:
            i = raw.find(anchor, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
        pos = None
        if len(hits) == 1:
            p = hits[0] + len(anchor)
            n_dims = struct.unpack_from("<I", raw, p)[0]
            p += 4 + 8 * n_dims
            if raw[p:p + 4] == struct.pack("<I", 40):
                pos = p
        if pos is None:
            add("N3", "gguf_scan 0.2.0 on the NVFP4 copy with type id 44",
                "GG010", "NOT RUN",
                reason="tensor-info anchor not found exactly once "
                       "(%d hits) or type bytes were not 40" % len(hits))
        else:
            raw[pos:pos + 4] = struct.pack("<I", 44)
            edited = os.path.join(files, "edited", "nvfp4-type44.gguf")
            os.makedirs(os.path.dirname(edited))
            with open(edited, "wb") as fh:
                fh.write(bytes(raw))
            res = scan(new, edited)
            add("N3", "gguf_scan 0.2.0 on the NVFP4 copy with type id 44",
                "GG010", "PASS" if "GG010" in res["rules"] else "FAIL", res)
    else:
        add("N3", "gguf_scan 0.2.0 on the NVFP4 copy with type id 44",
            "GG010", "NOT RUN", reason="NVFP4 file not written")

    if mixed_ok:
        res_new = scan(new, mixed)
        res_old = scan(old, mixed)
        reported["mixed_old"] = res_old
        add("N4", "gguf_scan 0.2.0 on one file holding every written type",
            "no GG010, nothing at MEDIUM or above",
            "PASS" if ("GG010" not in res_new["rules"]
                       and not res_new["loud"]) else "FAIL", res_new)
    else:
        add("N4", "gguf_scan 0.2.0 on one file holding every written type",
            "no GG010, nothing at MEDIUM or above", "NOT RUN",
            reason="mixed file not written")

    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    summary = {"check_version": 1,
               "held": sum(1 for r in graded if r["result"] == "PASS"),
               "graded": len(graded),
               "not_run": [r["id"] for r in rows
                           if r["result"] == "NOT RUN"],
               "reported": reported, "rows": rows}
    with open(os.path.join(args.out, "realfile_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"],
              json.dumps(r.get("got", ""), default=str)[:600],
              r.get("reason", ""))
    print("reported:", json.dumps(reported, default=str)[:2000])
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
