#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step of job pkl-diag-v1 (no network): trace the pickle opcode walk on
each file, run the scanners (each version in its own process), grade the
pre-registered rows (research/PREREG_PKL_DIAG.md) and write
<out>/diag_summary.json.

Usage: python diag.py --out /out --tree tree

The trace walker mirrors pickle_model_scan 0.3.0's scan_pickle_bytes exactly
(same opcode sets, same memo and push rules, same decompression as
scan_blob) and additionally records, for every STACK_GLOBAL it cannot
resolve, the 14 opcodes before it, where each operand came from, and where
the walk sits relative to joblib's inline array data. It never unpickles:
pickletools only disassembles bytes. Catches its own errors; exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import bz2
import collections
import gzip
import json
import os
import pickletools
import re
import subprocess
import sys
import traceback
import zlib

STRING_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})
MEMO_GET_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
MEMO_PUT_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
WRAPPER = ("joblib.numpy_pickle", "NumpyArrayWrapper")
HIGH = ("HIGH", "CRITICAL")
BYTE_RE = re.compile(r"@ byte (\d+)")
HERE = os.path.dirname(os.path.abspath(__file__))


def short(arg):
    if arg is None:
        return None
    text = repr(arg)
    return text if len(text) <= 60 else text[:57] + "..."


def unwrap(data):
    """Mirror pickle_model_scan.scan_blob's decompression for pickle files."""
    label = []
    for _ in range(4):
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
            label.append("gunzipped")
        elif data[:3] == b"BZh":
            data = bz2.decompress(data)
            label.append("bunzipped")
        elif data[:1] == b"\x78":
            try:
                data = zlib.decompress(data)
                label.append("inflated")
            except Exception:
                break
        else:
            break
    return data, label


def _ops(data):
    gen = getattr(pickletools, "_genops", None)
    if gen is not None:
        try:
            for op, arg, pos, end in gen(data, yield_end_pos=True):
                yield op, arg, pos, end
            return
        except TypeError as exc:
            if "yield_end_pos" not in str(exc):
                raise
    for op, arg, pos in pickletools.genops(data):
        yield op, arg, pos, None


def trace(data):
    memo = {}
    pushes = []
    hist = collections.deque(maxlen=14)
    globals_found = []
    nested_proto = []
    wrapper_builds = []        # (pos, end, next 8 bytes hex)
    pending_wrapper = False
    first_wrapper_build = None
    n_ops = 0
    n_stack_global = 0
    last_end = 0
    stop = {"kind": None}
    try:
        for opcode, arg, pos, end in _ops(data):
            n_ops += 1
            if end is not None:
                last_end = end
            name = opcode.name
            hist.append([pos, name, short(arg)])
            if name == "PROTO" and pos > 0:
                nested_proto.append(pos)
            if name == "BUILD" and pending_wrapper and end is not None:
                # The wrapper's own BUILD is the one followed by bytes that
                # are not an opcode (joblib's padding-length byte, then the
                # raw array). An earlier BUILD (the dtype's) is followed by
                # ordinary opcodes and is skipped.
                nxt = data[end:end + 1]
                if not nxt or chr(nxt[0]) not in pickletools.code2op:
                    pending_wrapper = False
                    wrapper_builds.append([pos, end, data[end:end + 8].hex()])
                    if first_wrapper_build is None:
                        first_wrapper_build = pos
            if name == "STOP":
                stop = {"kind": "STOP", "pos": pos}
            if name in ("FRAME", "PROTO"):
                continue
            if name in MEMO_PUT_OPCODES or name == "MEMOIZE":
                key = len(memo) if name == "MEMOIZE" else arg
                memo[key] = pushes[-1] if pushes else ("other", None, "empty")
                continue
            if name in ("GLOBAL", "INST"):
                mod, _, fn = (arg or "").partition(" ")
                globals_found.append({"pos": pos, "op": name, "module": mod,
                                      "name": fn, "resolved": True})
            elif name == "STACK_GLOBAL":
                n_stack_global += 1
                last_two = pushes[-2:]
                if (len(last_two) == 2 and last_two[0][0] == "str"
                        and last_two[1][0] == "str"):
                    mod, fn = last_two[0][1], last_two[1][1]
                    globals_found.append({"pos": pos, "op": name,
                                          "module": mod, "name": fn,
                                          "resolved": True})
                    if (mod, fn) == WRAPPER:
                        pending_wrapper = True
                else:
                    globals_found.append({
                        "pos": pos, "op": name, "resolved": False,
                        "operands": [[k, short(v), origin]
                                     for k, v, origin in last_two],
                        "context": list(hist)})
            if name in STRING_OPCODES:
                pushes.append(("str", arg, name))
            elif name in MEMO_GET_OPCODES:
                slot = memo.get(arg)
                if slot is None:
                    pushes.append(("other", None,
                                   "%s of never-stored slot %r" % (name, arg)))
                else:
                    pushes.append((slot[0], slot[1],
                                   "%s slot %r <- %s" % (name, arg, slot[2])))
            else:
                pushes.append(("other", None, name))
            del pushes[:-2]
    except Exception as exc:
        stop = {"kind": "error", "pos": last_end,
                "msg": "%s: %s" % (type(exc).__name__, str(exc)[:200]),
                "bytes_here": data[last_end:last_end + 16].hex()}
    unresolved = [g for g in globals_found if not g["resolved"]]
    for g in unresolved:
        if first_wrapper_build is not None and g["pos"] > first_wrapper_build:
            g["class"] = "after-array"
        elif nested_proto and g["pos"] > nested_proto[0]:
            g["class"] = "nested-pickle"
        elif any(str(o[2]).startswith(("GET", "BINGET", "LONG_BINGET"))
                 for o in g["operands"]):
            g["class"] = "memo"
        else:
            g["class"] = "other-push"
    resolved = sorted({"%s %s" % (g["module"], g["name"])
                       for g in globals_found if g["resolved"]})
    stop_pos = stop.get("pos")
    return {
        "bytes": len(data), "ops": n_ops, "stack_globals": n_stack_global,
        "stop": stop,
        "stop_at_last_byte": (stop.get("kind") == "STOP"
                              and stop_pos == len(data) - 1),
        "coverage": (round((stop_pos + 1) / len(data), 6)
                     if stop_pos is not None and len(data) else None),
        "nested_proto": nested_proto[:20],
        "wrapper_builds": wrapper_builds[:20],
        "first_wrapper_build": first_wrapper_build,
        "resolved_distinct": resolved,
        "unresolved_positions": [g["pos"] for g in unresolved],
        "unresolved": unresolved[:20],
    }


def run_scanner(label, module_path, module_name, paths, work):
    in_json = os.path.join(work, "scan_in_%s.json" % label)
    out_json = os.path.join(work, "scan_out_%s.json" % label)
    with open(in_json, "w", encoding="utf-8") as fh:
        json.dump(paths, fh)
    if not os.path.isfile(module_path):
        return {"__missing__": module_path}
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "scan_one.py"), module_path,
             module_name, in_json, out_json],
            capture_output=True, text=True, timeout=900)
        if proc.returncode != 0 or not os.path.isfile(out_json):
            return {"__error__": "exit %s: %s" % (proc.returncode,
                                                  proc.stderr[-800:])}
        with open(out_json, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        return {"__error__": "%s: %s" % (type(exc).__name__, exc)}


def rules(findings):
    if not isinstance(findings, list):
        return None
    return sorted({(f["rule"], f["severity"]) for f in findings})


def pkl007_positions(findings):
    out = set()
    for f in findings if isinstance(findings, list) else []:
        if f["rule"] == "PKL007":
            m = BYTE_RE.search(f["location"])
            if m:
                out.add(int(m.group(1)))
    return sorted(out)


def has_high(findings):
    return any(f["severity"] in HIGH
               for f in (findings if isinstance(findings, list) else []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    ap.add_argument("--tree", default="tree")
    args = ap.parse_args()
    work = os.path.join(args.out, "work")
    os.makedirs(work, exist_ok=True)
    summary = {"check_version": 1, "error": "", "rows": [], "reported": {}}
    rep = summary["reported"]
    try:
        _main(args, work, summary, rep)
    except Exception:
        summary["error"] = traceback.format_exc()[-2000:]
    graded = [r for r in summary["rows"] if r["result"] in ("PASS", "FAIL")]
    summary["held"] = sum(1 for r in graded if r["result"] == "PASS")
    summary["graded"] = len(graded)
    summary["not_run"] = [r["id"] for r in summary["rows"]
                          if r["result"] == "NOT RUN"]
    with open(os.path.join(args.out, "diag_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    for r in summary["rows"]:
        print(r["id"], r["result"], json.dumps(r.get("got"))[:400])
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    if summary["error"]:
        print(summary["error"], file=sys.stderr)
    return 0


def _row(summary, rid, case, expected, ok, got):
    result = "NOT RUN" if ok is None else ("PASS" if ok else "FAIL")
    summary["rows"].append({"id": rid, "case": case, "expected": expected,
                            "result": result, "got": got})


def _main(args, work, summary, rep):
    fetch = {}
    if os.path.isfile("fetch_report.json"):
        with open("fetch_report.json", encoding="utf-8") as fh:
            fetch = json.load(fh)
    rep["fetch"] = fetch
    gt = {}
    gt_path = os.path.join(work, "ground_truth.json")
    if os.path.isfile(gt_path):
        with open(gt_path, encoding="utf-8") as fh:
            gt = json.load(fh)
    rep["writers"] = {"versions": gt.get("versions"),
                      "errors": gt.get("errors"),
                      "files": {k: {kk: vv for kk, vv in v.items()
                                    if kk != "imports"}
                                for k, v in (gt.get("files") or {}).items()}}

    hub = {}
    for f in (fetch.get("hub") or {}).get("files", []):
        if f.get("status") == "ok":
            hub[f["rfilename"].rsplit("/", 1)[-1]] = f["path"]
    written_dir = os.path.join(args.out, "files", "written")
    written = {}
    for name in ("j1_df_str.pkl", "j2_np_int.pkl", "j3_df_str_z3.pkl",
                 "j4_df_str_p5.pkl"):
        p = os.path.join(written_dir, name)
        if os.path.isfile(p):
            written[name] = p
    all_files = dict(hub)
    all_files.update(written)

    # Row F0: setup
    versions = (fetch.get("tree") or {}).get("versions") or {}
    patched_rel = "research/pkl-memo/results/patched/pickle_model_scan.py"
    f0 = {"hub_ok": sorted(hub), "versions": versions}
    ok_f0 = ("churn_model.pkl" in hub and "mobile_model.pkl" in hub
             and versions.get("pickle_model_scan.py") == "0.2.1"
             and versions.get(patched_rel) == "0.3.0"
             and bool(versions.get("joblib_pickle_scan.py")))
    _row(summary, "F0", "setup: both files downloaded; main has pms 0.2.1, "
         "the published 0.3.0 and joblib_pickle_scan", "all true", ok_f0, f0)

    # Traces
    traces = {}
    for name, path in sorted(all_files.items()):
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            data, label = unwrap(raw)
            t = trace(data)
            t["unwrapped"] = label
            t["file_bytes"] = len(raw)
            traces[name] = t
        except Exception as exc:
            traces[name] = {"error": "%s: %s" % (type(exc).__name__, exc)}
    rep["traces"] = traces

    # Scanners, each in its own process
    paths = [all_files[k] for k in sorted(all_files)]
    tree = args.tree
    scans = {
        "pms021": run_scanner("pms021", os.path.join(tree,
                              "pickle_model_scan.py"), "pickle_model_scan",
                              paths, work),
        "pms030": run_scanner("pms030", os.path.join(tree, *patched_rel.split(
                              "/")), "pickle_model_scan", paths, work),
        "jlb": run_scanner("jlb", os.path.join(tree, "joblib_pickle_scan.py"),
                           "joblib_pickle_scan", paths, work),
    }
    by_name = {}
    for label, res in scans.items():
        for name, path in all_files.items():
            by_name.setdefault(name, {})[label] = (
                rules(res.get(path)) if isinstance(res.get(path), list)
                else res.get(path, res.get("__error__")
                             or res.get("__missing__")
                             or res.get("__load_error__")))
    rep["scans"] = by_name
    rep["scanner_versions"] = {k: v.get("__version__") for k, v in
                               scans.items()}
    rep["scanner_problems"] = {k: v.get("__error__") or v.get("__missing__")
                               or v.get("__load_error__")
                               for k, v in scans.items()}
    s030 = scans["pms030"]

    # Row T1: mirror fidelity on the two hub files
    t1 = {}
    ok_t1 = True
    for name in ("churn_model.pkl", "mobile_model.pkl"):
        if (name not in hub or "error" in traces.get(name, {"error": 1})
                or not isinstance(s030.get(hub[name]), list)):
            ok_t1 = None
            break
        mine = traces[name]["unresolved_positions"]
        theirs = pkl007_positions(s030.get(hub[name]))
        t1[name] = {"trace": mine[:50], "pms030": theirs[:50]}
        if not mine or sorted(set(mine)) != theirs:
            ok_t1 = False
    _row(summary, "T1", "trace walker's unresolved STACK_GLOBAL positions "
         "equal 0.3.0's PKL007 positions on both files, non-empty",
         "equal", ok_t1, t1)

    # Row D1: classification of each unresolved STACK_GLOBAL
    d1 = {}
    for name in sorted(hub):
        t = traces.get(name, {})
        d1[name] = dict(collections.Counter(
            g.get("class") for g in t.get("unresolved", [])))
    rep["D1_classes"] = d1
    if ok_t1 is None:
        _row(summary, "D1", "every unresolved STACK_GLOBAL in churn and "
             "mobile sits inside a nested pickle (after a PROTO at pos > 0)",
             "all nested-pickle", None, d1)
    else:
        ok = all(set(d1.get(n, {})) == {"nested-pickle"}
                 for n in ("churn_model.pkl", "mobile_model.pkl"))
        _row(summary, "D1", "every unresolved STACK_GLOBAL in churn and "
             "mobile sits inside a nested pickle (after a PROTO at pos > 0)",
             "all nested-pickle", ok, d1)

    # Ground-truth helpers
    files_gt = gt.get("files") or {}

    def gt_set(name):
        e = files_gt.get(name) or {}
        return set(e.get("distinct_imports") or [])

    # Row W0: writers
    w0 = {n: {"error": bool((files_gt.get(n) or {}).get("error")),
              "distinct": len(gt_set(n))}
          for n in ("j1_df_str.pkl", "j2_np_int.pkl", "j3_df_str_z3.pkl",
                    "j4_df_str_p5.pkl")}
    ok_w0 = all(n in written and not v["error"] and v["distinct"] >= 3
                for n, v in w0.items())
    _row(summary, "W0", "four honest files written; ground truth has >= 3 "
         "distinct imports each", "all", ok_w0, w0)

    def walk_vs_gt(name):
        t = traces.get(name) or {}
        seen = set(t.get("resolved_distinct") or [])
        truth = gt_set(name)
        return {"stop": t.get("stop"), "coverage": t.get("coverage"),
                "stop_at_last_byte": t.get("stop_at_last_byte"),
                "walk_distinct": len(seen), "truth_distinct": len(truth),
                "missed": sorted(truth - seen)[:40],
                "extra": sorted(seen - truth)[:40],
                "unresolved": len(t.get("unresolved_positions") or [])}

    # Row W1: plain pickle control
    if ok_w0:
        g = walk_vs_gt("j4_df_str_p5.pkl")
        ok = (g["stop_at_last_byte"] and g["unresolved"] == 0
              and not g["missed"] and not g["extra"])
        _row(summary, "W1", "J4 plain pickle p5: walk reaches STOP at the "
             "last byte, nothing unresolved, imports equal ground truth",
             "true", ok, g)
    else:
        _row(summary, "W1", "J4 control", "true", None, "writers failed")

    # Row W2: joblib files, walk stops early and misses imports
    if ok_w0:
        got = {n: walk_vs_gt(n) for n in ("j1_df_str.pkl", "j2_np_int.pkl",
                                          "j3_df_str_z3.pkl")}
        ok = all((not g["stop_at_last_byte"]) and g["missed"]
                 for g in got.values())
        _row(summary, "W2", "J1, J2, J3 (joblib.dump): the walk ends before "
             "the stream's last byte and misses at least one real import",
             "true for all three", ok, got)
    else:
        _row(summary, "W2", "joblib walk", "true", None, "writers failed")

    # Row W3 / W4: what 0.3.0 reports
    if ok_w0 and isinstance(s030.get(written.get("j4_df_str_p5.pkl", "")),
                            list):
        f4 = s030[written["j4_df_str_p5.pkl"]]
        ok = not has_high(f4) and not any(f["rule"] == "PKL007" for f in f4)
        _row(summary, "W3", "0.3.0 on J4: no PKL007, nothing HIGH or "
             "CRITICAL", "true", ok, rules(f4))
        # W4: J2 (numeric arrays only): the walk hits joblib's padding byte
        # and 0.3.0 says so (PKL000).
        f2 = s030.get(written["j2_np_int.pkl"])
        t2 = traces.get("j2_np_int.pkl") or {}
        ok = (isinstance(f2, list)
              and any(x["rule"] == "PKL000" for x in f2)
              and (t2.get("stop") or {}).get("kind") == "error")
        _row(summary, "W4", "J2: walk stops with a parse error and 0.3.0 "
             "reports PKL000", "true", ok,
             {"rules": rules(f2), "stop": t2.get("stop")})
        # W5: J1 and J3 (DataFrame model: object-dtype feature_names_in_ is
        # written as a nested pickle): the walk enters the nested pickle,
        # ends at ITS STOP with no parse error (so no PKL000), and 0.3.0
        # reports PKL007 there because the nested memo indices are looked up
        # in the outer stream's memo.
        got = {}
        ok = True
        for n in ("j1_df_str.pkl", "j3_df_str_z3.pkl"):
            f = s030.get(written[n])
            t = traces.get(n) or {}
            nested = t.get("nested_proto") or []
            pk7 = pkl007_positions(f)
            got[n] = {"rules": rules(f), "stop": t.get("stop"),
                      "nested_proto": nested[:5], "pkl007_at": pk7[:10]}
            if not (isinstance(f, list) and nested
                    and (t.get("stop") or {}).get("kind") == "STOP"
                    and not t.get("stop_at_last_byte")
                    and not any(x["rule"] == "PKL000" for x in f)
                    and pk7 and all(p > nested[0] for p in pk7)):
                ok = False
        _row(summary, "W5", "J1 and J3: walk enters a nested pickle and ends "
             "at its STOP; 0.3.0 gives no PKL000 but PKL007, all after the "
             "nested PROTO", "true for both", ok, got)
    else:
        _row(summary, "W3", "0.3.0 on J4", "true", None, "no scan")
        _row(summary, "W4", "J2 PKL000", "true", None, "no scan")
        _row(summary, "W5", "J1/J3 nested pickle", "true", None, "no scan")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(0)
