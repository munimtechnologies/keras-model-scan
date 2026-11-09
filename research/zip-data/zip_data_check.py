#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Grade job zip-data-v1 (research/PREREG_ZIP_DATA.md).

Base = tag v0.56.0 untouched (pickle_model_scan 0.5.0). Tree = the same tag
patched to 0.6.0 by patch_pms.py. Each version scans every local and
published file in its own process (probe.py). A finding is "in a storage
member" when its location names a member <prefix>/data/<key> of a zip that
holds <prefix>/data.pkl; that set is computed here from zipfile's name list
by an implementation independent of the patch.

Usage: zip_data_check.py --out OUT --tree tree --base base
Writes OUT/zip_data_summary.json. Catches its own exceptions, exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import collections
import json
import os
import re
import struct
import subprocess
import sys
import traceback
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
N_NEW = 10
NEW_MODULE = "test_pickle_model_scan_zip_storage"
EXPECTED_CHANGES = ["docstring", "version 0.6.0", "helper", "scan_zip"]
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"([0-9.]+)"')
AT_BYTE = re.compile(r" @ byte \d+$")
PAREN = re.compile(r" \([^()]*\)$")
RAN_RE = re.compile(r"Ran (\d+) tests?")
RELEASE_ROWS = ["P1", "V1", "S1", "S2", "W1", "G1", "F1", "F2", "F3", "C1",
                "E1"]
ROW_ORDER = RELEASE_ROWS + ["B1", "H1", "H2", "H3", "H4", "H5"]


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def version_of(path):
    try:
        with open(path, encoding="utf-8") as fh:
            m = VER_RE.search(fh.read())
        return m.group(1) if m else None
    except OSError:
        return None


def storage_members(names):
    """<prefix>/data/<key> members for every prefix holding data.pkl."""
    prefixes = {n[:-len("data.pkl")] for n in names
                if n == "data.pkl" or n.endswith("/data.pkl")}
    out = set()
    for n in names:
        for p in prefixes:
            if n.startswith(p + "data/"):
                rest = n[len(p) + len("data/"):]
                if rest and "/" not in rest:
                    out.add(n)
    return out


def zip_info(path):
    info = {"zip": False}
    try:
        if not zipfile.is_zipfile(path):
            return info
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            st = storage_members(names)
            first = {}
            small = {}
            for n in st:
                with zf.open(n) as fh:
                    head = fh.read(8)
                first[n] = head[:1].hex()
                if zf.getinfo(n).file_size == 8:
                    small[n] = head.hex()
        info.update(zip=True, members=len(names), storages=sorted(st),
                    first80=sorted(n for n in st if first[n] == "80"),
                    eight_byte=small,
                    data_pkl=sorted(n for n in names
                                    if n == "data.pkl"
                                    or n.endswith("/data.pkl")))
    except Exception as exc:
        info["error"] = "%s: %s" % (type(exc).__name__, exc)
    return info


def member_of(loc, path):
    if not isinstance(loc, str) or not loc.startswith(path + "!"):
        return None
    rest = AT_BYTE.sub("", loc[len(path) + 1:])
    while PAREN.search(rest):
        rest = PAREN.sub("", rest)
    return rest


def key(f):
    return (f.get("rule"), f.get("severity"), f.get("location"))


def run_probe(src, list_path, out_path):
    p = subprocess.run([sys.executable, os.path.join(HERE, "probe.py"), src,
                        list_path, out_path], capture_output=True, text=True,
                       timeout=5400)
    res = load(out_path, {})
    res["rc"] = p.returncode
    res["stderr_tail"] = p.stderr[-600:]
    return res


def run_cli(src, path):
    try:
        p = subprocess.run([sys.executable,
                            os.path.join(src, "model_file_scan.py"),
                            "--json", path], capture_output=True, text=True,
                           timeout=600)
        doc = json.loads(p.stdout) if p.stdout.strip() else {}
        n = sum(len(f.get("findings", [])) for f in doc.get("files", []))
        return {"exit": p.returncode, "findings": n,
                "stderr": p.stderr[-300:]}
    except Exception as exc:
        return {"exit": None, "error": "%s: %s" % (type(exc).__name__, exc)}


def run_new_module(tree):
    try:
        p = subprocess.run([sys.executable, "-m", "unittest", "-v",
                            NEW_MODULE], cwd=tree, capture_output=True,
                           text=True, timeout=900)
        m = RAN_RE.search(p.stderr + p.stdout)
        return {"exit": p.returncode, "ran": int(m.group(1)) if m else None,
                "tail": (p.stderr + p.stdout)[-1200:]}
    except Exception as exc:
        return {"exit": None, "error": "%s: %s" % (type(exc).__name__, exc)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tree", required=True)
    ap.add_argument("--base", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows = {}
    rep = {}

    def row(name, ok, detail):
        rows[name] = {"pass": ok, "detail": detail}

    man = load(os.path.join("local", "local_manifest.json"), {}) or {}
    mfiles = man.get("files", {})
    rep["torch"] = man.get("torch")
    rep["manifest_errors"] = man.get("errors")
    local = sorted(os.path.join("local", n) for n in os.listdir("local")
                   if n != "local_manifest.json") if os.path.isdir(
                       "local") else []
    census = load(os.path.join("hub", "zip_census.json"), {}) or {}
    hub = [d["path"] for d in census.get("downloads", [])
           if d.get("status") == "ok" and os.path.isfile(d.get("path", ""))]
    rep["hub_list"] = census.get("list")
    rep["hub_downloads"] = [{k: d.get(k) for k in ("n", "rank", "model",
                                                   "bytes", "status")}
                            for d in census.get("downloads", [])]
    files = local + hub
    list_path = os.path.join(a.out, "probe_list.json")
    with open(list_path, "w", encoding="utf-8") as fh:
        json.dump(files, fh)
    base = run_probe(a.base, list_path, os.path.join(a.out, "probe_base.json"))
    tree = run_probe(a.tree, list_path, os.path.join(a.out, "probe_tree.json"))
    zinfo = {p: zip_info(p) for p in files}

    def fnd(res, p):
        return (res.get("files", {}).get(p) or {}).get("findings")

    def storage_split(p, findings):
        st = set(zinfo[p].get("storages", []))
        on, off = [], []
        for f in findings or []:
            (on if member_of(f.get("location"), p) in st else off).append(f)
        return on, off

    # P1
    pr = load(os.path.join(a.out, "patch_report.json"), {}) or {}
    pf = (pr.get("files") or {}).get("pickle_model_scan.py", {})
    row("P1", bool(pr.get("ok")) and pf.get("changes") == EXPECTED_CHANGES
        and not pf.get("second_pass") and not pf.get("lost"),
        {"report": pf, "error": pr.get("error")})
    # V1
    v = {"base_pms": base.get("version"), "tree_pms": tree.get("version"),
         "base_mfs": version_of(os.path.join(a.base, "model_file_scan.py")),
         "tree_mfs": version_of(os.path.join(a.tree, "model_file_scan.py"))}
    row("V1", v["base_pms"] == "0.5.0" and v["tree_pms"] == "0.6.0"
        and v["base_mfs"] == "0.13.1" and v["tree_mfs"] == "0.13.1", v)
    # S1 / S2
    ts = load(os.path.join(a.out, "tests_summary.json"), {}) or {}
    tb = load(os.path.join(a.out, "tests_base.json"), {}) or {}
    rep["S0_base_suite"] = tb
    row("S1", bool(ts.get("ok")) and not ts.get("failures")
        and not ts.get("errors") and isinstance(tb.get("ran"), int)
        and ts.get("ran") == tb["ran"] + N_NEW,
        {"tree": ts, "base_ran": tb.get("ran")})
    s2 = run_new_module(a.tree)
    row("S2", s2.get("exit") == 0 and s2.get("ran") == N_NEW, s2)
    # W1
    need = (["bn_%d.pt" % n for n in (127, 128, 129, 384)]
            + ["mlp_%03d.pt" % s for s in range(200)] + ["ts_mlp.pt"])
    bad = [n for n in need if not (mfiles.get(n) or {}).get("load_ok")]
    ctrl = [n for n in ("legacy_bn_128.pt", "state.pkl")
            if not os.path.isfile(os.path.join("local", n))]
    row("W1", not bad and not ctrl and not man.get("errors"),
        {"not_loaded": bad[:20], "controls_missing": ctrl,
         "written": len(local)})
    # G1
    g = {}
    gok = True
    for n in (127, 128, 129, 384):
        p = os.path.join("local", "bn_%d.pt" % n)
        zi = zinfo.get(p, {})
        eight80 = {m: h for m, h in (zi.get("eight_byte") or {}).items()
                   if h.startswith("80")}
        val = (mfiles.get("bn_%d.pt" % n) or {}).get("num_batches_tracked")
        if n in (128, 384):
            ok = (val == n and len(eight80) == 1
                  and list(eight80.values())[0] == struct.pack("<q", n).hex())
        else:
            ok = val == n and not eight80
        g["bn_%d" % n] = {"value": val, "eight_byte_0x80": eight80, "ok": ok}
        gok = gok and ok
    row("G1", gok, g)
    # B1 (diagnosis, reported)
    b = {}
    bok = True
    for n in (127, 128, 129, 384):
        p = os.path.join("local", "bn_%d.pt" % n)
        on, _off = storage_split(p, fnd(base, p))
        rules = [(f["rule"], f["severity"]) for f in on]
        ok = rules == [("PKL000", "LOW")] if n in (128, 384) else rules == []
        b["bn_%d" % n] = {"base_on_storage": rules, "ok": ok}
        bok = bok and ok
    row("B1", bok, b)
    # F1 / F2
    f1 = {}
    f2 = {}
    probe_err = []
    local_storage_total = local_first80 = 0
    base_storage_findings_local = 0
    for p in files:
        bf, tf = fnd(base, p), fnd(tree, p)
        if bf is None or tf is None:
            probe_err.append(p)
            continue
        zi = zinfo[p]
        if p in local:
            local_storage_total += len(zi.get("storages", []))
            local_first80 += len(zi.get("first80", []))
        b_on, b_off = storage_split(p, bf)
        t_on, _t_off = storage_split(p, tf)
        if p in local:
            base_storage_findings_local += len(b_on)
            if t_on:
                f1[p] = [key(f) for f in t_on]
        if collections.Counter(map(key, tf)) != collections.Counter(
                map(key, b_off)):
            f2[p] = {"tree": [key(f) for f in tf][:10],
                     "base_off_storage": [key(f) for f in b_off][:10]}
    local_err = [p for p in probe_err if p in local]
    row("F1", not f1 and not local_err and bool(local),
        {"tree_storage_findings": f1, "local_probe_errors": local_err})
    row("F2", not f2 and not local_err and bool(files),
        {"differences": dict(list(f2.items())[:20]),
         "files_compared": len(files) - len(probe_err),
         "probe_errors": probe_err[:20]})
    rep["local_storages"] = local_storage_total
    rep["local_storages_first_0x80"] = local_first80
    rep["local_base_storage_findings"] = base_storage_findings_local
    # F3: TorchScript data.pkl still walked
    p = os.path.join("local", "ts_mlp.pt")
    dp = set(zinfo.get(p, {}).get("data_pkl", []))
    bd = [key(f) for f in fnd(base, p) or []
          if member_of(f.get("location"), p) in dp]
    td = [key(f) for f in fnd(tree, p) or []
          if member_of(f.get("location"), p) in dp]
    row("F3", bool(bd) and collections.Counter(bd) == collections.Counter(td),
        {"base_on_data_pkl": bd, "tree_on_data_pkl": td})
    # C1: non-zip controls
    c = {}
    cok = True
    for n in ("legacy_bn_128.pt", "state.pkl"):
        p = os.path.join("local", n)
        bf, tf = fnd(base, p), fnd(tree, p)
        ok = bf is not None and tf is not None and [key(f) for f in bf] == [
            key(f) for f in tf]
        c[n] = {"base": [key(f) for f in bf or []],
                "tree": [key(f) for f in tf or []], "ok": ok}
        cok = cok and ok
    row("C1", cok, c)
    # E1: CLI
    e = {}
    eok = True
    for n in (128, 384):
        p = os.path.join("local", "bn_%d.pt" % n)
        t = run_cli(a.tree, p)
        bs = run_cli(a.base, p)
        e["bn_%d" % n] = {"tree": t, "base": bs}
        eok = eok and t.get("exit") == 0 and t.get("findings") == 0
    row("E1", eok, e)
    # Hub rows (graded, not gating)
    hub_ok = [p for p in hub if fnd(base, p) is not None
              and fnd(tree, p) is not None and zinfo[p].get("zip")]
    row("H1", len(hub_ok) >= 30, {"published_scanned": len(hub_ok)})
    if hub_ok:
        tree_on = {p: len(storage_split(p, fnd(tree, p))[0]) for p in hub_ok}
        base_on = {p: len(storage_split(p, fnd(base, p))[0]) for p in hub_ok}
        row("H2", sum(tree_on.values()) == 0,
            {"tree_storage_findings": sum(tree_on.values())})
        share = sum(1 for v_ in base_on.values() if v_) / len(hub_ok)
        row("H3", 0.15 <= share <= 0.85,
            {"files_with_base_storage_finding": sum(
                1 for v_ in base_on.values() if v_),
             "of": len(hub_ok), "share": round(share, 4)})
        st_total = sum(len(zinfo[p].get("storages", [])) for p in hub_ok)
        st80 = sum(len(zinfo[p].get("first80", [])) for p in hub_ok)
        frac = st80 / st_total if st_total else None
        row("H4", frac is not None and 0.002 <= frac <= 0.006,
            {"storages": st_total, "first_0x80": st80,
             "share": round(frac, 5) if frac is not None else None})
    else:
        for r in ("H2", "H3", "H4"):
            rows[r] = {"pass": None, "detail": "not run: no published file"}
    # H5: base storage findings sit exactly on storages starting with 0x80
    mism = []
    for p in files:
        bf = fnd(base, p)
        if bf is None or not zinfo[p].get("zip"):
            continue
        on, _off = storage_split(p, bf)
        hit = {member_of(f.get("location"), p) for f in on}
        first80 = set(zinfo[p].get("first80", []))
        if hit != first80:
            mism.append({"file": p, "finding_members": sorted(hit)[:5],
                         "first80": sorted(first80)[:5]})
    row("H5", not mism, {"mismatches": mism[:20]})
    # reported: torch.export file in both versions
    p = os.path.join("local", "ep_mlp.pt2")
    rep["ep_mlp_pt2"] = {"base": [key(f) for f in fnd(base, p) or []],
                         "tree": [key(f) for f in fnd(tree, p) or []],
                         "written": os.path.isfile(p)}
    rep["probe_rc"] = {"base": base.get("rc"), "tree": tree.get("rc"),
                       "base_stderr": base.get("stderr_tail"),
                       "tree_stderr": tree.get("stderr_tail")}

    held = [r for r in ROW_ORDER if rows.get(r, {}).get("pass") is True]
    failed = [r for r in ROW_ORDER if rows.get(r, {}).get("pass") is False]
    not_run = [r for r in ROW_ORDER if rows.get(r, {}).get("pass") is None]
    summary = {"rows": rows, "held": held, "failed": failed,
               "not_run": not_run, "release_rows": RELEASE_ROWS,
               "release_rows_all_pass": all(
                   rows.get(r, {}).get("pass") is True for r in RELEASE_ROWS),
               "reported": rep}
    with open(os.path.join(a.out, "zip_data_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"held": held, "failed": failed, "not_run": not_run,
                      "release_rows_all_pass":
                      summary["release_rows_all_pass"]}, indent=1))
    return 0


if __name__ == "__main__":
    try:
        main()
    except Exception:
        err = traceback.format_exc()[-1500:]
        print(err, file=sys.stderr)
        try:
            out = sys.argv[sys.argv.index("--out") + 1]
            with open(os.path.join(out, "zip_data_summary.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"crashed": err}, fh, indent=1)
        except Exception:
            pass
    sys.exit(0)
