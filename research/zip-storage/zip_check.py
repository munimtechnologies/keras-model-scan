#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step (no network): what does pickle_model_scan 0.4.0 (release v0.54.0)
report on the tensor-storage members of honest zip-format PyTorch files?

torch.load unpickles only <prefix>/data.pkl; each tensor storage is a member
<prefix>/data/<key> that it copies as raw bytes (torch/serialization.py,
_load and load_tensor: get_storage_from_record(f"data/{key}", ...)). The
scanner's scan_zip walks any member whose first byte is 0x80 as a pickle, so
a storage that happens to start with 0x80 is walked as one.

For every file (local ones written by make_local.py, published ones from
fetch_hub_zip.py) this records each storage member and its first byte, runs
scan_file of the released scanner in this process, and assigns each finding
to the member it names. The released model-file-scan CLI is also run on the
BatchNorm files to get its exit code. Rows are those of PREREG_ZIP_STORAGE.md.
Writes zip_storage_summary.json. Catches its own exceptions, exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
import traceback
import zipfile

SUFFIX_RX = re.compile(r"(?: \([^()]*\)| @ byte \d+)+$")
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def member_of(location):
    if "!" not in location:
        return None
    rest = location.split("!", 1)[1]
    return SUFFIX_RX.sub("", rest)


def storages_of(zf):
    names = zf.namelist()
    prefixes = [n[:-len("data.pkl")] for n in names
                if n == "data.pkl" or n.endswith("/data.pkl")]
    out = {}
    for p in prefixes:
        for n in names:
            if n.startswith(p + "data/") and len(n) > len(p) + 5 \
                    and not n.endswith("/"):
                with zf.open(n) as fh:
                    head = fh.read(8)
                out[n] = {"first": head[:1].hex(), "head8": head.hex(),
                          "size": zf.getinfo(n).file_size}
    return prefixes, out


def examine(pms, path):
    rec = {"path": path}
    try:
        with zipfile.ZipFile(path) as zf:
            prefixes, st = storages_of(zf)
            rec["members"] = len(zf.namelist())
    except Exception as exc:
        rec["error"] = "zip: %s: %s" % (type(exc).__name__, exc)
        return rec
    rec["pickle_records"] = [p + "data.pkl" for p in prefixes]
    rec["storages"] = len(st)
    rec["storages_0x80"] = sorted(n for n, v in st.items() if v["first"] == "80")
    try:
        findings = pms.scan_file(path) or []
    except Exception as exc:
        rec["error"] = "scan: %s: %s" % (type(exc).__name__, exc)
        return rec
    fs = []
    for f in findings:
        m = member_of(f.location)
        if m is None:
            where = "file"
        elif m in st:
            where = "storage"
        elif m.endswith(".pkl"):
            where = "pickle_record"
        else:
            where = "other"
        fs.append({"rule": f.rule, "severity": f.severity, "member": m,
                   "where": where,
                   "member_first": st[m]["first"] if m in st else None,
                   "member_head8": st[m]["head8"] if m in st else None,
                   "member_size": st[m]["size"] if m in st else None,
                   "detail": (f.detail or "")[:200]})
    rec["findings"] = fs
    rec["storage_0x80_with_finding"] = sorted(
        {x["member"] for x in fs if x["where"] == "storage"
         and x["member_first"] == "80"})
    return rec


def cli_exit(base, path):
    try:
        p = subprocess.run([sys.executable, os.path.join(base,
                                                         "model_file_scan.py"),
                            "--json", path], capture_output=True, text=True,
                           timeout=300)
        return {"rc": p.returncode, "stdout_tail": p.stdout[-1500:],
                "stderr_tail": p.stderr[-400:]}
    except Exception as exc:
        return {"rc": None, "error": "%s: %s" % (type(exc).__name__, exc)}


def row(ok, observed):
    return {"status": "not run" if ok is None else ("held" if ok else
                                                    "failed"),
            "observed": observed}


def main(args):
    out = {"rows": {}, "reported": {}}
    sys.path.insert(0, os.path.abspath(args.base))
    import pickle_model_scan as pms  # the released v0.54.0 module
    import model_file_scan as mfs
    out["versions"] = {"pickle_model_scan": pms.__version__,
                       "model_file_scan": mfs.__version__}
    try:
        with open(os.path.join("local", "local_manifest.json"),
                  encoding="utf-8") as fh:
            man = json.load(fh)
    except Exception as exc:
        man = {"files": {}, "errors": ["manifest: %s" % exc]}
    out["local_manifest"] = {"torch": man.get("torch"),
                             "errors": man.get("errors"),
                             "not_loaded": sorted(
                                 k for k, v in man.get("files", {}).items()
                                 if not v.get("load_ok"))}
    local = {}
    for name in sorted(man.get("files", {})):
        path = os.path.join("local", name)
        if os.path.isfile(path):
            local[name] = examine(pms, path)
    hub = []
    for path in sorted(glob.glob(os.path.join("hub", "zip", "*",
                                              "pytorch_model.bin"))):
        hub.append(examine(pms, path))

    out["rows"]["P0"] = row(pms.__version__ == "0.4.0"
                            and mfs.__version__ == "0.12.1",
                            out["versions"])

    # R1 / R2: the num_batches_tracked storage of the BatchNorm files.
    r1, r2, r1_ok, r2_ok, cli = {}, {}, None, None, {}
    for n in (127, 128, 129, 384):
        name = "bn_%d.pt" % n
        rec = local.get(name)
        info = man.get("files", {}).get(name, {})
        if not rec or "error" in rec or not info.get("load_ok"):
            obs = {"missing_or_error": rec.get("error") if rec else "missing"}
            ok = False
        else:
            want = n.to_bytes(8, "little").hex()
            with zipfile.ZipFile(rec["path"]) as zf:
                _p, st = storages_of(zf)
            nbt = [m for m, v in st.items() if v["size"] == 8
                   and v["head8"] == want]
            hits = [f for f in rec["findings"] if f["member"] in nbt]
            obs = {"nbt_member": nbt, "loaded_value":
                   info.get("num_batches_tracked"),
                   "findings_on_it": hits}
            if n in (128, 384):
                ok = (len(nbt) == 1 and info.get("num_batches_tracked") == n
                      and any(f["rule"] == "PKL000" and f["severity"] == "LOW"
                              for f in hits))
                cli[name] = cli_exit(args.base, rec["path"])
            else:
                ok = (len(nbt) == 1 and info.get("num_batches_tracked") == n
                      and not hits)
        target = r1 if n in (128, 384) else r2
        target[name] = dict(obs, ok=ok)
    if r1:
        r1_ok = all(v["ok"] for v in r1.values())
    if r2:
        r2_ok = all(v["ok"] for v in r2.values())
    out["rows"]["R1"] = row(r1_ok, r1)
    out["rows"]["R2"] = row(r2_ok, r2)

    allrecs = list(local.values()) + hub
    on_storage = [(r["path"], f) for r in allrecs for f in r.get("findings", [])
                  if f["where"] == "storage"]
    bad = [(p, f) for p, f in on_storage if f["member_first"] != "80"]
    out["rows"]["R3"] = row(not bad if allrecs else None,
                            {"findings_on_storages": len(on_storage),
                             "not_starting_0x80": bad[:20]})

    sd_local = [r for k, r in local.items()
                if k.startswith(("bn_", "mlp_"))]
    on_pkl = [(r["path"], f) for r in sd_local for f in r.get("findings", [])
              if f["where"] == "pickle_record"]
    out["rows"]["R4"] = row(not on_pkl if sd_local else None,
                            {"files": len(sd_local), "on_data_pkl": on_pkl[:20]})

    r5 = {k: v.get("rc") for k, v in cli.items()}
    out["rows"]["R5"] = row(all(v == 0 for v in r5.values()) if r5 else None,
                            r5)
    out["reported"]["cli_bn"] = cli

    mlps = [r for k, r in local.items() if k.startswith("mlp_")
            and "error" not in r]
    n_st = sum(r.get("storages", 0) for r in mlps)
    n80 = sum(len(r.get("storages_0x80", [])) for r in mlps)
    n80_hit = sum(len(r.get("storage_0x80_with_finding", [])) for r in mlps)
    med_plus = [(r["path"], f) for r in mlps for f in r.get("findings", [])
                if SEV_RANK.get(f["severity"], 0) >= 2]
    out["rows"]["S1"] = row((3 <= n80 <= 30) if mlps else None,
                            {"files": len(mlps), "storages": n_st,
                             "starting_0x80": n80})
    out["rows"]["S2"] = row((n80 > 0 and n80_hit >= 0.9 * n80) if mlps
                            else None,
                            {"starting_0x80": n80, "with_finding": n80_hit})
    out["rows"]["S3"] = row(not med_plus if mlps else None,
                            {"medium_or_higher": med_plus[:20]})
    out["reported"]["mlp_rules"] = _hist(mlps)

    hub_ok = [r for r in hub if "error" not in r]
    h_with80 = [r for r in hub_ok if r.get("storages_0x80")]
    h_storage_findings = [f for r in hub_ok for f in r.get("findings", [])
                          if f["where"] == "storage"]
    out["rows"]["H1"] = row(len(hub_ok) >= 80, {"scanned": len(hub_ok),
                                                "errors": len(hub) - len(hub_ok)})
    share = (len(h_with80) / len(hub_ok)) if hub_ok else None
    out["rows"]["H2"] = row((0.05 <= share <= 0.60) if hub_ok else None,
                            {"files_with_0x80_storage": len(h_with80),
                             "share": share})
    out["rows"]["H3"] = row(all(f["severity"] == "LOW"
                                for f in h_storage_findings) if hub_ok
                            else None,
                            {"findings_on_storages": len(h_storage_findings),
                             "not_low": [f for f in h_storage_findings
                                         if f["severity"] != "LOW"][:20]})
    out["reported"]["hub_rules_by_where"] = _hist(hub_ok)
    out["reported"]["hub_files_with_any_finding"] = sum(
        1 for r in hub_ok if r.get("findings"))
    out["reported"]["hub_storages_total"] = sum(r.get("storages", 0)
                                                for r in hub_ok)
    out["reported"]["hub_storages_0x80"] = sum(len(r.get("storages_0x80", []))
                                               for r in hub_ok)
    out["reported"]["torchscript_and_export"] = {
        k: local[k] for k in ("ts_mlp.pt", "ep_mlp.pt2") if k in local}
    out["reported"]["hub_examples"] = [
        {"path": r["path"], "findings": r["findings"][:5]}
        for r in hub_ok if r.get("findings")][:15]
    graded = [k for k in ("P0", "R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3")]
    out["gating_rows_all_held"] = all(out["rows"][k]["status"] == "held"
                                      for k in graded)
    with open(os.path.join(args.out, "local_detail.json"), "w",
              encoding="utf-8") as fh:
        json.dump(local, fh, indent=1)
    with open(os.path.join(args.out, "hub_detail.json"), "w",
              encoding="utf-8") as fh:
        json.dump(hub, fh, indent=1)
    return out


def _hist(recs):
    h = {}
    for r in recs:
        for f in r.get("findings", []):
            k = "%s %s @%s" % (f["rule"], f["severity"], f["where"])
            h[k] = h.get(k, 0) + 1
    return h


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    ap.add_argument("--base", default="base")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    try:
        result = main(a)
    except Exception:
        result = {"fatal": traceback.format_exc()[-1500:]}
    for extra in ("fetch_report.json", "setup_report.json",
                  os.path.join("hub", "zip_census.json")):
        try:
            with open(extra, encoding="utf-8") as fh:
                result.setdefault("inputs", {})[extra] = json.load(fh)
        except Exception as exc:
            result.setdefault("inputs", {})[extra] = "missing: %s" % exc
    with open(os.path.join(a.out, "zip_storage_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(result, fh, indent=1)
    print(json.dumps({k: v.get("status") for k, v in
                      result.get("rows", {}).items()}))
    sys.exit(0)
