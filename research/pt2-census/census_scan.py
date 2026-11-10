#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step for job pt2-census-v1 (no network): scan every downloaded
.pt2 / .torchscript / .ptl file with the unchanged v0.58.0 tree, list each
file's zip members with Python's zipfile (names and first 4 bytes only),
and grade the pre-registered rows R1-R5 of research/PREREG_PT2_CENSUS.md.

Static only: the scanner reads bytes and disassembles opcodes; nothing is
unpickled, imported or loaded.

Usage: census_scan.py --out OUT_DIR [--tree tree] [--hub hub]
Writes OUT/census_summary.json, OUT/census_files.json and a copy of
hub/archive_census.json.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import json
import os
import shutil
import sys
import zipfile

from census_lib import (NATIVE, SEVERITY, ext_of, max_severity, member_of,
                        member_role, share)

MIN_FILES = 3


def rows_of(findings, root):
    rows = []
    for f in findings:
        d = f.as_dict() if hasattr(f, "as_dict") else dict(f)
        rows.append({
            "rule": d.get("rule"),
            "severity": str(d.get("severity", "")).upper(),
            "title": d.get("title"),
            "detail": str(d.get("detail") or "")[:400],
            "location": str(d.get("location") or "").replace(root, "HUB")})
    return rows


def local_members(path):
    out = {"zip": False, "members": 0, "roles": {}, "first4": {},
           "native": []}
    try:
        with zipfile.ZipFile(path) as zf:
            out["zip"] = True
            infos = zf.infolist()
            out["members"] = len(infos)
            for i in infos[:3000]:
                r = member_role(i.filename)
                out["roles"][r] = out["roles"].get(r, 0) + 1
                if ext_of(i.filename) in NATIVE:
                    out["native"].append(i.filename)
                try:
                    with zf.open(i) as fh:
                        out["first4"][i.filename] = fh.read(4).hex()
                except Exception as exc:
                    out["first4"][i.filename] = "error: %s" % type(exc).__name__
    except Exception as exc:
        out["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
    return out


def grade_lists(lists):
    rows = {}
    py = lists.get("pytorch") or {}
    n = py.get("open") or 0
    em = py.get("ext_models") or {}
    s_pt2 = share(em.get(".pt2", 0), n)
    s_ts = share(em.get("torchscript|ptl", 0), n)
    if n < 1000:
        rows["R1"] = {"verdict": "untestable", "open": n}
    else:
        rows["R1"] = {"verdict": "held" if s_pt2 < 0.005 and s_ts < 0.005
                      else "failed", "open": n, "pt2_models": em.get(".pt2", 0),
                      "pt2_share": s_pt2,
                      "torchscript_or_ptl_models": em.get("torchscript|ptl", 0),
                      "torchscript_or_ptl_share": s_ts}
    ex = lists.get("executorch") or {}
    n = ex.get("open") or 0
    em = ex.get("ext_models") or {}
    s_pte = share(em.get(".pte", 0), n)
    s_pt2 = share(em.get(".pt2", 0), n)
    if n < 20:
        rows["R2"] = {"verdict": "untestable", "open": n}
    else:
        rows["R2"] = {"verdict": "held" if s_pte > 0.9 and s_pt2 < 0.05
                      else "failed", "open": n, "pte_share": s_pte,
                      "pt2_share": s_pt2}
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tree", default="tree")
    ap.add_argument("--hub", default="hub")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    census_path = os.path.join(a.hub, "archive_census.json")
    summary = {"job": "pt2-census-v1", "prereg": "research/PREREG_PT2_CENSUS.md"}
    if not os.path.isfile(census_path):
        summary["error"] = "hub/archive_census.json missing (setup failed)"
        with open(os.path.join(a.out, "census_summary.json"), "w") as fh:
            json.dump(summary, fh, indent=1)
        print(json.dumps(summary))
        return 0
    shutil.copy(census_path, os.path.join(a.out, "archive_census.json"))
    with open(census_path, encoding="utf-8") as fh:
        census = json.load(fh)
    sys.path.insert(0, os.path.abspath(a.tree))
    import model_file_scan as mfs
    import pickle_model_scan as pms
    summary["versions"] = {"model_file_scan": mfs.__version__,
                           "pickle_model_scan": pms.__version__}
    summary["lists"] = {k: {"pages": v.get("pages"), "models": v.get("models"),
                            "open": v.get("open"), "error": v.get("error"),
                            "ext_models": v.get("ext_models")}
                        for k, v in census.get("lists", {}).items()}
    summary["targets_found"] = census.get("targets_found")
    kinds = {}
    for t in census.get("targets", []):
        key = "%s:%s" % (t.get("ext"), t.get("kind"))
        kinds[key] = kinds.get(key, 0) + 1
    summary["target_kinds"] = kinds
    rows = grade_lists(census.get("lists", {}))
    root = os.path.abspath(a.hub)
    files = []
    for d in census.get("downloads", []):
        if d.get("status") != "ok":
            continue
        path = os.path.abspath(d["path"])
        rec = {"model": d["model"], "rfilename": d["rfilename"],
               "ext": d["ext"], "bytes": d.get("bytes")}
        try:
            rec["findings"] = rows_of(mfs.scan_path(path), root)
            rec["error"] = None
        except Exception as exc:
            rec["findings"] = []
            rec["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        mem = local_members(path)
        rec["zip"] = mem
        rules = {}
        for r in rec["findings"]:
            rules[r["rule"]] = rules.get(r["rule"], 0) + 1
        rec["rules"] = rules
        rec["max_severity"] = max_severity(rec["findings"])
        notes = []
        for r in rec["findings"]:
            if r["rule"] != "PKL000":
                continue
            m = member_of(r["location"])
            first = mem["first4"].get(m) if m else None
            notes.append({"member": m, "role": member_role(m) if m else None,
                          "first4": first})
        rec["pkl000"] = notes
        files.append(rec)
    high = SEVERITY["HIGH"]
    ts = [f for f in files if f["ext"] in (".torchscript", ".ptl")
          and f["zip"]["zip"]]
    pt2 = [f for f in files if f["ext"] == ".pt2"]
    if len(ts) < MIN_FILES:
        rows["R3"] = {"verdict": "untestable", "files": len(ts)}
    else:
        bad = [f["model"] + "/" + f["rfilename"] for f in ts
               if f["error"] or f["rules"].get("PKL040", 0) != 1
               or f["max_severity"] >= high]
        rows["R3"] = {"verdict": "failed" if bad else "held",
                      "files": len(ts), "not_matching": bad}
    if len(pt2) < MIN_FILES:
        rows["R4"] = {"verdict": "untestable", "files": len(pt2)}
        rows["R5"] = {"verdict": "untestable", "files": len(pt2)}
    else:
        bad = [f["model"] + "/" + f["rfilename"] for f in pt2
               if f["error"] or f["max_severity"] >= high]
        rows["R4"] = {"verdict": "failed" if bad else "held",
                      "files": len(pt2), "not_matching": bad}
        nested = [f for f in pt2 if any(n["first4"] == "504b0304"
                                        for n in f["pkl000"])]
        rows["R5"] = {"verdict": "held" if 2 * len(nested) >= len(pt2)
                      else "failed", "files": len(pt2),
                      "with_pkl000_on_nested_zip": len(nested)}
    summary["rows"] = rows
    # Recorded without prediction.
    summary["recorded"] = {
        "downloaded": {"pt2": len(pt2), "torchscript_family": len(ts),
                       "all": len(files)},
        "pkl000_by_role": {},
        "pkl000_on_weights_starting_0x80": [],
        "native_members_downloaded": [],
        "remote": [],
    }
    rec_ = summary["recorded"]
    for f in files:
        for n in f["pkl000"]:
            role = n["role"] or "none"
            rec_["pkl000_by_role"][role] = rec_["pkl000_by_role"].get(role, 0) + 1
            if role in ("weights", "constants") and (n["first4"] or "").startswith("80"):
                rec_["pkl000_on_weights_starting_0x80"].append(
                    f["model"] + "/" + f["rfilename"] + "!" + str(n["member"]))
        if f["zip"]["native"]:
            rec_["native_members_downloaded"].append(
                {"file": f["model"] + "/" + f["rfilename"],
                 "native": f["zip"]["native"][:20],
                 "rules": f["rules"]})
    for r in census.get("remote", []):
        rec_["remote"].append({"file": r["model"] + "/" + r["rfilename"],
                               "size": r.get("size"), "status": r.get("status"),
                               "members": r.get("members"),
                               "roles": r.get("roles"),
                               "native": (r.get("native") or [])[:20]})
    summary["files"] = [{k: f[k] for k in ("model", "rfilename", "ext", "bytes",
                                           "rules", "max_severity", "error",
                                           "pkl000")} for f in files]
    with open(os.path.join(a.out, "census_files.json"), "w",
              encoding="utf-8") as fh:
        json.dump(files, fh, indent=1)
    with open(os.path.join(a.out, "census_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"rows": {k: v["verdict"] for k, v in rows.items()},
                      "downloaded": rec_["downloaded"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
