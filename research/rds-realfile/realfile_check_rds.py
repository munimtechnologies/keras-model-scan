#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Pre-registered real-file check of r_serialized_scan (PREREG_RDS_REALFILE.md).

Scans the files make_files.R wrote with R itself and grades R1-R15. A file
that R failed to build is NOT TESTED, never a pass. Made with AI agents
working in the name of MV2 of Munim, Inc.
"""

import argparse
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "ship", "rds"))

import r_serialized_scan as rs  # noqa: E402


def _exactly(rules, needles=()):
    def check(found, evidence):
        return found == rules and all(n in evidence for n in needles)
    return check


def _no_high_and(rule, needles):
    def check(found, evidence):
        return (not {"RDS001", "RDS002", "RDS004"} & set(found)
                and rule in found and all(n in evidence for n in needles))
    return check


def _pkgfun(found, evidence):
    return ("RDS002" in found and "RDS003" in found and "RDS004" not in found
            and "rpart" in evidence and "eval" in evidence)


CASES = [
    ("R1", "plain.rds", _exactly([])),
    ("R2", "lm.rds", _exactly([])),
    ("R3", "glm.rds", _exactly([])),
    ("R4", "rpart.rds", _no_high_and("RDS003", ["rpart"])),
    ("R5", "fn_system.rds", _exactly(["RDS002"], ["calls system()"])),
    ("R6", "fn_system_bc.rds", _exactly(["RDS002"], ["calls system()"])),
    ("R7", "promise.rds", _exactly(["RDS001"], ["promise calls Sys.time()"])),
    ("R8", "active.rds", _exactly(["RDS001"], ["active binding"])),
    ("R9", "pkgfun.rds", _pkgfun),
    ("R10", "fn_ascii.rds", _exactly(["RDS002"], ["calls system()"])),
    ("R11", "plain_xz.rds", _exactly([])),
    ("R12", "plain_bz2.rds", _exactly([])),
    ("R13", "workspace.RData", _exactly([])),
    ("R14", "plain_v2.rds", _exactly([])),
    ("R15", "altrep.rds", _exactly([])),
]


def _status(files):
    status = {}
    path = os.path.join(files, "build_status.tsv")
    if os.path.isfile(path):
        with open(path) as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t", 1)
                if len(parts) == 2:
                    status[parts[0]] = parts[1]
    return status


def _head(path, count=12):
    with open(path, "rb") as handle:
        return handle.read(count).hex()


def run(out_dir):
    files = os.path.join(out_dir, "files")
    status = _status(files)
    rows = []
    for pid, name, check in CASES:
        path = os.path.join(files, name)
        row = {"id": pid, "file": name, "build": status.get(pid, "missing")}
        if row["build"] != "ok" or not os.path.isfile(path):
            row["result"] = "NOT TESTED"
            rows.append(row)
            print(json.dumps(row))
            continue
        try:
            findings = rs.scan_file(path)
            found = [f["rule"] for f in findings]
            evidence = " | ".join(f["evidence"] for f in findings)
            row.update({"rules": found, "findings": findings,
                        "bytes": os.path.getsize(path),
                        "head_hex": _head(path),
                        "result": "PASS" if check(found, evidence)
                        else "FAIL"})
        except Exception as exc:
            row.update({"result": "FAIL",
                        "error": "%s: %s" % (type(exc).__name__, exc),
                        "traceback": traceback.format_exc()[-2000:]})
        rows.append(row)
        print(json.dumps({k: v for k, v in row.items()
                          if k not in ("findings", "traceback")}))
    version = ""
    vpath = os.path.join(files, "r_version.txt")
    if os.path.isfile(vpath):
        with open(vpath) as handle:
            version = handle.read().strip()
    summary = {"r": version, "scanner": rs.__version__,
               "passed": sum(1 for r in rows if r["result"] == "PASS"),
               "failed": sum(1 for r in rows if r["result"] == "FAIL"),
               "not_tested": sum(1 for r in rows
                                 if r["result"] == "NOT TESTED"),
               "total": len(rows), "rows": rows}
    with open(os.path.join(out_dir, "realfile_summary.json"), "w") as handle:
        json.dump(summary, handle, indent=1)
    print("passed %d, failed %d, not tested %d of %d" % (
        summary["passed"], summary["failed"], summary["not_tested"],
        summary["total"]))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/out")
    sys.exit(run(parser.parse_args().out))
