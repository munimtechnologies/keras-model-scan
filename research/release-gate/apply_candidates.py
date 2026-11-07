#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step of the release gate: copy each named candidate's files from
TREE/research/candidates/<name>/ to the places its manifest.json names, after
checking that the live files it replaces are still the versions the
candidate was checked against.

manifest.json:
  {"name": "...", "job": "<job that graded it>",
   "expect_main": {"<repo file>": "<version on main>"},
   "expect_after": {"<repo file>": "<version after overlay>"},
   "files": {"<file in the candidate folder>": "<repo path>"}}

Usage: python apply_candidates.py TREE OUT name [name ...]
Writes OUT/apply_report.json. Always exits 0 (the gate grades the report).
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import hashlib
import json
import os
import re
import shutil
import sys

VER_RE = re.compile(r'(?m)^__version__\s*=\s*"(\d+\.\d+\.\d+)"')


def version_in(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            m = VER_RE.search(fh.read())
        return m.group(1) if m else None
    except OSError:
        return None


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def apply_one(tree, name):
    row = {"name": name, "ok": False, "problems": []}
    base = os.path.join(tree, "research", "candidates", name)
    try:
        with open(os.path.join(base, "manifest.json"), encoding="utf-8") as fh:
            man = json.load(fh)
    except (OSError, ValueError) as exc:
        row["problems"].append("manifest: %s" % exc)
        return row
    row["job"] = man.get("job")
    row["main_versions"] = {}
    for path, want in (man.get("expect_main") or {}).items():
        have = version_in(os.path.join(tree, path))
        row["main_versions"][path] = have
        if have != want:
            row["problems"].append("%s on main is %s, expected %s"
                                   % (path, have, want))
    row["copied"] = {}
    for src, dest in (man.get("files") or {}).items():
        s = os.path.join(base, src)
        d = os.path.join(tree, dest)
        if not os.path.isfile(s):
            row["problems"].append("missing candidate file %s" % src)
            continue
        if row["problems"]:
            continue
        existed = os.path.isfile(d)
        shutil.copyfile(s, d)
        row["copied"][dest] = {"from": src, "replaced": existed,
                               "sha256": sha256(d)}
    row["after_versions"] = {}
    for path, want in (man.get("expect_after") or {}).items():
        have = version_in(os.path.join(tree, path))
        row["after_versions"][path] = have
        if have != want:
            row["problems"].append("%s after overlay is %s, expected %s"
                                   % (path, have, want))
    row["ok"] = not row["problems"] and bool(row["copied"])
    return row


def main():
    tree, out = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(out, exist_ok=True)
    rows = []
    for name in sys.argv[3:]:
        try:
            rows.append(apply_one(tree, name))
        except Exception as exc:  # recorded, graded as a failed G1
            rows.append({"name": name, "ok": False,
                         "problems": ["%s: %s" % (type(exc).__name__, exc)]})
    report = {"candidates": rows, "all_ok": bool(rows) and all(r["ok"] for r in rows)}
    with open(os.path.join(out, "apply_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
