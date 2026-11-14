#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step for job pte-dtype-v2 (no network): compare the patched
executorch_pte_scan dtype table with ExecuTorch's own source, saved by
fetch_vendor.py at the pinned commit.

Usage: vendor_check.py PATCHED_DIR TREE_DIR OUT

Correction to job pte-dtype-v1 (pre-registered in
research/PREREG_PTE_DTYPE_FIX_V2.md): v1's entry regex could not match an
`_(ctype, Name)` entry whose line is wrapped with a backslash continuation
between the C type and the name. In scalar_type.h that is ComplexHalf (8)
and the four Float8 types (23-26), so v1 numbered the remaining entries by
position, shifted by one, and failed V1 on a grader error. Here:

- Line continuations (backslash + newline) are joined BEFORE parsing.
- V1 (unchanged meaning): one entry per `_(ctype, Name)` in order (index =
  position; the `/* n */` comment must agree), every C type has a known
  size, the patched table has exactly those keys and every size matches.
- V3 (new, parse completeness): the number of `_(` entry starts, the number
  of parsed entries and the number of `/* n */` comments are equal, every
  entry has a comment, and the comments are exactly 0..N-1. A grader that
  silently skips an entry fails V3 instead of grading a shifted list.
- V2 (unchanged): tensor_parser_portable.cpp still rejects a tensor only
  through isValid(scalar_type), and isValid's body tests >= 0, NumOptions
  and Undefined.
Writes OUT/vendor_check.json. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")

BASE = {"uint8_t": 1, "int8_t": 1, "int16_t": 2, "int32_t": 4, "int64_t": 8,
        "uint16_t": 2, "uint32_t": 4, "uint64_t": 8, "float": 4, "double": 8,
        "bool": 1, "Half": 2, "BFloat16": 2, "qint8": 1, "quint8": 1,
        "qint32": 4, "quint4x2": 1, "quint2x4": 1, "bits1x8": 1, "bits2x4": 1,
        "bits4x2": 1, "bits8": 1, "bits16": 2, "Float8_e5m2": 1,
        "Float8_e4m3fn": 1, "Float8_e5m2fnuz": 1, "Float8_e4m3fnuz": 1}
ENTRY_RX = re.compile(r"_\(\s*([^,()]+?)\s*,\s*(\w+)\s*\)"
                      r"(?:\s*/\*\s*(\d+)\s*\*/)?")
START_RX = re.compile(r"(?:^|[^\w])_\(")
COMMENT_RX = re.compile(r"/\*\s*(\d+)\s*\*/")
CONT_RX = re.compile(r"\\[ \t]*\r?\n")
COMPLEX_RX = re.compile(r"^(?:::)?(?:\w+::)*complex<(.+)>$")


def csize(ctype):
    t = re.sub(r"\s+", "", ctype)
    m = COMPLEX_RX.match(t)
    if m:
        inner = csize(m.group(1))
        return 2 * inner if inner else None
    return BASE.get(t.split("::")[-1])


def macro_block(text, name):
    m = re.search(r"#define\s+" + re.escape(name) + r"\s*\(", text)
    if m is None:
        return None
    lines = []
    for line in text[m.start():].splitlines(keepends=True):
        lines.append(line)
        if not line.rstrip().endswith("\\"):
            break
    return "".join(lines)


def flatten(block):
    """Join backslash line continuations into one logical line."""
    return CONT_RX.sub(" ", block)


def parse_entries(block):
    flat = flatten(block)
    entries = []
    for pos, (ctype, name, num) in enumerate(ENTRY_RX.findall(flat)):
        entries.append({"index": pos, "name": name, "ctype": ctype.strip(),
                        "comment": int(num) if num else None,
                        "size": csize(ctype)})
    return entries


def completeness(block, entries):
    """Row V3: nothing in the macro was skipped by the parser."""
    flat = flatten(block)
    starts = len(START_RX.findall(flat))
    comments = [int(c) for c in COMMENT_RX.findall(flat)]
    problems = []
    if not (starts == len(entries) == len(comments)):
        problems.append("entry starts %d, parsed %d, comments %d"
                        % (starts, len(entries), len(comments)))
    missing = [e["name"] for e in entries if e["comment"] is None]
    if missing:
        problems.append("entries without a comment: %s" % missing)
    got = [e["comment"] for e in entries]
    if got != list(range(len(entries))):
        problems.append("comments are not 0..N-1: %s" % got)
    return problems, {"starts": starts, "parsed": len(entries),
                      "comments": len(comments)}


def compare(entries, table):
    """Row V1: positions, comments, sizes and table keys all agree."""
    problems = []
    for e in entries:
        if e["comment"] is not None and e["comment"] != e["index"]:
            problems.append("%s: comment %d at position %d"
                            % (e["name"], e["comment"], e["index"]))
        if e["size"] is None:
            problems.append("%s: unknown C type %s" % (e["name"], e["ctype"]))
    runtime = {e["index"]: e["size"] for e in entries}
    if set(table) != set(runtime):
        problems.append("keys differ: table only %s, runtime only %s"
                        % (sorted(set(table) - set(runtime)),
                           sorted(set(runtime) - set(table))))
    for k in sorted(set(table) & set(runtime)):
        if table[k] != runtime[k]:
            problems.append("dtype %d: table %s, runtime %s"
                            % (k, table[k], runtime[k]))
    return problems


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(name):
    with open(os.path.join(VENDOR, name), encoding="utf-8") as fh:
        return fh.read()


def main():
    patched, tree, out = (os.path.abspath(a) for a in sys.argv[1:4])
    os.makedirs(out, exist_ok=True)
    rep = {"V1": {"result": "untestable", "why": ""},
           "V2": {"result": "untestable", "why": ""},
           "V3": {"result": "untestable", "why": ""}}
    try:
        with open(os.path.join(VENDOR, "fetch.json"), encoding="utf-8") as fh:
            rep["fetch"] = json.load(fh)
    except Exception as exc:
        rep["fetch"] = {"error": str(exc)}
    try:
        new = load(os.path.join(patched, "executorch_pte_scan.py"), "pte_new")
        old = load(os.path.join(tree, "executorch_pte_scan.py"), "pte_old")
        table_new, table_old = dict(new._ELEMENT_SIZE), dict(old._ELEMENT_SIZE)
    except Exception as exc:
        rep["V1"]["why"] = "scanner import failed: %s" % exc
        table_new = table_old = None
    try:
        block = macro_block(read("scalar_type.h"), "ET_FORALL_SCALAR_TYPES")
        if block is None:
            raise ValueError("ET_FORALL_SCALAR_TYPES not found")
        entries = parse_entries(block)
        rep["entries"] = entries
        v3_problems, counts = completeness(block, entries)
        rep["counts"] = counts
        rep["V3"] = {"result": "failed" if v3_problems else "held",
                     "why": "; ".join(v3_problems) or
                            "%d entry starts, %d parsed, %d comments, 0..%d"
                            % (counts["starts"], counts["parsed"],
                               counts["comments"], len(entries) - 1)}
        if table_new is not None and entries:
            problems = compare(entries, table_new)
            rep["unpatched_missing"] = [
                {"index": e["index"], "name": e["name"]} for e in entries
                if e["index"] not in table_old]
            rep["V1"] = {"result": "failed" if problems else "held",
                         "why": "; ".join(problems) or
                                "%d runtime dtypes, table equal" % len(entries)}
        elif not entries:
            rep["V1"]["why"] = "no entries parsed"
    except Exception as exc:
        rep["V1"]["why"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        parser = read("tensor_parser_portable.cpp")
        util = read("scalar_type_util.h")
        m = re.search(r"inline\s+bool\s+isValid\s*\([^)]*\)\s*\{(.*?)\}",
                      util, re.S)
        body = m.group(1) if m else ""
        checks = {"parser_calls_isValid": "isValid(scalar_type)" in parser,
                  "isValid_found": bool(m),
                  "nonnegative": ">= 0" in body,
                  "NumOptions": "NumOptions" in body,
                  "Undefined": "Undefined" in body}
        rep["V2"] = {"result": "held" if all(checks.values()) else "failed",
                     "why": json.dumps(checks)}
        rep["isValid_body"] = re.sub(r"\s+", " ", body).strip()[:300]
    except Exception as exc:
        rep["V2"]["why"] = "%s: %s" % (type(exc).__name__, exc)
    with open(os.path.join(out, "vendor_check.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({k: rep[k] for k in ("V1", "V2", "V3")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
