#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Staged (run 282, NOT yet run or filed): executorch_pte_scan PTE005 fires
only when a headerless program lists a segment that holds bytes.

Why: ExecuTorch's own writer (exir/_serialize/_program.py,
serialize_pte_binary) appends the constant segment whenever
constant_segment_offsets is non-empty -- a program with no constants still
gets offsets [0] and an EMPTY segment, so program.segments lists one entry
of size 0 -- and then skips the eh00 extended header when the segment bytes
total zero ("if len(segments_data) == 0: return Cord(result.data)"). The
runtime (runtime/executor/program.cpp) treats a headerless file as having
no segments and a one-offset constant segment as "no constants", so nothing
is ever read from that segment. 0.1.0 still raised PTE005 (medium) on this
writer output: all 8 PTE005 files of 450 honest published .pte files in
job pte-census-v1 are headerless and list exactly 1 segment.

Usage: patch_pte005.py TREE PATCHED OUT FROM TO

TREE holds executorch_pte_scan.py (version FROM), test_executorch_pte_scan.py,
EXECUTORCH_PTE_SCAN.md and any other test_executorch_pte_*.py. Version-
agnostic: apply on top of whatever version ships last (0.1.1 dtype or 0.1.2
PTE003 severity); none of the anchors below overlaps those edits.

Edits:
1. __version__ FROM -> TO.
2. Docstring PTE005 row: "segments without a segment base offset" becomes
   "non-empty segments without a segment base offset".
3. scan(): the headerless PTE005 test becomes "any listed segment has a
   non-zero size" (was: "any segment is listed"). A segment of size 0 holds
   no bytes, so no read can leave the file through it. Sizes > 0 with no
   header still raise PTE005 exactly as before (existing test unchanged).
4. Every test_executorch_pte_*.py: pte.__version__ "FROM" -> "TO".
5. EXECUTORCH_PTE_SCAN.md: "Changes in TO" section appended.
Copies test_executorch_pte_segments.py in, writes OUT/patched and
OUT/patch_report.json. Always exits 0; the report is graded.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

ROW_OLD = ("                         than its extended header says, segments "
           "without a\n"
           "                         segment base offset, or findings capped.\n")
ROW_NEW = ("                         than its extended header says, non-empty "
           "segments\n"
           "                         without a segment base offset, or "
           "findings capped.\n")

SCAN_OLD = "        if self.segments and region is None:\n"
SCAN_NEW = ("        # ExecuTorch's writer lists an empty constant segment and "
            "writes\n"
            "        # no eh00 header when a program has no constants; a size-0 "
            "segment\n"
            "        # holds no bytes, so only a non-empty one needs a base "
            "offset.\n"
            "        if region is None and any(size for _, size in "
            "self.segments):\n")

VERSION_RE = r"^\d+\.\d+\.\d+$"


def doc_section(to):
    return ('''
## Changes in %s

- PTE005 no longer fires on a program that has no `eh00` extended header and
  lists only **empty** (size 0) data segments. This is what ExecuTorch's own
  writer produces for a program without constants
  (`exir/_serialize/_program.py`: the constant segment is listed with
  offsets `[0]` and no bytes, and the extended header is skipped when the
  segment data is empty); the runtime treats a headerless file as having no
  segments, so nothing is read from it. All 8 PTE005 findings among 450
  honest published `.pte` files in job pte-census-v1 had this shape
  ([RESULTS_PTE_CENSUS_2026-11.md](RESULTS_PTE_CENSUS_2026-11.md)). A
  headerless program that lists a segment holding bytes still gets PTE005.
  Pre-registered in
  [research/PREREG_PTE005_EMPTY_SEGMENT.md](research/PREREG_PTE005_EMPTY_SEGMENT.md).
''' % to)


def edit_once(text, old, new, name, rep):
    n = text.count(old)
    rep["edits"].append({"file": name, "anchor": old[:60], "matches": n})
    if n != 1:
        rep["ok"] = False
        return text
    return text.replace(old, new, 1)


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main():
    tree, patched, out = (os.path.abspath(a) for a in sys.argv[1:4])
    old_v, new_v = sys.argv[4], sys.argv[5]
    rep = {"ok": True, "edits": [], "error": None, "from": old_v, "to": new_v}
    try:
        if not (re.match(VERSION_RE, old_v) and re.match(VERSION_RE, new_v)):
            raise ValueError("FROM and TO must be X.Y.Z")
        shutil.rmtree(patched, ignore_errors=True)
        os.makedirs(patched)

        name = "executorch_pte_scan.py"
        with open(os.path.join(tree, name), encoding="utf-8") as fh:
            mod = fh.read()
        mod = edit_once(mod, '__version__ = "%s"\n' % old_v,
                        '__version__ = "%s"\n' % new_v, name, rep)
        mod = edit_once(mod, ROW_OLD, ROW_NEW, name, rep)
        mod = edit_once(mod, SCAN_OLD, SCAN_NEW, name, rep)
        write(os.path.join(patched, name), mod)

        pin_old = 'pte.__version__, "%s")' % old_v
        pin_new = 'pte.__version__, "%s")' % new_v
        for test in sorted(os.listdir(tree)):
            if not (test.startswith("test_executorch_pte_")
                    and test.endswith(".py")):
                continue
            with open(os.path.join(tree, test), encoding="utf-8") as fh:
                text = fh.read()
            n = text.count(pin_old)
            rep["edits"].append({"file": test, "anchor": pin_old,
                                 "matches": n})
            if test == "test_executorch_pte_scan.py" and n != 1:
                rep["ok"] = False
            write(os.path.join(patched, test), text.replace(pin_old, pin_new))

        name = "EXECUTORCH_PTE_SCAN.md"
        with open(os.path.join(tree, name), encoding="utf-8") as fh:
            doc = fh.read()
        if "## Changes in %s" % new_v in doc:
            rep["ok"] = False
            rep["edits"].append({"file": name, "anchor": "already has " + new_v,
                                 "matches": 1})
        write(os.path.join(patched, name),
              doc.rstrip("\n") + "\n" + doc_section(new_v))

        extra = "test_executorch_pte_segments.py"
        shutil.copy(os.path.join(HERE, extra), os.path.join(patched, extra))
        dest = os.path.join(out, "patched")
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(patched, dest)
    except Exception as exc:
        rep["ok"] = False
        rep["error"] = "%s: %s" % (type(exc).__name__, exc)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps(rep, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
