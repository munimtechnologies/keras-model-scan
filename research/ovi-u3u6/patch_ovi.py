#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""openvino_ir_scan 0.1.2: give the size checks bit widths for u3 and u6.

OpenVINO's element types include u3 and u6 (element_type.hpp). 0.1.1 has no
bit width for them, so OVI004 (size overflow) and OVI005 (declared size too
small) silently skip u3/u6 Consts. OpenVINO up to 2026.4 packs them in 3-byte
units (8 u3 or 4 u6 values per 3 bytes); PR #37430 (milestone 2026.5) packs
them tightly, ceil(n * bits / 8) bytes. The scanner's existing formula,
(n * bits + 7) >> 3, is the tight size, which is never more than the 3-byte
split size, so honest files of either layout pass.

Keeps a copy of the original as ORIG_DIR/openvino_ir_scan.py, patches TREE in
place, writes the patched file and the new test to OUT, copies the new test
into TREE. Each edit applies exactly once or is already in place; a second
pass changes nothing.

Usage: patch_ovi.py TREE OUT ORIG_DIR

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEST = "test_openvino_ir_scan_u3u6.py"
ROW_RE = re.compile(r'(?m)^([ \t]*)"nf4": 4, "boolean": 8,[ \t]*$')
ADDED = '"u3": 3, "u6": 6,  # tight size; never above the 3-byte split size'
VER_OLD = '__version__ = "0.1.1"'
VER_NEW = '__version__ = "0.1.2"'


def apply(text):
    notes = []
    if ADDED not in text:
        hits = list(ROW_RE.finditer(text))
        if len(hits) != 1:
            raise ValueError("nf4/boolean row found %d times" % len(hits))
        m = hits[0]
        text = (text[:m.end()] + "\n" + m.group(1) + ADDED
                + text[m.end():])
        notes.append("u3/u6 bit widths")
    if VER_NEW not in text:
        if text.count(VER_OLD) != 1:
            raise ValueError("version line found %d times"
                             % text.count(VER_OLD))
        text = text.replace(VER_OLD, VER_NEW)
        notes.append("version 0.1.2")
    return text, notes


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    tree, out, orig = args
    os.makedirs(out, exist_ok=True)
    os.makedirs(orig, exist_ok=True)
    path = os.path.join(tree, "openvino_ir_scan.py")
    with open(path, encoding="utf-8", newline="") as fh:
        old = fh.read()
    with open(os.path.join(orig, "openvino_ir_scan.py"), "w",
              encoding="utf-8", newline="") as fh:
        fh.write(old)
    report = {}
    status = 0
    try:
        if "\r\n" in old:
            raise ValueError("CRLF")
        new, notes = apply(old)
        again, notes2 = apply(new)
        o, n = old.split("\n"), new.split("\n")
        # Nothing but the one added line and the version line may differ.
        lost = [ln for ln in o if ln not in n and ln != VER_OLD]
        ok = not notes2 and again == new and not lost and \
            len(n) - len(o) in (0, 1)
        report = {"changes": notes, "second_pass": notes2, "lost": lost,
                  "lines": [len(o), len(n)], "ok": ok}
        if not ok:
            status = 6
        else:
            for dest in (path, os.path.join(out, "openvino_ir_scan.py")):
                with open(dest, "w", encoding="utf-8", newline="") as fh:
                    fh.write(new)
            for dest in (os.path.join(tree, TEST), os.path.join(out, TEST)):
                shutil.copyfile(os.path.join(HERE, TEST), dest)
    except ValueError as exc:
        report = {"error": str(exc)}
        status = 5
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return status


if __name__ == "__main__":
    sys.exit(main())
