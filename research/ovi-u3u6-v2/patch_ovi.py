#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""openvino_ir_scan 0.1.2 (second attempt): u3/u6 bit widths, the old test's
exact version pin, and the doc section.

ovi-u3u6-v1 held 9 of 10 rows; S1 failed only because
test_openvino_ir_scan.test_version asserts __version__ == "0.1.1" exactly.
This version makes three edits, each exactly once or already in place:

  openvino_ir_scan.py        add "u3": 3, "u6": 6 to _BITWIDTH; 0.1.1 -> 0.1.2
  test_openvino_ir_scan.py   exact pin -> minimum-version check (>= 0.1.2)
  OPENVINO_IR_SCAN.md        a "u3 and u6" section before "Prior art ..."

A second pass must change nothing and no line may be lost except the replaced
ones. Only if every file passes are the patched files written to TREE and
OUT/patched (originals go to ORIG_DIR). The new test module is copied too.
Always exits 0: the result is graded as row P1 by u3u6_check.py.

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

PIN_RE = re.compile(
    r'(?m)^([ \t]*)self\.assertEqual\(ov\.__version__, "0\.1\.1"\)[ \t]*$')
PIN_DONE = "self.assertGreaterEqual(parts, (0, 1, 2))"
PIN_NEW = ('{i}parts = tuple(int(p) for p in ov.__version__.split("."))\n'
           '{i}' + PIN_DONE)

DOC_ANCHOR = "## Prior art and honest limits"
DOC_MARK = "<!-- ovi-u3u6 -->"
DOC_SECTION = """<!-- ovi-u3u6 -->
## u3 and u6 (v0.1.2, November 2026)

OpenVINO's element types include `u3` and `u6`. Up to 0.1.1 they had no
entry in the bit-width table, so the size-overflow check (OVI004) and the
declared-size check (OVI005) skipped Consts of those types. 0.1.2 gives them
3 and 6 bits. The size it requires is the tight size, ceil(n x bits / 8)
bytes. OpenVINO up to 2026.4 writes a larger 3-byte layout (8 u3 or 4 u6
values per 3 bytes, rounded up); OpenVINO PR #37430 (milestone 2026.5) packs
them tightly. Honest files of either layout pass. Pre-registered checks on
files written by OpenVINO 2026.4.1:
[first run](REALFILE_CHECK_OVI_U3U6_2026-11.md) (its only failure was an old
test pinning the version string) and the re-run in
[research/PREREG_OVI_U3U6_V2.md](research/PREREG_OVI_U3U6_V2.md).

"""


def edit_scanner(text):
    notes = []
    if ADDED not in text:
        hits = list(ROW_RE.finditer(text))
        if len(hits) != 1:
            raise ValueError("nf4/boolean row found %d times" % len(hits))
        m = hits[0]
        text = text[:m.end()] + "\n" + m.group(1) + ADDED + text[m.end():]
        notes.append("u3/u6 bit widths")
    if VER_NEW not in text:
        if text.count(VER_OLD) != 1:
            raise ValueError("version line found %d times"
                             % text.count(VER_OLD))
        text = text.replace(VER_OLD, VER_NEW)
        notes.append("version 0.1.2")
    return text, notes


def edit_test(text):
    if PIN_DONE in text:
        return text, []
    hits = list(PIN_RE.finditer(text))
    if len(hits) != 1:
        raise ValueError("exact version pin found %d times" % len(hits))
    m = hits[0]
    text = text[:m.start()] + PIN_NEW.format(i=m.group(1)) + text[m.end():]
    return text, ["version pin -> minimum (0, 1, 2)"]


def edit_doc(text):
    if DOC_MARK in text:
        return text, []
    n = text.count("\n" + DOC_ANCHOR)
    if n > 1:
        raise ValueError("doc anchor found %d times" % n)
    if n == 0:  # no anchor: append at the end instead
        sep = "" if text.endswith("\n\n") else ("\n" if text.endswith("\n")
                                                 else "\n\n")
        return text + sep + DOC_SECTION.rstrip("\n") + "\n", \
            ["doc section (appended)"]
    i = text.index("\n" + DOC_ANCHOR) + 1
    return text[:i] + DOC_SECTION + text[i:], ["doc section"]


EDITS = (
    ("openvino_ir_scan.py", edit_scanner, {VER_OLD}),
    ("test_openvino_ir_scan.py", edit_test, None),
    ("OPENVINO_IR_SCAN.md", edit_doc, set()),
)


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 0
    tree, out, orig = args
    patched_dir = os.path.join(out, "patched")
    for d in (out, orig, patched_dir):
        os.makedirs(d, exist_ok=True)
    report = {"files": {}, "ok": False}
    new_texts = {}
    try:
        for name, fn, allowed_lost in EDITS:
            path = os.path.join(tree, name)
            with open(path, encoding="utf-8", newline="") as fh:
                old = fh.read()
            with open(os.path.join(orig, name), "w", encoding="utf-8",
                      newline="") as fh:
                fh.write(old)
            entry = {}
            try:
                if "\r\n" in old:
                    raise ValueError("CRLF")
                new, notes = fn(old)
                again, notes2 = fn(new)
                o, n = old.split("\n"), new.split("\n")
                new_set = set(n)
                lost = [ln for ln in o if ln not in new_set]
                if allowed_lost is None:
                    # the test edit replaces exactly the pinned line
                    lost = [ln for ln in lost if not PIN_RE.match(ln)]
                else:
                    lost = [ln for ln in lost if ln not in allowed_lost]
                entry = {"changes": notes, "second_pass": notes2,
                         "lost": lost, "lines": [len(o), len(n)],
                         "ok": bool(notes) and not notes2 and again == new
                         and not lost}
                new_texts[name] = new
            except ValueError as exc:
                entry = {"error": str(exc), "ok": False}
            report["files"][name] = entry
        report["ok"] = all(e.get("ok") for e in report["files"].values()) \
            and len(report["files"]) == len(EDITS)
        if report["ok"]:
            for name, text in new_texts.items():
                for dest in (os.path.join(tree, name),
                             os.path.join(patched_dir, name)):
                    with open(dest, "w", encoding="utf-8", newline="") as fh:
                        fh.write(text)
            for dest in (os.path.join(tree, TEST),
                         os.path.join(patched_dir, TEST)):
                shutil.copyfile(os.path.join(HERE, TEST), dest)
            report["written"] = sorted(list(new_texts) + [TEST])
    except Exception as exc:  # never stop later steps
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
        report["ok"] = False
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
