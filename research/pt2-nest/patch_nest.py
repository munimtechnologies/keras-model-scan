#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""pickle_model_scan 0.8.0: a zip member that is itself a zip is scanned as
a zip.

Jobs torchscript-v1 and ts-fix-v1 recorded that an honest torch.export .pt2
file gets one PKL000 LOW "could not be fully parsed" on its member
<prefix>/data/sample_inputs/model.pt: the member has a pickle-like extension,
so scan_zip handed its bytes to the pickle walker, but it starts with the zip
magic PK\\x03\\x04. The pickles inside it were never read.

Edits to pickle_model_scan.py (each exactly once, or already in place; a
second pass changes nothing; no line is lost except the replaced version and
signature lines):
  docstring paragraph; __version__ 0.7.0 -> 0.8.0;
  helpers _ZIP_MAGIC, _ZIP_NEST_MAX = 2, _opens_as_zip() before scan_zip;
  scan_zip(data, source) -> scan_zip(data, source, _depth=0) (callers keep
  working); in its member loop, a member that starts with the zip magic, is
  not a raw tensor storage, opens as a zip, and sits less than _ZIP_NEST_MAX
  levels deep is scanned with scan_zip(member, member_src, _depth + 1).
  Anything else takes the old path unchanged.
model_file_scan.py and pyproject.toml are not changed (0.14.0).

Copies the new test file into TREE. All-or-nothing: nothing is written unless
every edit checks out. Changed files go to OUT/patched, originals to OUT/orig,
every top-level .py to OUT/tree_py, the report to OUT/patch_report.json.
Always exits 0; the check grades row P1.

Usage: patch_nest.py TREE OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ("test_pickle_model_scan_nested_zip.py",)

PMS_VER = ('__version__ = "0.7.0"', '__version__ = "0.8.0"')
DOC_ANCHOR = "A flag means a pattern worth human review, not proof of malice."
DOC_MARK = "Since 0.8.0, a zip member"
DOC_NEW = (
    "Since 0.8.0, a zip member that is itself a zip archive (for example the\n"
    "torch.save archive that torch.export.save stores as\n"
    "<prefix>/data/sample_inputs/model.pt inside a .pt2 file) is scanned as a\n"
    "zip, up to two levels deep, instead of being read as one pickle stream.\n"
    "Up to 0.7.0 such a member got a PKL000 LOW \"could not be fully parsed\"\n"
    "note and the pickles inside it were never read. Raw tensor storages are\n"
    "never opened this way.\n"
    "\n")

SIG_OLD = "def scan_zip(data, source):\n"
SIG_MARK = "def _opens_as_zip("
SIG_NEW = r'''_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_NEST_MAX = 2


def _opens_as_zip(data):
    """True when zipfile can open DATA as an archive.

    Used for a zip member that is itself a zip, such as the torch.save
    archive torch.export.save stores at <prefix>/data/sample_inputs/model.pt
    inside a .pt2 file. Such a member is scanned as a zip (up to
    _ZIP_NEST_MAX levels below the outer file) instead of being read as one
    pickle stream."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.namelist()
        return True
    except Exception:
        return False


def scan_zip(data, source, _depth=0):
'''

LOOP_OLD = r'''        if ext == ".npy":
            findings += scan_npy(member, member_src)
        elif (ext in PICKLE_EXTS or base == "data.pkl"
'''
LOOP_MARK = "_depth < _ZIP_NEST_MAX"
LOOP_NEW = r'''        if ext == ".npy":
            findings += scan_npy(member, member_src)
        elif (member[:4] == _ZIP_MAGIC and name not in raw_storage
              and _depth < _ZIP_NEST_MAX and _opens_as_zip(member)):
            findings += scan_zip(member, member_src, _depth + 1)
        elif (ext in PICKLE_EXTS or base == "data.pkl"
'''


def once(text, old, new, mark, label, notes):
    if mark in text:
        return text
    n = text.count(old)
    if n != 1:
        raise ValueError("%s: anchor found %d times" % (label, n))
    notes.append(label)
    return text.replace(old, new)


def apply_pms(text):
    notes = []
    text = once(text, DOC_ANCHOR, DOC_NEW + DOC_ANCHOR, DOC_MARK, "docstring",
                notes)
    text = once(text, PMS_VER[0], PMS_VER[1], PMS_VER[1], "version 0.8.0",
                notes)
    text = once(text, SIG_OLD, SIG_NEW, SIG_MARK, "helpers+signature", notes)
    text = once(text, LOOP_OLD, LOOP_NEW, LOOP_MARK, "scan_zip loop", notes)
    return text, notes


PLAN = (("pickle_model_scan.py", apply_pms, 4,
         {PMS_VER[0], SIG_OLD.rstrip("\n")}),)


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 0
    tree, out = args
    pdir = os.path.join(out, "patched")
    orig = os.path.join(out, "orig")
    for d in (out, orig, pdir):
        os.makedirs(d, exist_ok=True)
    report = {"files": {}, "ok": False}
    try:
        for name in ("README.md", "PICKLE_SCAN.md", "MODEL_FILE_SCAN.md",
                     "pyproject.toml", "model_file_scan.py",
                     "pickle_model_scan.py", "test_attribution.py"):
            src = os.path.join(tree, name)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(orig, name))
        allpy = os.path.join(out, "tree_py")
        os.makedirs(allpy, exist_ok=True)
        for entry in sorted(os.listdir(tree)):
            if entry.endswith(".py") and os.path.isfile(
                    os.path.join(tree, entry)):
                shutil.copyfile(os.path.join(tree, entry),
                                os.path.join(allpy, entry))
        report["tree_py"] = sorted(os.listdir(allpy))
        staged = {}
        for name, fn, want, replaced in PLAN:
            old = read(os.path.join(tree, name))
            if "\r\n" in old:
                raise ValueError("%s: CRLF" % name)
            new, notes = fn(old)
            again, notes2 = fn(new)
            o, n = old.split("\n"), new.split("\n")
            nset = set(n)
            lost = [ln for ln in o if ln not in nset and ln not in replaced]
            ok = (len(notes) == want and not notes2 and again == new
                  and not lost)
            report["files"][name] = {"changes": notes, "second_pass": notes2,
                                     "lost": lost[:20],
                                     "lines": [len(o), len(n)], "ok": ok}
            if not ok:
                raise ValueError("%s: check failed" % name)
            compile(new, name, "exec")
            staged[name] = new
        for name, new in staged.items():
            write(os.path.join(tree, name), new)
            write(os.path.join(pdir, name), new)
        for test in TESTS:
            for dest in (os.path.join(tree, test), os.path.join(pdir, test)):
                shutil.copyfile(os.path.join(HERE, test), dest)
        report["ok"] = True
        report["written"] = sorted(staged) + list(TESTS)
    except Exception as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps({k: v for k, v in report.items() if k != "tree_py"},
                     indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
