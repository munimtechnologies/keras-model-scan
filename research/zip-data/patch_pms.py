#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""pickle_model_scan 0.6.0: in a torch.save zip, raw tensor storages are not
sniffed as pickles.

torch.load opens a zip-format checkpoint and unpickles only <prefix>/data.pkl.
Each tensor's storage is a separate member <prefix>/data/<key> that it copies
as raw bytes (torch/serialization.py, _load and load_tensor); those bytes
never reach an unpickler. pickle_model_scan 0.5.0 (release v0.56.0) walks any
zip member whose first byte is 0x80 as a pickle, so a storage that happens to
start with 0x80 (BatchNorm's num_batches_tracked after 128 batches, or about
1 in 256 trained float32 storages) gets a false PKL000 LOW "could not be
fully parsed" (job zip-storage-v1, research/zip-storage/).

Edits to pickle_model_scan.py (each exactly once, or already in place; a
second pass changes nothing; no line lost except the replaced ones):
  docstring   one paragraph before "A flag means a pattern worth human review"
  __version__ 0.5.0 -> 0.6.0
  helper      _torch_storage_members(names), inserted before scan_zip
  scan_zip    computes the storage members once, and skips only the
              first-byte (0x80) sniff for them. A member with a pickle
              extension, any data.pkl, and every member of a zip without a
              <prefix>/data.pkl are walked exactly as before.
and copies test_pickle_model_scan_zip_storage.py into TREE. Changed files go
to OUT/patched, originals to OUT/orig, the report to OUT/patch_report.json.
Always exits 0; the check grades row P1.

Usage: patch_pms.py TREE OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = "pickle_model_scan.py"
TEST = "test_pickle_model_scan_zip_storage.py"
NEW_VERSION = "0.6.0"

DOC_ANCHOR = "A flag means a pattern worth human review, not proof of malice."
DOC_MARK = "Since 0.6.0, in a torch.save zip"
DOC_NEW = (
    "Since 0.6.0, in a torch.save zip that holds <prefix>/data.pkl, the raw\n"
    "tensor storages <prefix>/data/<key> are not sniffed as pickles. torch.load\n"
    "unpickles only data.pkl and copies each storage as raw bytes; up to 0.5.0\n"
    "a storage whose first byte happened to be 0x80 was walked as a pickle and\n"
    "reported as a damaged stream (PKL000) on honest files.\n"
    "\n")

VER = ('__version__ = "0.5.0"', '__version__ = "%s"' % NEW_VERSION)

HELPER_ANCHOR = "def scan_zip(data, source):\n"
HELPER_MARK = "def _torch_storage_members("
HELPER_NEW = r'''def _torch_storage_members(names):
    """The raw tensor-storage members of a torch.save zip.

    torch.load unpickles only <prefix>/data.pkl and copies each storage
    <prefix>/data/<key> as raw bytes (torch/serialization.py, _load and
    load_tensor); those bytes never reach an unpickler. Returns the names
    <prefix>/data/<key> (exactly one path part after data/) for every
    prefix that has a data.pkl."""
    prefixes = set()
    for name in names:
        if name == "data.pkl" or name.endswith("/data.pkl"):
            prefixes.add(name[:-len("data.pkl")])
    storages = set()
    for name in names:
        head, _sep, rest = name.rpartition("/")
        if not rest:
            continue
        if head == "data":
            prefix = ""
        elif head.endswith("/data"):
            prefix = head[:-len("data")]
        else:
            continue
        if prefix in prefixes:
            storages.add(name)
    return storages


'''

SZ_OLD1 = '''                        f"zipfile could not read the archive: {exc}", source)]
    for name in zf.namelist():
'''
SZ_MARK = "raw_storage = _torch_storage_members(zf.namelist())"
SZ_NEW1 = '''                        f"zipfile could not read the archive: {exc}", source)]
    raw_storage = _torch_storage_members(zf.namelist())
    for name in zf.namelist():
'''
SZ_OLD2 = r'''        elif ext in PICKLE_EXTS or base == "data.pkl" or member[:1] == b"\x80":
'''
SZ_NEW2 = r'''        elif (ext in PICKLE_EXTS or base == "data.pkl"
              or (member[:1] == b"\x80" and name not in raw_storage)):
'''


def apply(text):
    notes = []
    if DOC_MARK not in text:
        if text.count(DOC_ANCHOR) != 1:
            raise ValueError("doc anchor found %d times" % text.count(DOC_ANCHOR))
        text = text.replace(DOC_ANCHOR, DOC_NEW + DOC_ANCHOR)
        notes.append("docstring")
    if VER[1] not in text:
        if text.count(VER[0]) != 1:
            raise ValueError("version line found %d times" % text.count(VER[0]))
        text = text.replace(VER[0], VER[1])
        notes.append("version " + NEW_VERSION)
    if HELPER_MARK not in text:
        if text.count(HELPER_ANCHOR) != 1:
            raise ValueError("scan_zip def found %d times"
                             % text.count(HELPER_ANCHOR))
        text = text.replace(HELPER_ANCHOR, HELPER_NEW + HELPER_ANCHOR)
        notes.append("helper")
    if SZ_MARK not in text:
        if text.count(SZ_OLD1) != 1:
            raise ValueError("scan_zip loop found %d times" % text.count(SZ_OLD1))
        if text.count(SZ_OLD2) != 1:
            raise ValueError("scan_zip sniff found %d times"
                             % text.count(SZ_OLD2))
        text = text.replace(SZ_OLD1, SZ_NEW1).replace(SZ_OLD2, SZ_NEW2)
        notes.append("scan_zip")
    return text, notes


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
        # verbatim originals for the next run's doc and version edits
        for name in ("README.md", "PICKLE_SCAN.md", "MODEL_FILE_SCAN.md",
                     "pyproject.toml", "model_file_scan.py",
                     "test_attribution.py"):
            src = os.path.join(tree, name)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(orig, name))
        old = read(os.path.join(tree, TARGET))
        write(os.path.join(orig, TARGET), old)
        if "\r\n" in old:
            raise ValueError("%s: CRLF" % TARGET)
        new, notes = apply(old)
        again, notes2 = apply(new)
        o, n = old.split("\n"), new.split("\n")
        nset = set(n)
        replaced = set(SZ_OLD2.split("\n")) | {VER[0]}
        lost = [ln for ln in o if ln not in nset and ln not in replaced]
        ok = len(notes) == 4 and not notes2 and again == new and not lost
        report["files"][TARGET] = {"changes": notes, "second_pass": notes2,
                                   "lost": lost[:20], "lines": [len(o), len(n)],
                                   "ok": ok}
        if not ok:
            raise ValueError("%s: check failed" % TARGET)
        compile(new, TARGET, "exec")
        write(os.path.join(tree, TARGET), new)
        write(os.path.join(pdir, TARGET), new)
        for dest in (os.path.join(tree, TEST), os.path.join(pdir, TEST)):
            shutil.copyfile(os.path.join(HERE, TEST), dest)
        report["ok"] = True
        report["written"] = [TARGET, TEST]
    except Exception as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
    with open(os.path.join(out, "patch_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
