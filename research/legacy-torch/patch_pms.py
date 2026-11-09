#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""pickle_model_scan 0.5.0: walk every pickle the loader reads, not just the
first one.

torch.save(obj, f, _use_new_zipfile_serialization=False) -- the legacy format,
which torch.load still reads and which most Hub pytorch_model.bin files saved
before PyTorch 1.6 use -- writes five pickles back to back and then the raw
tensor storage (torch/serialization.py, _legacy_save and _legacy_load): the
magic number 0x1950A86A20F9469CFC6C, the protocol version 1001, a sys_info
dict, the object itself, and the sorted storage keys. torch.load unpickles all
five, each with a fresh unpickler. pickle_model_scan 0.4.0 walks one stream,
to the first STOP, so on such a file it reads only the 15-byte magic-number
pickle and reports the file clean without seeing the object's imports.

Plain files written with several pickle.dump calls (read back with repeated
pickle.load) have the same shape without the magic number.

Edits to pickle_model_scan.py (each exactly once, or already in place; a
second pass changes nothing; no line lost except the replaced ones):
  docstring      one paragraph before "A flag means a pattern worth human review"
  __version__    0.4.0 -> 0.5.0
  _walk_pickle   replaced: after a stream reaches STOP, walk the next one
                 (fresh memo) -- exactly five in all for a legacy torch file
                 (then raw storage follows), otherwise while the next bytes
                 open a PROTO 2-5 header. A legacy torch file that ends early
                 gets PKL000 LOW.
  pickle_walk    two more keys: "streams" and "torch_legacy"
and copies test_pickle_model_scan_streams.py into TREE. Changed files go to
OUT/patched, originals to OUT/orig, the report to OUT/patch_report.json.
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
TEST = "test_pickle_model_scan_streams.py"
NEW_VERSION = "0.5.0"

DOC_ANCHOR = "A flag means a pattern worth human review, not proof of malice."
DOC_MARK = "Since 0.5.0 it walks every pickle in the file"
DOC_NEW = (
    "Since 0.5.0 it walks every pickle in the file that the loader reads, not\n"
    "only the first. torch.save(..., _use_new_zipfile_serialization=False) -- the\n"
    "legacy format torch.load still reads -- writes five pickles back to back\n"
    "(magic number, protocol version, sys_info, the object, the storage keys) and\n"
    "then raw tensor bytes; torch.load unpickles all five. Up to 0.4.0 the walk\n"
    "stopped after the 15-byte magic-number pickle and never saw the object's\n"
    "imports. Files written with several pickle.dump calls are walked the same\n"
    "way, one stream after another while the next bytes open a protocol 2-5\n"
    "pickle.\n"
    "\n")

VER = ('__version__ = "0.4.0"', '__version__ = "%s"' % NEW_VERSION)

WALK_OLD = '''def _walk_pickle(data, source):
    walk = _Walk(data, source)
    joblib_mode = _JOBLIB_MARKER in data
    _walk_stream(io.BytesIO(data), walk, joblib_mode)
    return walk
'''

WALK_MARK = "_TORCH_LEGACY_MAGIC = "
WALK_NEW = '''# torch.save(..., _use_new_zipfile_serialization=False), the legacy format
# torch.load still reads, writes five pickles back to back and then the raw
# tensor storage (torch/serialization.py, _legacy_save / _legacy_load): the
# magic number, the protocol version 1001, a sys_info dict, the object itself
# and the sorted storage keys. torch.load unpickles all five, each with a
# fresh unpickler. Up to 0.4.0 the walk stopped after the first.
_TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
_TORCH_LEGACY_STREAMS = 5
# Python's pickler opens every protocol 2-5 pickle with PROTO <n>. Another
# pickle.dump into the same file starts the same way; pickle.load reads them
# one after another, each with its own memo.
_MAX_STREAMS = 4096


def _first_int(data):
    """The integer a pickle holds when its first real opcode pushes one,
    else None (the legacy torch magic number is the whole first pickle)."""
    try:
        for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
            if opcode.name in ("PROTO", "FRAME"):
                continue
            if opcode.name in INT_OPCODES and isinstance(arg, int):
                return arg
            return None
    except Exception:
        return None
    return None


def _opens_pickle(data, pos):
    """True when data[pos:] starts with a PROTO 2-5 header."""
    head = bytes(data[pos:pos + 2])
    return len(head) == 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _walk_pickle(data, source):
    walk = _Walk(data, source)
    walk.streams = 0
    walk.torch_legacy = _first_int(data) == _TORCH_LEGACY_MAGIC
    joblib_mode = _JOBLIB_MARKER in data
    buf = io.BytesIO(data)
    while True:
        if not _walk_stream(buf, walk, joblib_mode):
            return walk
        walk.streams += 1
        pos = buf.tell()
        if walk.torch_legacy:
            if walk.streams >= _TORCH_LEGACY_STREAMS:
                return walk  # raw storage bytes follow; torch reads them raw
            if pos >= walk.end:
                walk.findings.append(Finding(
                    "PKL000", "LOW", "Pickle stream could not be fully parsed",
                    "This is a legacy-format torch.save file (it starts with "
                    "torch's magic number), but it ends after %d of the %d "
                    "pickles torch.load reads, so it is truncated."
                    % (walk.streams, _TORCH_LEGACY_STREAMS), source))
                return walk
            continue
        if pos >= walk.end or not _opens_pickle(data, pos):
            return walk
        if walk.streams >= _MAX_STREAMS:
            walk.findings.append(Finding(
                "PKL000", "LOW", "Pickle stream could not be fully parsed",
                "The file holds more than %d pickles one after another; the "
                "rest (from byte %d) was not analysed." % (_MAX_STREAMS, pos),
                source))
            return walk
'''

PW_OLD = '''        "rules": sorted({f.rule for f in walk.findings}),
    }'''
PW_MARK = '"torch_legacy": walk.torch_legacy,'
PW_NEW = '''        "rules": sorted({f.rule for f in walk.findings}),
        "streams": walk.streams,
        "torch_legacy": walk.torch_legacy,
    }'''


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
    if WALK_MARK not in text:
        if text.count(WALK_OLD) != 1:
            raise ValueError("_walk_pickle found %d times" % text.count(WALK_OLD))
        text = text.replace(WALK_OLD, WALK_NEW)
        notes.append("_walk_pickle")
    if PW_MARK not in text:
        if text.count(PW_OLD) != 1:
            raise ValueError("pickle_walk keys found %d times" % text.count(PW_OLD))
        text = text.replace(PW_OLD, PW_NEW)
        notes.append("pickle_walk keys")
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
        # verbatim originals for the next run's doc edits (never WebFetch them)
        for name in ("README.md", "PICKLE_SCAN.md", "MODEL_FILE_SCAN.md",
                     "pyproject.toml", "test_attribution.py"):
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
        replaced = set(WALK_OLD.split("\n")) | set(PW_OLD.split("\n")) | {VER[0]}
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
