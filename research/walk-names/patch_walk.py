#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""model-file-scan 0.13.0: directory walks keep pickle-bearing names that
the extension table misses.

pytorch/examples (imagenet/main.py) saves torch.save checkpoints as
checkpoint.pth.tar and model_best.pth.tar; paddle.save writes a Layer
state_dict as .pdparams and an Optimizer state_dict as .pdopt, both plain
pickle (protocol 4 by default). Their last extension (.tar, .pdparams,
.pdopt) is not in _MODEL_EXTS, so model-file-scan 0.12.0's directory walk
skips them; a file given by name already goes to the pickle scanner.

Edits (each exactly once, or already in place; a second pass changes nothing;
no line lost except the replaced ones):
  model_file_scan.py   helper _is_pickle_name(name) before def route();
                       _walk_keeps also keeps _is_pickle_name(low);
                       __version__ 0.12.0 -> 0.13.0
  pyproject.toml       version 0.12.0 -> 0.13.0
  test_attribution.py  floor (model_file_scan, (0, 12, 0)) -> (0, 13, 0)
  MODEL_FILE_SCAN.md   heading, "everything else" row, Action pin (optional)
and copies test_model_file_scan_walk_names.py into TREE. Changed files and
the new test go to OUT/patched, originals to ORIG_DIR, the report to
OUT/patch_report.json. Always exits 0; the check grades row P1.

Usage: patch_walk.py TREE OUT ORIG_DIR

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEST = "test_model_file_scan_walk_names.py"

ANCHOR = re.compile(r"(?m)^def route\(")
MARK = "_PICKLE_NAME = "
HELPER = '''# Pickle-bearing files whose last extension is not in _MODEL_EXTS:
# pytorch/examples saves torch.save checkpoints as checkpoint.pth.tar, and
# paddle.save writes .pdparams / .pdopt (pickle). route() already sends them
# to the pickle scanner; directory walks keep them through this helper
# (REALFILE_CHECK_WALK_NAMES_2026-11.md).
import re as _name_re  # noqa: E402

_PICKLE_NAME = _name_re.compile(
    r"\\.(?:pt|pth|ckpt)\\.tar$|\\.(?:pdparams|pdopt)$", _name_re.IGNORECASE)


def _is_pickle_name(name):
    """True for torch / paddle file names the extension table misses."""
    return bool(_PICKLE_NAME.search(str(name)))


'''
WALK_OLD = ('    if ext in _MODEL_EXTS or low == "config.json" or '
            '_is_shard_index(low):')
WALK_NEW = ('    if (ext in _MODEL_EXTS or low == "config.json" or '
            '_is_shard_index(low)\n'
            '            or _is_pickle_name(low)):')
VER = ('__version__ = "0.12.0"', '__version__ = "0.13.0"')

SIMPLE = {
    "pyproject.toml": [('version = "0.12.0"', 'version = "0.13.0"')],
    "test_attribution.py": [
        ("(model_file_scan, (0, 12, 0))", "(model_file_scan, (0, 13, 0))")],
}
DOC = "MODEL_FILE_SCAN.md"
DOC_EDITS = [
    ("## Formats routed in 0.12.0 (release v0.52.0)",
     "## Formats routed in 0.13.0 (release v0.53.0)"),
    ("`.ckpt`, and a `.model` that is neither of the above) | "
     "`pickle_model_scan` | |",
     "`.ckpt`, and a `.model` that is neither of the above; directory walks "
     "also pick up `*.pth.tar`, `*.pt.tar`, `*.ckpt.tar`, `.pdparams` and "
     "`.pdopt`) | `pickle_model_scan` | "
     "[walk names](REALFILE_CHECK_WALK_NAMES_2026-11.md) |"),
    ("munimtechnologies/keras-model-scan@v0.52.0",
     "munimtechnologies/keras-model-scan@v0.53.0"),
]


def apply_mfs(text):
    notes = []
    if MARK not in text:
        hits = list(ANCHOR.finditer(text))
        if len(hits) != 1:
            raise ValueError("def route anchor found %d times" % len(hits))
        text = text[:hits[0].start()] + HELPER + text[hits[0].start():]
        notes.append("helper")
    if WALK_NEW not in text:
        if text.count(WALK_OLD) != 1:
            raise ValueError("walk line found %d times"
                             % text.count(WALK_OLD))
        text = text.replace(WALK_OLD, WALK_NEW)
        notes.append("walk keeps pickle names")
    if VER[1] not in text:
        if text.count(VER[0]) != 1:
            raise ValueError("version line found %d times"
                             % text.count(VER[0]))
        text = text.replace(VER[0], VER[1])
        notes.append("version 0.13.0")
    return text, notes


def apply_simple(text, pairs):
    notes = []
    for old, new in pairs:
        if new in text:
            continue
        if text.count(old) != 1:
            raise ValueError("%r found %d times" % (old, text.count(old)))
        text = text.replace(old, new)
        notes.append(new)
    return text, notes


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 0
    tree, out, orig = args
    pdir = os.path.join(out, "patched")
    for d in (out, orig, pdir):
        os.makedirs(d, exist_ok=True)
    report = {"files": {}, "ok": False}
    staged = {}
    try:
        name = "model_file_scan.py"
        old = read(os.path.join(tree, name))
        write(os.path.join(orig, name), old)
        if "\r\n" in old:
            raise ValueError("%s: CRLF" % name)
        new, notes = apply_mfs(old)
        again, notes2 = apply_mfs(new)
        o, n = old.split("\n"), new.split("\n")
        nset = set(n)
        lost = [ln for ln in o if ln not in nset
                and ln not in (WALK_OLD, VER[0])]
        ok = (len(notes) == 3 and not notes2 and again == new and not lost)
        report["files"][name] = {"changes": notes, "second_pass": notes2,
                                 "lost": lost[:20],
                                 "lines": [len(o), len(n)], "ok": ok}
        if not ok:
            raise ValueError("%s: check failed" % name)
        staged[name] = new
        for name, pairs in SIMPLE.items():
            old = read(os.path.join(tree, name))
            write(os.path.join(orig, name), old)
            new, notes = apply_simple(old, pairs)
            again, notes2 = apply_simple(new, pairs)
            ok = (len(notes) == len(pairs) and not notes2 and again == new
                  and len(old.split("\n")) == len(new.split("\n")))
            report["files"][name] = {"changes": notes, "second_pass": notes2,
                                     "ok": ok}
            if not ok:
                raise ValueError("%s: check failed" % name)
            staged[name] = new
        try:
            old = read(os.path.join(tree, DOC))
            write(os.path.join(orig, DOC), old)
            new, done, skipped = old, [], []
            for a, b in DOC_EDITS:
                if b in new:
                    continue
                if new.count(a) == 1:
                    new = new.replace(a, b)
                    done.append(b[:70])
                else:
                    skipped.append([a[:70], new.count(a)])
            report["files"][DOC] = {"changes": done, "skipped": skipped,
                                    "optional": True}
            if new != old:
                staged[DOC] = new
        except OSError as exc:
            report["files"][DOC] = {"error": str(exc), "optional": True}
        for name, text in staged.items():
            write(os.path.join(tree, name), text)
            write(os.path.join(pdir, name), text)
        for dest in (os.path.join(tree, TEST), os.path.join(pdir, TEST)):
            shutil.copyfile(os.path.join(HERE, TEST), dest)
        report["ok"] = True
        report["written"] = sorted(staged) + [TEST]
    except Exception as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
