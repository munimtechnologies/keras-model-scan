#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""model-file-scan 0.13.0: directory walks keep pickle-bearing names that
the extension table misses.

- pytorch/examples (imagenet/main.py) saves torch.save checkpoints as
  checkpoint.pth.tar (and copies the best to model_best.pth.tar).
- paddle.save writes a Layer state_dict as .pdparams and an Optimizer
  state_dict as .pdopt, both plain pickle (protocol 4 by default).
- joblib.dump picks its compressor from the file name's ending (its dump
  docstring: '.z', '.gz', '.bz2', '.xz' or '.lzma'; '.lz4' with lz4
  installed), so model.joblib.gz or model.pkl.xz is a compressed pickle.
Their last extension is not in _MODEL_EXTS, so model-file-scan 0.12.1's
directory walk skips them (a folder of only such files prints "no model
files found" and exits 0). A file given by name already goes to the pickle
scanner, which opens zlib, gzip, bz2, xz and lzma and reports lz4 as
PKL006 LOW (not scanned).

Edits (each exactly once, or already in place; a second pass changes nothing;
no line lost except the replaced ones):
  model_file_scan.py   helper _is_pickle_name(name) before def route();
                       _walk_keeps also keeps _is_pickle_name(low);
                       __version__ 0.12.1 -> 0.13.0
  pyproject.toml       version 0.12.1 -> 0.13.0
  test_attribution.py  floor (model_file_scan, (0, 12, x)) -> (0, 13, 0) when
                       present (optional)
  MODEL_FILE_SCAN.md   heading, "everything else" row, Action pin (optional)
and copies test_model_file_scan_walk_names.py into TREE. Changed files and
the new test go to OUT/patched, originals to OUT/orig, the report to
OUT/patch_report.json. Always exits 0; the check grades row P1.

Usage: patch_walk.py TREE OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEST = "test_model_file_scan_walk_names.py"
NEW_VERSION = "0.13.0"
NEW_TAG = "v0.55.0"

ANCHOR = re.compile(r"(?m)^def route\(")
MARK = "_PICKLE_NAME = "
HELPER = '''# Pickle-bearing files whose last extension is not in _MODEL_EXTS:
# pytorch/examples saves torch.save checkpoints as checkpoint.pth.tar,
# paddle.save writes .pdparams / .pdopt (pickle), and joblib.dump compresses
# a file named *.pkl.gz, *.joblib.xz, ... with the codec its ending names.
# route() already sends them to the pickle scanner; directory walks keep them
# through this helper (REALFILE_CHECK_WALK_NAMES_2026-11.md).
import re as _name_re  # noqa: E402

_PICKLE_NAME = _name_re.compile(
    r"\\.(?:pt|pth|ckpt)\\.tar$|\\.(?:pdparams|pdopt)$"
    r"|\\.(?:pkl|pickle|joblib)\\.(?:z|gz|bz2|xz|lzma|lz4)$",
    _name_re.IGNORECASE)


def _is_pickle_name(name):
    """True for torch / paddle / compressed-joblib names the extension
    table misses."""
    return bool(_PICKLE_NAME.search(str(name)))


'''
WALK_OLD = ('    if ext in _MODEL_EXTS or low == "config.json" or '
            '_is_shard_index(low):')
WALK_NEW = ('    if (ext in _MODEL_EXTS or low == "config.json" or '
            '_is_shard_index(low)\n'
            '            or _is_pickle_name(low)):')
VER = ('__version__ = "0.12.1"', '__version__ = "%s"' % NEW_VERSION)
PYPROJECT = ('version = "0.12.1"', 'version = "%s"' % NEW_VERSION)
FLOOR_RE = re.compile(r"\(model_file_scan, \(0, 1[0-2], \d+\)\)")
FLOOR_NEW = "(model_file_scan, (0, 13, 0))"

DOC = "MODEL_FILE_SCAN.md"
DOC_ROW_OLD = ("`.ckpt`, and a `.model` that is neither of the above) | "
               "`pickle_model_scan` |")
DOC_ROW_NEW = ("`.ckpt`, and a `.model` that is neither of the above; directory "
               "walks also pick up `*.pth.tar`, `*.pt.tar`, `*.ckpt.tar`, "
               "`.pdparams`, `.pdopt`, and `*.pkl` / `*.pickle` / `*.joblib` "
               "ending in `.z`, `.gz`, `.bz2`, `.xz`, `.lzma` or `.lz4`) | "
               "`pickle_model_scan` |")
DOC_HEAD_RE = re.compile(r"(?m)^## Formats routed in [0-9.]+ \(release v[0-9.]+\)")
DOC_HEAD_NEW = "## Formats routed in %s (release %s)" % (NEW_VERSION, NEW_TAG)
DOC_PIN_RE = re.compile(r"uses: munimtechnologies/keras-model-scan@v[0-9]+\.[0-9]+\.[0-9]+")
DOC_PIN_NEW = "uses: munimtechnologies/keras-model-scan@" + NEW_TAG


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
            raise ValueError("walk line found %d times" % text.count(WALK_OLD))
        text = text.replace(WALK_OLD, WALK_NEW)
        notes.append("walk keeps pickle names")
    if VER[1] not in text:
        if text.count(VER[0]) != 1:
            raise ValueError("version line found %d times" % text.count(VER[0]))
        text = text.replace(VER[0], VER[1])
        notes.append("version " + NEW_VERSION)
    return text, notes


def apply_pyproject(text):
    if PYPROJECT[1] in text:
        return text, []
    if text.count(PYPROJECT[0]) != 1:
        raise ValueError("pyproject version found %d times"
                         % text.count(PYPROJECT[0]))
    return text.replace(PYPROJECT[0], PYPROJECT[1]), [PYPROJECT[1]]


def apply_floor(text):
    hits = FLOOR_RE.findall(text)
    if len(hits) > 1:
        raise ValueError("floor found %d times" % len(hits))
    if not hits:
        return text, []
    return FLOOR_RE.sub(FLOOR_NEW, text), [FLOOR_NEW]


def apply_doc(text):
    done, skipped = [], []
    if DOC_ROW_NEW not in text:
        if text.count(DOC_ROW_OLD) == 1:
            text = text.replace(DOC_ROW_OLD, DOC_ROW_NEW)
            done.append("row")
        else:
            skipped.append(["row", text.count(DOC_ROW_OLD)])
    n = len(DOC_HEAD_RE.findall(text))
    if DOC_HEAD_NEW not in text:
        if n == 1:
            text = DOC_HEAD_RE.sub(DOC_HEAD_NEW, text)
            done.append("heading")
        else:
            skipped.append(["heading", n])
    pins = DOC_PIN_RE.findall(text)
    if pins and any(p != DOC_PIN_NEW for p in pins):
        text = DOC_PIN_RE.sub(DOC_PIN_NEW, text)
        done.append("pin x%d" % len(pins))
    return text, done, skipped


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
    staged = {}
    try:
        # verbatim originals for the next run's doc edits (never WebFetch them)
        for name in ("README.md", DOC, "test_attribution.py", "action.yml"):
            src = os.path.join(tree, name)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(orig, name))
        name = "model_file_scan.py"
        old = read(os.path.join(tree, name))
        write(os.path.join(orig, name), old)
        if "\r\n" in old:
            raise ValueError("%s: CRLF" % name)
        new, notes = apply_mfs(old)
        again, notes2 = apply_mfs(new)
        o, n = old.split("\n"), new.split("\n")
        nset = set(n)
        lost = [ln for ln in o if ln not in nset and ln not in (WALK_OLD, VER[0])]
        ok = (len(notes) == 3 and not notes2 and again == new and not lost)
        report["files"][name] = {"changes": notes, "second_pass": notes2,
                                 "lost": lost[:20], "lines": [len(o), len(n)],
                                 "ok": ok}
        if not ok:
            raise ValueError("%s: check failed" % name)
        staged[name] = new

        old = read(os.path.join(tree, "pyproject.toml"))
        write(os.path.join(orig, "pyproject.toml"), old)
        new, notes = apply_pyproject(old)
        again, notes2 = apply_pyproject(new)
        ok = len(notes) == 1 and not notes2 and again == new
        report["files"]["pyproject.toml"] = {"changes": notes, "ok": ok}
        if not ok:
            raise ValueError("pyproject.toml: check failed")
        staged["pyproject.toml"] = new

        old = read(os.path.join(tree, "test_attribution.py"))
        new, notes = apply_floor(old)
        report["files"]["test_attribution.py"] = {"changes": notes,
                                                  "optional": True}
        if new != old:
            staged["test_attribution.py"] = new

        try:
            old = read(os.path.join(tree, DOC))
            new, done, skipped = apply_doc(old)
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
    with open(os.path.join(out, "patch_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
