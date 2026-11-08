#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step of job pkl-joblib-v1: put pickle_model_scan 0.4.0 into TREE.

0.4.0 = the memo fix of 0.3.0 (graded 12 of 13 in pkl-memo-v1, never
released) plus the joblib-aware walk. The candidate module ships with this
job as a whole file, so it replaces TREE/pickle_model_scan.py only when the
file on main is still 0.2.1 (otherwise P1 fails and nothing is graded).

Edits (each exactly once; a second pass changes nothing):
  pickle_model_scan.py       replaced by ./pickle_model_scan.py (0.4.0)
  test_pickle_model_scan.py  test_unresolved_stack_global_is_flagged uses a
                             memo slot that holds a tuple (same edit as
                             pkl-memo-v1: since 0.3.0 a memoized string
                             resolves, so the old stream is no longer PKL007)
  model_file_scan.py         version 0.12.1
  pyproject.toml             version 0.12.1
  PICKLE_SCAN.md             two sections appended (memo; joblib)
  + test_pickle_model_scan_memo.py and test_pickle_model_scan_joblib.py

A full copy of the unpatched tree goes to ORIG_TREE first. Patched files go
to TREE and OUT/patched only if every edit passes. Always exits 0 (row P1).

Usage: patch_jl.py TREE OUT ORIG_TREE
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NEW_TESTS = ("test_pickle_model_scan_memo.py", "test_pickle_model_scan_joblib.py")
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"([^"]+)"')

MFS_VER_OLD = '__version__ = "0.12.0"'
MFS_VER_NEW = '__version__ = "0.12.1"'
PY_VER_NEW = 'version = "0.12.1"'


def edit_pms(text, removed):
    with open(os.path.join(HERE, "pickle_model_scan.py"), encoding="utf-8",
              newline="") as fh:
        new = fh.read()
    if text == new:
        return text, []
    m = VER_RE.search(text)
    if not m or m.group(1) != "0.2.1":
        raise ValueError("pickle_model_scan.py on main is %r, not 0.2.1"
                         % (m.group(1) if m else None))
    if VER_RE.search(new).group(1) != "0.4.0":
        raise ValueError("candidate is not 0.4.0")
    removed.update(text.split("\n"))
    return new, ["replaced by the 0.4.0 candidate"]


TEST_RE = re.compile(r"(?m)^    def test_unresolved_stack_global_is_flagged"
                     r"\(self\):\n(?:(?:        [^\n]*|[ \t]*)\n)*")
TEST_NEW = '''\
    def test_unresolved_stack_global_is_flagged(self):
        # STACK_GLOBAL operands fetched from memo slots that hold no string
        # (here an empty tuple) cannot be resolved: the shape behind the
        # picklescan bypass GHSA-9gvj-pp9x-gcfr. Since 0.4.0 a memoized
        # string IS resolved, as Python's pickler writes it at protocols 4
        # and 5 (see test_pickle_model_scan_memo.py).
        data = (b"\\x80\\x04" + pickle.EMPTY_TUPLE + pickle.MEMOIZE
                + pickle.BINGET + b"\\x00" + pickle.BINGET + b"\\x00"
                + pickle.STACK_GLOBAL + pickle.STOP)
        hits = [f for f in pms.scan_pickle_bytes(data, "t")
                if getattr(f, "rule", None) == "PKL007"]
        self.assertTrue(hits)
        self.assertEqual(hits[0].severity, "HIGH")
'''


def edit_test(text, removed):
    if "memo slots that hold no string" in text:
        return text, []
    hits = list(TEST_RE.finditer(text))
    if len(hits) != 1:
        raise ValueError("PKL007 test found %d times" % len(hits))
    m = hits[0]
    lines = m.group(0).split("\n")
    while lines and lines[-1].strip() == "":
        lines.pop()
    body_end = m.start() + len("\n".join(lines)) + 1
    old = text[m.start():body_end]
    if "PKL007" not in old or "BINGET" not in old:
        raise ValueError("PKL007 test does not look as expected")
    removed.update(old.split("\n"))
    return text[:m.start()] + TEST_NEW + text[body_end:], \
        ["PKL007 test uses a non-string memo slot"]


def edit_mfs(text, removed):
    if MFS_VER_NEW in text:
        return text, []
    if text.count(MFS_VER_OLD) != 1:
        raise ValueError("mfs version line found %d times"
                         % text.count(MFS_VER_OLD))
    removed.add(MFS_VER_OLD)
    return text.replace(MFS_VER_OLD, MFS_VER_NEW), ["version 0.12.1"]


def edit_pyproject(text, removed):
    if re.search(r'(?m)^version = "0\.12\.1"$', text):
        return text, []
    hits = list(re.finditer(r'(?m)^version = "0\.12\.0"$', text))
    if len(hits) != 1:
        raise ValueError("pyproject version found %d times" % len(hits))
    removed.add('version = "0.12.0"')
    m = hits[0]
    return text[:m.start()] + PY_VER_NEW + text[m.end():], ["version 0.12.1"]


DOC_MARK = "<!-- pkl-joblib -->"
DOC = """<!-- pkl-memo -->
## STACK_GLOBAL operands from the memo (0.4.0, November 2026)

At pickle protocols 4 and 5, an import is written as two strings and
`STACK_GLOBAL`. Python's pickler memoizes each string, and when the same
module name comes again (for example `numpy.ndarray`, then `numpy.dtype`) it
fetches it from the memo (`BINGET`) instead of writing it twice. Up to 0.2.1
this scanner treated any memo fetch as an unresolved operand and reported
PKL007 HIGH, so honest `paddle.save` files (`.pdparams`, `.pdopt`) and other
protocol-4/5 pickles were flagged.

Since 0.4.0 the scanner tracks the memo the way the unpickler fills it (`PUT`,
`BINPUT`, `LONG_BINPUT`, and `MEMOIZE` at the next free index). It resolves a
`STACK_GLOBAL` when the two opcodes that pushed its operands are string
literals or fetches of a memoized string literal, with only memo stores,
`FRAME` or `PROTO` in between. Everything else stays PKL007 HIGH: a memo slot
that holds no string, an index that was never stored, and operands that are
not the last two pushes. Checked in
[REALFILE_CHECK_PKL_MEMO_2026-11.md](REALFILE_CHECK_PKL_MEMO_2026-11.md)
(12 of 13 rows held; the miss led to the joblib section below).

<!-- pkl-joblib -->
## joblib.dump files are walked to the end (0.4.0, November 2026)

`joblib.dump` does not write a plain pickle. Each numpy array becomes a
`NumpyArrayWrapper` object, and right after that object's `BUILD` opcode
joblib writes the array itself, inside the stream: a padding-length byte,
padding and the raw bytes for a numeric array (joblib 1.2 and later; earlier
versions write no padding byte), or a complete, separate pickle with its own
memo for an object-dtype array. `joblib.load` reads them back the same way
(`joblib/numpy_pickle.py`, `NumpyArrayWrapper.read_array`).

Up to 0.2.1 the opcode walk stopped at the first array: at a numeric array it
hit bytes that are not opcodes (PKL000 LOW), and at an object array it walked
into the nested pickle with the outer memo (a false PKL007 HIGH) and then
ended quietly at the nested `STOP`. On honest scikit-learn files it read
about 12% of the stream, and it never saw the imports after the first array
([REALFILE_CHECK_PKL_DIAG_2026-11.md](REALFILE_CHECK_PKL_DIAG_2026-11.md)).

0.4.0 follows `joblib.load`. In streams that name `NumpyArrayWrapper` it keeps
a symbolic stack (values are described, never built) to see the wrapper's
state when its `BUILD` comes. For a numeric array it reads the padding byte
when the state has `numpy_array_alignment_bytes`, then skips
`prod(shape) * itemsize` bytes; the itemsize comes from the pickled dtype
(its `elsize` for flexible and structured types, else its type string, such
as `f8`). For an object-dtype array it walks the nested pickle with a fresh
memo and carries on after its `STOP`. If the size cannot be derived it
reports **PKL008 MEDIUM** ("joblib array data could not be sized; the rest of
the file was not analysed") instead of stopping quietly; a file that ends
inside an array gets PKL000 LOW. It also decompresses joblib's `xz` and
`lzma` files (standard library), next to zlib, gzip and bz2; lz4 stays
PKL006 LOW (unscanned).

`pickle_walk(data)` returns what the walk covered: the imports it resolved,
the byte offset of the outer `STOP`, and how many arrays it skipped or walked
as nested pickles. A walk that covers the whole file ends at its last byte.

Pre-registered check on files written by scikit-learn, pandas, numpy and
joblib, compared with the imports `joblib.load` really makes, and on
published Hub files: [research/PREREG_PKL_JOBLIB.md](research/PREREG_PKL_JOBLIB.md).
"""


def edit_doc(text, removed):
    if DOC_MARK in text:
        return text, []
    if "<!-- pkl-memo -->" in text:
        raise ValueError("PICKLE_SCAN.md already has a pkl-memo section")
    sep = "" if text.endswith("\n\n") else (
        "\n" if text.endswith("\n") else "\n\n")
    return text + sep + DOC, ["doc sections (appended)"]


EDITS = (("pickle_model_scan.py", edit_pms),
         ("test_pickle_model_scan.py", edit_test),
         ("model_file_scan.py", edit_mfs),
         ("pyproject.toml", edit_pyproject),
         ("PICKLE_SCAN.md", edit_doc))


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 0
    tree, out, orig_tree = args
    patched_dir = os.path.join(out, "patched")
    for d in (out, patched_dir):
        os.makedirs(d, exist_ok=True)
    report = {"files": {}, "ok": False}
    new_texts = {}
    try:
        if not os.path.isdir(orig_tree):
            shutil.copytree(tree, orig_tree)
        clash = [t for t in NEW_TESTS
                 if os.path.exists(os.path.join(orig_tree, t))]
        if clash:
            report["clash"] = clash
        for name, fn in EDITS:
            entry = {}
            try:
                with open(os.path.join(orig_tree, name), encoding="utf-8",
                          newline="") as fh:
                    old = fh.read()
                if "\r\n" in old:
                    raise ValueError("CRLF")
                removed = set()
                new, notes = fn(old, removed)
                again, notes2 = fn(new, set())
                new_set = set(new.split("\n"))
                lost = [ln for ln in old.split("\n") if ln not in new_set
                        and ln not in removed]
                compiled = True
                if name.endswith(".py"):
                    try:
                        compile(new, name, "exec")
                    except SyntaxError as exc:
                        compiled = False
                        entry["syntax_error"] = str(exc)
                entry.update({"changes": notes, "second_pass": notes2,
                              "lost": lost[:20], "removed_lines": len(removed),
                              "lines": [old.count("\n"), new.count("\n")],
                              "compiles": compiled,
                              "ok": bool(notes) and not notes2
                              and again == new and not lost and compiled})
                new_texts[name] = new
            except (ValueError, OSError) as exc:
                entry = {"error": "%s: %s" % (type(exc).__name__, exc),
                         "ok": False}
            report["files"][name] = entry
        report["ok"] = (all(e.get("ok") for e in report["files"].values())
                        and len(report["files"]) == len(EDITS)
                        and not report.get("clash"))
        if report["ok"]:
            for name, text in new_texts.items():
                for dest in (os.path.join(tree, name),
                             os.path.join(patched_dir, name)):
                    with open(dest, "w", encoding="utf-8", newline="") as fh:
                        fh.write(text)
            for t in NEW_TESTS:
                for dest in (os.path.join(tree, t),
                             os.path.join(patched_dir, t)):
                    shutil.copyfile(os.path.join(HERE, t), dest)
            report["written"] = sorted(list(new_texts) + list(NEW_TESTS))
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
