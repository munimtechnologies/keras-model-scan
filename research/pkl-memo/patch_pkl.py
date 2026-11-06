#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""pickle_model_scan 0.3.0: STACK_GLOBAL operands taken from the memo.

Up to 0.2.1 a STACK_GLOBAL whose module or name came from a memo fetch
(GET / BINGET / LONG_BINGET) was always PKL007 HIGH ("unresolved"). Python's
own pickler writes exactly that at protocols 4 and 5 whenever a module name
repeats (it memoizes the string and fetches it the second time), so honest
paddle.save files and other protocol-4/5 pickles were flagged HIGH.

0.3.0 tracks the memo (PUT / BINPUT / LONG_BINPUT / MEMOIZE, with MEMOIZE's
index = current memo size, as in the unpickler) and resolves a STACK_GLOBAL
when the two opcodes that pushed its operands, ignoring only memo stores,
FRAME and PROTO, are string literals or memo fetches of a memoized string.
Anything else, including operands that are not the last two pushes (an
intervening POP), stays PKL007.

Edits (each exactly once, or already in place; a second pass changes nothing):
  pickle_model_scan.py       version 0.3.0; MEMO_PUT_OPCODES after
                             MEMO_GET_OPCODES; the operand-tracking part of
                             scan_pickle_bytes (from 'recent = []' up to the
                             'except Exception' of its try) replaced;
                             optional: the PKL007 message wording
  test_pickle_model_scan.py  test_unresolved_stack_global_is_flagged now uses
                             a memo slot that holds a tuple (still PKL007);
                             the old stream (a memoized string) resolves now
  model_file_scan.py         version 0.12.1
  pyproject.toml             version 0.12.1
  PICKLE_SCAN.md             a section appended at the end

Only if every file passes are the patched files written to TREE and
OUT/patched. A full copy of the unpatched tree goes to ORIG_TREE first. The
new test module is copied too. Always exits 0: graded as row P1.

Usage: patch_pkl.py TREE OUT ORIG_TREE

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEST = "test_pickle_model_scan_memo.py"

PMS_VER_OLD = '__version__ = "0.2.1"'
PMS_VER_NEW = '__version__ = "0.3.0"'
MFS_VER_OLD = '__version__ = "0.12.0"'
MFS_VER_NEW = '__version__ = "0.12.1"'
PY_VER_OLD = 'version = "0.12.0"'
PY_VER_NEW = 'version = "0.12.1"'

GET_LINE = 'MEMO_GET_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})'
PUT_LINE = 'MEMO_PUT_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})'

NEW_SPAN = '''\
    # Each STACK_GLOBAL takes its module and name from the top two stack
    # items. Since 0.3.0 they are resolved when the two opcodes that pushed
    # them are string literals or memo fetches (GET/BINGET/LONG_BINGET) of a
    # memoized string literal, with nothing in between that changes the stack
    # (memo stores, FRAME and PROTO do not). Pickle protocols 4 and 5 write
    # exactly this when a module name repeats (numpy.ndarray, then
    # numpy.dtype). Any other operand stays unresolved (PKL007), as before.
    memo = {}            # memo index -> ('str', value) or ('other', None)
    pushes = []          # the last two stack pushes, same shape
    globals_found = []   # (module, name, pos, resolvable)
    exec_ops = 0

    try:
        for opcode, arg, pos in pickletools.genops(data):
            name = opcode.name
            if name in EXEC_OPCODES:
                exec_ops += 1
            if name in ("FRAME", "PROTO"):
                continue
            if name in MEMO_PUT_OPCODES or name == "MEMOIZE":
                key = len(memo) if name == "MEMOIZE" else arg
                memo[key] = pushes[-1] if pushes else ("other", None)
                continue
            if name in ("GLOBAL", "INST"):
                mod, _, fn = (arg or "").partition(" ")
                globals_found.append((mod, fn, pos, True))
            elif name == "STACK_GLOBAL":
                last_two = pushes[-2:]
                if (len(last_two) == 2 and last_two[0][0] == "str"
                        and last_two[1][0] == "str"):
                    globals_found.append((last_two[0][1], last_two[1][1], pos, True))
                else:
                    globals_found.append((None, None, pos, False))
            if name in STRING_OPCODES:
                pushes.append(("str", arg))
            elif name in MEMO_GET_OPCODES:
                pushes.append(memo.get(arg, ("other", None)))
            else:
                pushes.append(("other", None))
            del pushes[:-2]
'''
SPAN_START = re.compile(r"(?m)^    recent = \[\][^\n]*\n")
SPAN_END = re.compile(r"(?m)^    except Exception as exc:[^\n]*\n")
SPAN_MUST = ("STACK_GLOBAL", "recent[-2:]", "globals_found = []",
             "exec_ops = 0", "pickletools.genops(data)", "MEMO_GET_OPCODES")

MSG_RE = re.compile(r'(?m)^([ \t]+)"two preceding string literals \(the '
                    r'operands come from the memo or are "[ \t]*\n')
MSG_NEW = ('{i}"two string literals pushed just before it, directly or as "\n'
           '{i}"memoized copies (the operands come from other objects or are "\n')


def edit_pms(text, removed):
    notes = []
    if PMS_VER_NEW not in text:
        if text.count(PMS_VER_OLD) != 1:
            raise ValueError("pms version line found %d times"
                             % text.count(PMS_VER_OLD))
        text = text.replace(PMS_VER_OLD, PMS_VER_NEW)
        removed.add(PMS_VER_OLD)
        notes.append("version 0.3.0")
    if PUT_LINE not in text:
        if text.count(GET_LINE + "\n") != 1:
            raise ValueError("MEMO_GET_OPCODES line found %d times"
                             % text.count(GET_LINE + "\n"))
        text = text.replace(GET_LINE + "\n", GET_LINE + "\n" + PUT_LINE + "\n")
        notes.append("MEMO_PUT_OPCODES")
    if "pushes = []" not in text:
        starts = list(SPAN_START.finditer(text))
        if len(starts) != 1:
            raise ValueError("'recent = []' found %d times" % len(starts))
        s = starts[0].start()
        end = SPAN_END.search(text, s)
        if not end:
            raise ValueError("no 'except Exception' after 'recent = []'")
        old_span = text[s:end.start()]
        miss = [m for m in SPAN_MUST if m not in old_span]
        if miss:
            raise ValueError("old span lacks %r" % miss)
        if old_span.count("\n") > 40:
            raise ValueError("old span unexpectedly long (%d lines)"
                             % old_span.count("\n"))
        removed.update(old_span.split("\n"))
        text = text[:s] + NEW_SPAN + text[end.start():]
        notes.append("operand tracking replaced")
    if "memoized copies (the operands come from other objects" not in text:
        hits = list(MSG_RE.finditer(text))
        if len(hits) == 1:
            m = hits[0]
            removed.add(m.group(0).rstrip("\n"))
            text = text[:m.start()] + MSG_NEW.format(i=m.group(1)) \
                + text[m.end():]
            notes.append("PKL007 wording (optional)")
        # optional: if the wording differs, the message is left as it is
    return text, notes


TEST_RE = re.compile(r"(?m)^    def test_unresolved_stack_global_is_flagged"
                     r"\(self\):\n(?:(?:        [^\n]*|[ \t]*)\n)*")
TEST_NEW = '''\
    def test_unresolved_stack_global_is_flagged(self):
        # STACK_GLOBAL operands fetched from memo slots that hold no string
        # (here an empty tuple) cannot be resolved: the shape behind the
        # picklescan bypass GHSA-9gvj-pp9x-gcfr. Since 0.3.0 a memoized
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
    removed.add(PY_VER_OLD)
    m = hits[0]
    return text[:m.start()] + PY_VER_NEW + text[m.end():], ["version 0.12.1"]


DOC_MARK = "<!-- pkl-memo -->"
DOC = """<!-- pkl-memo -->
## STACK_GLOBAL operands from the memo (0.3.0, November 2026)

At pickle protocols 4 and 5, an import is written as two strings and
`STACK_GLOBAL`. Python's pickler memoizes each string, and when the same
module name comes again (for example `numpy.ndarray`, then `numpy.dtype`) it
fetches it from the memo (`BINGET`) instead of writing it twice. Up to 0.2.1
this scanner treated any memo fetch as an unresolved operand and reported
PKL007 HIGH, so honest `paddle.save` files (`.pdparams`, `.pdopt`) and other
protocol-4/5 pickles were flagged. Our walk-names check found this on 6 of 7
published `.pdparams` files.

0.3.0 tracks the memo the way the unpickler fills it (`PUT`, `BINPUT`,
`LONG_BINPUT`, and `MEMOIZE` at the next free index). It resolves a
`STACK_GLOBAL` when the two opcodes that pushed its operands are string
literals or fetches of a memoized string literal, with only memo stores,
`FRAME` or `PROTO` in between. The resolved import is then classified like
any other: a memoized `os` / `system` is PKL001 or PKL002, not just PKL007.
Everything else stays PKL007 HIGH as before: a memo slot that holds no
string, an index that was never stored, and operands that are not the last
two pushes (for example strings followed by `POP`). That last case is
stricter than 0.2.1, which looked at the last two strings anywhere before.
picklescan's `_list_globals` already resolves memo fetches in much the same
way; this brings our scanner in line with it.

Pre-registered check on files written by paddle, torch, numpy and Python's
pickler, and on published Hub files:
[research/PREREG_PKL_MEMO.md](research/PREREG_PKL_MEMO.md).
"""


def edit_doc(text, removed):
    if DOC_MARK in text:
        return text, []
    sep = "" if text.endswith("\n\n") else (
        "\n" if text.endswith("\n") else "\n\n")
    return text + sep + DOC, ["doc section (appended)"]


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
                if name == "pickle_model_scan.py":
                    entry["wording_changed"] = \
                        "PKL007 wording (optional)" in notes
                new_texts[name] = new
            except (ValueError, OSError) as exc:
                entry = {"error": "%s: %s" % (type(exc).__name__, exc),
                         "ok": False}
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
