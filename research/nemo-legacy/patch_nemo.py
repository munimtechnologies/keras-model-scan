#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""nemo_container_scan 0.3.0: walk every pickle torch.load reads from a
legacy-format checkpoint inside a .nemo, not just the first one.

torch.save(obj, f, _use_new_zipfile_serialization=False) -- the legacy format
(the default before PyTorch 1.6), which torch.load still reads -- writes five
pickles back to back and then raw tensor bytes (torch/serialization.py,
_legacy_save / _legacy_load): the magic number 0x1950A86A20F9469CFC6C, the
protocol version 1001, a sys_info dict, the object and the storage keys.
nemo_container_scan 0.2.0 walks a bare-pickle tar member to the first STOP
only, so for such a model_weights.ckpt (up to MAX_MEMBER_BYTES) it sees just
the magic-number pickle, finds no import, and reports nothing at all -- not
even NEMO010, which a zip-format checkpoint of the same model gets.

Edits to nemo_container_scan.py (each exactly once, or already in place; a
second pass changes nothing; no line lost except the replaced ones):
  docstring          one paragraph before "Rules\\n-----"
  __version__        0.2.0 -> 0.3.0
  _scan_pickle_ops   replaced by _walk_one + _scan_pickle_ops(data,
                     all_streams=False, info=None): one stream by default (a
                     torch zip's data.pkl, which torch reads once); for a bare
                     member, every stream the loader reads -- exactly five for
                     a legacy torch file, else while the next bytes open a
                     PROTO 2-5 pickle (cap 4096). STACK_GLOBAL keeps the pair
                     0.2.0 reported and adds the pair whose module string was
                     fetched back from the memo (protocol 4+), when different.
  bare branch        of _pickles_in_payload: walks all streams, says
                     "legacy torch.save, N of 5 pickles" in the evidence, and
                     reports a legacy checkpoint even when it names nothing.
and copies test_nemo_container_scan_streams.py into TREE. Changed files go to
OUT/patched, originals to OUT/orig, the report to OUT/patch_report.json.
Always exits 0; the check grades row P1.

Usage: patch_nemo.py TREE OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = "nemo_container_scan.py"
TEST = "test_nemo_container_scan_streams.py"
NEW_VERSION = "0.3.0"

DOC_ANCHOR = "Rules\n-----\n"
DOC_MARK = "Since 0.3.0 a bare-pickle member is walked"
DOC_NEW = (
    "Since 0.3.0 a bare-pickle member is walked the way the loader reads it.\n"
    "torch.save(..., _use_new_zipfile_serialization=False) -- the legacy\n"
    "format, the default before PyTorch 1.6, which torch.load still reads --\n"
    "writes five pickles back to back (magic number, protocol version,\n"
    "sys_info, the object, the storage keys) and then raw tensor bytes;\n"
    "torch.load unpickles all five. Up to 0.2.0 only the first (the magic\n"
    "number) was walked, so a legacy model_weights.ckpt got no finding at all.\n"
    "A torch zip's data.pkl is still read as one pickle, as torch reads it.\n"
    "STACK_GLOBAL also resolves a module name fetched back from the memo\n"
    "(protocol 4+), in addition to the pair 0.2.0 reported.\n"
    "\n")

VER = ('__version__ = "0.2.0"', '__version__ = "%s"' % NEW_VERSION)

OPS_OLD = '''def _scan_pickle_ops(data):
    """Disassemble a pickle without executing. Returns (dangerous, all_globals).
    Parsing stops gracefully at the first malformed byte."""
    import pickletools  # lazy; stdlib only

    dangerous = []
    all_globals = []
    recent_strings = []
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            opname = opcode.name
            if opname in _STR_OPS:
                recent_strings.append(arg if isinstance(arg, str) else "")
                if len(recent_strings) > 8:
                    recent_strings.pop(0)
            elif opname == "GLOBAL":
                mod, _, nm = (arg or "").partition(" ")
                all_globals.append((mod, nm))
                if _is_dangerous(mod, nm):
                    dangerous.append((mod, nm))
            elif opname == "STACK_GLOBAL":
                nm = recent_strings[-1] if recent_strings else ""
                mod = recent_strings[-2] if len(recent_strings) >= 2 else ""
                all_globals.append((mod, nm))
                if _is_dangerous(mod, nm):
                    dangerous.append((mod, nm))
    except Exception:
        pass
    return dangerous, all_globals
'''

OPS_MARK = "_TORCH_LEGACY_MAGIC = "
OPS_NEW = '''# torch.save(..., _use_new_zipfile_serialization=False), the legacy format
# (the default before PyTorch 1.6) that torch.load still reads, writes five
# pickles back to back and then the raw tensor bytes (torch/serialization.py,
# _legacy_save / _legacy_load): this magic number, the protocol version 1001,
# a sys_info dict, the object itself and the sorted storage keys. torch.load
# unpickles all five. Up to 0.2.0 only the first was walked.
_TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
_TORCH_LEGACY_STREAMS = 5
# Several pickle.dump calls into one file: each starts with PROTO <n>.
_MAX_STREAMS = 4096

_INT_OPS = frozenset({"INT", "BININT", "BININT1", "BININT2", "LONG",
                      "LONG1", "LONG4"})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})


def _opens_pickle(data, pos):
    """True when data[pos:] starts with a PROTO 2-5 header."""
    return len(data) >= pos + 2 and data[pos] == 0x80 and 2 <= data[pos + 1] <= 5


def _add_global(pair, dangerous, all_globals):
    all_globals.append(pair)
    if _is_dangerous(pair[0], pair[1]):
        dangerous.append(pair)


def _walk_one(buf, dangerous, all_globals):
    """Walk one pickle from the file object ``buf`` up to and including its
    STOP, leaving ``buf`` just after it. Returns (complete, first_int):
    whether STOP was reached, and the integer the pickle starts with (None
    unless its first value is an integer).

    STACK_GLOBAL records the pair 0.2.0 recorded (the last two string
    literals) and, when different, the two values pushed right before it --
    which may be strings fetched back from the memo, as protocol 4+ does
    when a second class comes from an already-named module."""
    import pickletools  # lazy; stdlib only

    strings = []   # 0.2.0: string literals only, last 8
    recent = []    # values pushed, as far as they are strings, else None
    memo = {}
    first_int = None
    seen_value = False
    complete = False
    try:
        for opcode, arg, _pos in pickletools.genops(buf):
            opname = opcode.name
            if opname == "STOP":
                complete = True
                break
            if not seen_value and opname not in ("PROTO", "FRAME"):
                seen_value = True
                if opname in _INT_OPS and isinstance(arg, int):
                    first_int = arg
            if opname in _STR_OPS:
                strings.append(arg if isinstance(arg, str) else "")
                if len(strings) > 8:
                    strings.pop(0)
                recent.append(arg if isinstance(arg, str) else None)
            elif opname in _GET_OPS:
                recent.append(memo.get(arg))
            elif opname in _PUT_OPS:
                memo[arg] = recent[-1] if recent else None
            elif opname == "MEMOIZE":
                memo[len(memo)] = recent[-1] if recent else None
            elif opname == "GLOBAL":
                mod, _, nm = (arg or "").partition(" ")
                _add_global((mod, nm), dangerous, all_globals)
                recent.append(None)
            elif opname == "STACK_GLOBAL":
                old = (strings[-2] if len(strings) >= 2 else "",
                       strings[-1] if strings else "")
                _add_global(old, dangerous, all_globals)
                top = recent[-2:]
                if (len(top) == 2 and all(isinstance(x, str) and x for x in top)
                        and tuple(top) != old):
                    _add_global(tuple(top), dangerous, all_globals)
                recent.append(None)
            elif opcode.stack_after:
                recent.append(None)
            if len(recent) > 64:
                del recent[:-8]
    except Exception:
        pass
    return complete, first_int


def _scan_pickle_ops(data, all_streams=False, info=None):
    """Disassemble pickles without executing. Returns (dangerous, all_globals).

    One pickle by default. With ``all_streams`` every pickle the loader reads
    is walked, each with its own memo: exactly five for a legacy torch.save
    file (raw tensor bytes follow; torch reads them raw), otherwise while the
    next bytes open a protocol 2-5 pickle, up to _MAX_STREAMS. A dict passed
    as ``info`` receives ``streams``, ``torch_legacy`` and ``truncated``.
    Parsing stops gracefully at the first malformed byte."""
    import io

    dangerous = []
    all_globals = []
    if not isinstance(info, dict):
        info = {}
    info.update(streams=0, torch_legacy=False, truncated=False)
    buf = io.BytesIO(data)
    end = len(data)
    while True:
        complete, first_int = _walk_one(buf, dangerous, all_globals)
        if not complete:
            if info["torch_legacy"]:
                info["truncated"] = True
            return dangerous, all_globals
        info["streams"] += 1
        if info["streams"] == 1:
            info["torch_legacy"] = first_int == _TORCH_LEGACY_MAGIC
        if not all_streams:
            return dangerous, all_globals
        pos = buf.tell()
        if info["torch_legacy"]:
            if info["streams"] >= _TORCH_LEGACY_STREAMS:
                return dangerous, all_globals
            if pos >= end:
                info["truncated"] = True
                return dangerous, all_globals
            continue
        if pos >= end or not _opens_pickle(data, pos):
            return dangerous, all_globals
        if info["streams"] >= _MAX_STREAMS:
            info["truncated"] = True
            return dangerous, all_globals


def _where_bare(member_name, info):
    """Location text for a bare-pickle member, with how much was read."""
    where = "tar:%s" % member_name
    if info.get("torch_legacy"):
        where += " (legacy torch.save, %d of %d pickles%s)" % (
            info.get("streams", 0), _TORCH_LEGACY_STREAMS,
            "; truncated" if info.get("truncated") else "")
    elif info.get("streams", 0) > 1:
        where += " (%d pickles%s)" % (
            info["streams"], "; more not read" if info.get("truncated") else "")
    return where
'''

BARE_OLD = '''    if _looks_like_pickle(payload):
        dang, allg = _scan_pickle_ops(payload)
        if allg or dang:
            results.append(("tar:%s" % member_name, dang, allg))
    return results
'''
BARE_MARK = "_scan_pickle_ops(payload, True, info)"
BARE_NEW = '''    if _looks_like_pickle(payload):
        info = {}
        dang, allg = _scan_pickle_ops(payload, True, info)
        if allg or dang or info.get("torch_legacy"):
            results.append((_where_bare(member_name, info), dang, allg))
    return results
'''

EDITS = (("docstring", DOC_MARK, DOC_ANCHOR, DOC_NEW + DOC_ANCHOR),
         ("version " + NEW_VERSION, VER[1], VER[0], VER[1]),
         ("_scan_pickle_ops", OPS_MARK, OPS_OLD, OPS_NEW),
         ("bare branch", BARE_MARK, BARE_OLD, BARE_NEW))


def apply(text):
    notes = []
    for label, mark, old, new in EDITS:
        if mark in text:
            continue
        if text.count(old) != 1:
            raise ValueError("%s: anchor found %d times" % (label, text.count(old)))
        text = text.replace(old, new)
        notes.append(label)
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
        for name in ("README.md", "NEMO_CONTAINER_SCAN.md", "MODEL_FILE_SCAN.md",
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
        replaced = (set(OPS_OLD.split("\n")) | set(BARE_OLD.split("\n"))
                    | {VER[0]})
        lost = [ln for ln in o if ln not in nset and ln not in replaced]
        ok = len(notes) == 4 and not notes2 and again == new and not lost
        report["files"][TARGET] = {"changes": notes, "second_pass": notes2,
                                   "lost": lost[:20], "lines": [len(o), len(n)],
                                   "ok": ok}
        if not ok:
            raise ValueError("%s: check failed" % TARGET)
        compile(new, TARGET, "exec")
        if "MIT" in new.split('"""', 2)[1]:
            raise ValueError("docstring contains MIT")
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
