#!/usr/bin/env python3
"""pickle_model_scan.py - static, no-execution scanner for pickle-based model files.

Pickle-based model files (.joblib, .pkl, PyTorch .pt/.bin/.pth, object-dtype .npy,
and the pickles nested inside .pt/.npz archives) are the most common real-world
remote-code-execution vector in machine-learning supply chains: loading one runs
whatever the author put in a __reduce__ hook. This tool reads the pickle *opcode
stream* with the standard library's pickletools.genops, which parses the bytes but
NEVER unpickles, imports, or executes anything, and flags the opcodes behind those
attacks (GLOBAL / STACK_GLOBAL imports of dangerous modules, and REDUCE / BUILD /
NEWOBJ execution opcodes).

It also recognises the safe formats - safetensors and GGUF have no code-execution
surface - and reports them as such, and it explicitly flags STACK_GLOBAL operands
that cannot be resolved from preceding string literals, a documented way to bypass
naive scanners (GHSA-9gvj-pp9x-gcfr / CVE-2025-71325) rather than silently passing.

Since 0.4.0 it reads joblib.dump files the way joblib.load does. joblib writes
each numpy array as a NumpyArrayWrapper object followed by the array itself,
inside the pickle stream: raw bytes for a numeric array, a separate nested
pickle for an object-dtype array. The walk now skips the raw bytes by the size
the wrapper's pickled shape and dtype give, walks each nested pickle with its
own memo, and carries on to the end of the file. Up to 0.3.0 it stopped at the
first array and never saw the rest of the file.

Since 0.5.0 it walks every pickle in the file that the loader reads, not
only the first. torch.save(..., _use_new_zipfile_serialization=False) -- the
legacy format torch.load still reads -- writes five pickles back to back
(magic number, protocol version, sys_info, the object, the storage keys) and
then raw tensor bytes; torch.load unpickles all five. Up to 0.4.0 the walk
stopped after the 15-byte magic-number pickle and never saw the object's
imports. Files written with several pickle.dump calls are walked the same
way, one stream after another while the next bytes open a protocol 2-5
pickle.

A flag means a pattern worth human review, not proof of malice. A clean result is
not a guarantee of safety: this is a static heuristic, not a sandbox.

Made with AI by MV2 of Munim, Inc. Stdlib only (Python 3.8+). Apache-2.0 licensed.
Never imports or executes the scanned model; never unpickles. Use it as a pre-load
or CI gate before anyone calls torch.load / joblib.load / numpy.load / pickle.load
on an untrusted file.
"""
from __future__ import annotations

import argparse
import ast
import bz2
import gzip
import io
import json
import lzma
import os
import pickletools
import re
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass

__version__ = "0.5.0"

# Modules whose presence in a pickle is a direct code-execution concern.
DANGEROUS_MODULES = frozenset({
    "idlelib",  # CVE-2025-71340/71342/71357/71358 (picklescan idlelib RCE gadget cluster, CWE-502)
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "platform", "ctypes", "multiprocessing", "runpy", "importlib", "code",
    "codeop", "webbrowser", "pdb", "bdb", "commands", "popen2", "timeit",
    "asyncio", "signal", "resource", "fcntl", "pickle", "dill", "cloudpickle",
})
# Names in builtins that execute code or reach arbitrary attributes.
DANGEROUS_BUILTINS = frozenset({
    "eval", "exec", "compile", "open", "__import__", "input", "breakpoint",
    "getattr", "setattr", "globals", "vars", "memoryview", "exit", "quit",
})
# Top-level packages that are normal, benign model reconstructors.
BENIGN_TOP = frozenset({
    "numpy", "torch", "collections", "scipy", "sklearn", "pandas", "joblib",
    "_codecs", "copyreg", "copy_reg", "array", "decimal", "datetime",
    "torchvision", "transformers", "keras", "tensorflow", "xgboost", "lightgbm",
})
# Fully-qualified gadget submodules that execute code even though their top-level
# package is an ordinary model reconstructor. numpy.f2py.crackfortran exposes many
# helpers (e.g. _eval_length, getlincoef) that call eval() on their argument;
# NumPy's own security documentation states the whole numpy.f2py must be treated
# as unsafe when reached from an untrusted pickle, so a benign-looking 'numpy'
# import is NOT enough to clear a global whose module is under numpy.f2py.
# Refs: CVE-2025-71339 / GHSA-6556-fwc2-fg2p; GHSA-r8g5-cgf2-4m4m.
GADGET_MODULE_PREFIXES = (
    "numpy.f2py",
)

STRING_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})
MEMO_GET_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
MEMO_PUT_OPCODES = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
EXEC_OPCODES = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"})
INT_OPCODES = frozenset({"INT", "BININT", "BININT1", "BININT2", "LONG",
                         "LONG1", "LONG4"})

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

PICKLE_EXTS = frozenset({
    ".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin", ".model", ".ckpt",
    ".dat", ".pck", ".pt2",
})

# joblib's array placeholder class. joblib.load replaces it, right after its
# BUILD, with the array data that follows in the file (joblib/numpy_pickle.py,
# NumpyUnpickler.load_build and NumpyArrayWrapper.read_array). The second
# module name is the copy of joblib that scikit-learn bundled before 0.23.
JOBLIB_WRAPPER_MODULES = frozenset({
    "joblib.numpy_pickle", "sklearn.externals.joblib.numpy_pickle",
})
JOBLIB_WRAPPER_NAME = "NumpyArrayWrapper"
_JOBLIB_MARKER = JOBLIB_WRAPPER_NAME.encode("ascii")
# Containers bigger than this keep no items in the symbolic stack (a wrapper's
# state dict has 6 keys, a shape tuple at most 64 entries).
_SYM_KEEP = 256


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    location: str
    cve: str = None

    def as_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "location": self.location,
            "cve": self.cve,
        }


def _classify(module, name):
    """Return one of 'dangerous', 'rce_gadget', 'gadget', 'benign', 'unknown'.

    'rce_gadget' is a callable under a known code-execution submodule (numpy.f2py)
    whose top-level package is otherwise benign; it must not be cleared by the
    benign-package allowlist.
    """
    module = module or ""
    name = name or ""
    top = module.split(".", 1)[0]
    if any(module == p or module.startswith(p + ".") for p in GADGET_MODULE_PREFIXES):
        return "rce_gadget"
    if top in ("builtins", "__builtin__", "__builtins__"):
        return "dangerous" if name in DANGEROUS_BUILTINS else "benign"
    if top in DANGEROUS_MODULES:
        return "dangerous"
    if module == "functools" and name in ("partial", "reduce"):
        return "gadget"
    if module == "operator" and name in ("attrgetter", "methodcaller"):
        return "gadget"
    if top in BENIGN_TOP:
        return "benign"
    return "unknown"


# ---------------------------------------------------------------------------
# Symbolic stack (joblib files only). Values are described, never built.
# ---------------------------------------------------------------------------
class _Broken(Exception):
    """The symbolic stack no longer matches the stream (e.g. an underflow)."""


class _V(object):
    """A symbolic stack value: kind is one of str, int, bool, none, tuple,
    list, dict, global, obj, other. ``val`` holds the literal, the items, the
    (module, name) pair, or the (callable, args) pair; ``state`` is what a
    BUILD set on it."""
    __slots__ = ("kind", "val", "state")

    def __init__(self, kind, val=None):
        self.kind = kind
        self.val = val
        self.state = None


_MARK = object()


def _sym_pop(stack):
    if not stack or stack[-1] is _MARK:
        raise _Broken("stack underflow")
    return stack.pop()


def _sym_top(stack):
    if not stack or stack[-1] is _MARK:
        raise _Broken("stack underflow")
    return stack[-1]


def _sym_pop_mark(stack):
    for i in range(len(stack) - 1, -1, -1):
        if stack[i] is _MARK:
            items = stack[i + 1:]
            del stack[i:]
            return items
    raise _Broken("no MARK")


def _sym_tuple(items):
    return _V("tuple", list(items) if len(items) <= _SYM_KEEP else None)


def _sym_setitem(d, k, v):
    if d.kind != "dict" or d.val is None or k.kind != "str":
        return
    if len(d.val) >= _SYM_KEEP and k.val not in d.val:
        d.val = None  # too big to be a wrapper state; stop keeping items
        return
    d.val[k.val] = v


def _sym_step(opcode, arg, stack, vmemo):
    """Apply one opcode's stack effect to the symbolic stack, the way the
    unpickler would but without building anything. Returns the value a BUILD
    just updated, else None. Raises _Broken when the stream does not fit."""
    name = opcode.name
    push = stack.append
    if name in STRING_OPCODES:
        push(_V("str", arg if isinstance(arg, str) else str(arg)))
    elif name in INT_OPCODES:
        push(_V("bool" if isinstance(arg, bool) else "int", arg))
    elif name in ("NEWTRUE", "NEWFALSE"):
        push(_V("bool", name == "NEWTRUE"))
    elif name == "NONE":
        push(_V("none"))
    elif name == "EMPTY_TUPLE":
        push(_V("tuple", []))
    elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
        n = int(name[-1])
        items = [_sym_pop(stack) for _ in range(n)]
        items.reverse()
        push(_sym_tuple(items))
    elif name == "TUPLE":
        push(_sym_tuple(_sym_pop_mark(stack)))
    elif name == "EMPTY_LIST":
        push(_V("list"))
    elif name == "LIST":
        _sym_pop_mark(stack)
        push(_V("list"))
    elif name == "APPEND":
        _sym_pop(stack)
        _sym_top(stack)
    elif name == "APPENDS":
        _sym_pop_mark(stack)
        _sym_top(stack)
    elif name == "EMPTY_DICT":
        push(_V("dict", {}))
    elif name == "DICT":
        items = _sym_pop_mark(stack)
        d = _V("dict", {})
        for i in range(0, len(items) - 1, 2):
            _sym_setitem(d, items[i], items[i + 1])
        push(d)
    elif name == "SETITEM":
        v = _sym_pop(stack)
        k = _sym_pop(stack)
        _sym_setitem(_sym_top(stack), k, v)
    elif name == "SETITEMS":
        items = _sym_pop_mark(stack)
        d = _sym_top(stack)
        for i in range(0, len(items) - 1, 2):
            _sym_setitem(d, items[i], items[i + 1])
    elif name == "MARK":
        push(_MARK)
    elif name == "POP":
        if not stack:
            raise _Broken("stack underflow")
        stack.pop()  # an empty frame pops its MARK, as the unpickler does
    elif name == "POP_MARK":
        _sym_pop_mark(stack)
    elif name == "DUP":
        push(_sym_top(stack))
    elif name in MEMO_PUT_OPCODES:
        vmemo[arg] = _sym_top(stack)
    elif name == "MEMOIZE":
        vmemo[len(vmemo)] = _sym_top(stack)
    elif name in MEMO_GET_OPCODES:
        if arg not in vmemo:
            raise _Broken("memo index %r was never stored" % (arg,))
        push(vmemo[arg])
    elif name == "GLOBAL":
        mod, _, fn = (arg or "").partition(" ")
        push(_V("global", (mod, fn)))
    elif name == "STACK_GLOBAL":
        fn = _sym_pop(stack)
        mod = _sym_pop(stack)
        if mod.kind == "str" and fn.kind == "str":
            push(_V("global", (mod.val, fn.val)))
        else:
            push(_V("global", (None, None)))
    elif name in ("REDUCE", "NEWOBJ"):
        args = _sym_pop(stack)
        fn = _sym_pop(stack)
        push(_V("obj", (fn, args)))
    elif name == "NEWOBJ_EX":
        _sym_pop(stack)
        args = _sym_pop(stack)
        cls = _sym_pop(stack)
        push(_V("obj", (cls, args)))
    elif name == "OBJ":
        items = _sym_pop_mark(stack)
        if not items:
            raise _Broken("OBJ without a class")
        push(_V("obj", (items[0], _sym_tuple(items[1:]))))
    elif name == "INST":
        items = _sym_pop_mark(stack)
        mod, _, fn = (arg or "").partition(" ")
        push(_V("obj", (_V("global", (mod, fn)), _sym_tuple(items))))
    elif name == "BUILD":
        state = _sym_pop(stack)
        target = _sym_top(stack)
        target.state = state
        return target
    elif name == "STOP":
        _sym_pop(stack)
    elif name in ("FRAME", "PROTO"):
        pass
    else:
        # Anything else (floats, bytes, sets, buffers, persistent ids,
        # extension codes): the effect pickletools documents, values unknown.
        before = opcode.stack_before
        if pickletools.markobject in before:
            _sym_pop_mark(stack)
            for _ in range(before.index(pickletools.markobject)):
                _sym_pop(stack)
        else:
            for _ in range(len(before)):
                _sym_pop(stack)
        for _ in range(len(opcode.stack_after)):
            push(_V("other"))
    return None


def _is_wrapper_class(v):
    return (v is not None and v.kind == "global"
            and v.val[1] == JOBLIB_WRAPPER_NAME
            and v.val[0] in JOBLIB_WRAPPER_MODULES)


def _is_wrapper(v):
    """True for an object the unpickler would create as a NumpyArrayWrapper:
    NEWOBJ of the class (protocol 2+), or copyreg._reconstructor(class, ...)
    (protocols 0 and 1)."""
    if v is None or v.kind != "obj":
        return False
    fn, args = v.val
    if _is_wrapper_class(fn):
        return True
    return (fn.kind == "global"
            and fn.val in (("copyreg", "_reconstructor"),
                           ("copy_reg", "_reconstructor"))
            and args.kind == "tuple" and bool(args.val)
            and _is_wrapper_class(args.val[0]))


def _dtype_info(v, depth=0):
    """(itemsize or None, hasobject) of a pickled numpy dtype, from the
    arguments and state numpy's dtype.__reduce__ writes: args (typestr, align,
    copy); state (version, byteorder, subarray, names, fields, elsize,
    alignment, flags[, metadata]). elsize > 0 is the itemsize of flexible and
    structured dtypes; builtin types give -1 and their typestr ('f8', 'i4',
    'M8', 'O8') carries the size. Flag bit 1 is NPY_ITEM_HASOBJECT."""
    if v is None or v.kind != "obj" or depth > 16:
        return None, False
    fn, args = v.val
    if (fn.kind != "global" or fn.val[1] != "dtype"
            or (fn.val[0] or "").split(".", 1)[0] != "numpy"):
        return None, False
    if args.kind != "tuple" or not args.val or args.val[0].kind != "str":
        return None, False
    typestr = args.val[0].val
    st = v.state.val if (v.state is not None and v.state.kind == "tuple"
                         and v.state.val is not None) else []

    def item(i, kind):
        return st[i].val if len(st) > i and st[i].kind == kind else None

    hasobj = typestr[:1] == "O"
    flags = item(7, "int")
    if flags is not None and flags & 1:
        hasobj = True
    fields = st[4] if len(st) > 4 else None
    if fields is not None and fields.kind == "dict" and fields.val:
        for fv in fields.val.values():
            if fv.kind == "tuple" and fv.val:
                if _dtype_info(fv.val[0], depth + 1)[1]:
                    hasobj = True
    sub = st[2] if len(st) > 2 else None
    if sub is not None and sub.kind == "tuple" and sub.val:
        if _dtype_info(sub.val[0], depth + 1)[1]:
            hasobj = True
    elsize = item(5, "int")
    if elsize is not None and elsize > 0:
        return elsize, hasobj
    m = re.match(r"^([A-Za-z])(\d+)$", typestr)
    if m and int(m.group(2)) > 0:
        n = int(m.group(2))
        return (4 * n if m.group(1) == "U" else n), hasobj
    return None, hasobj


def _wrapper_layout(wrapper):
    """What joblib.load reads after this wrapper's BUILD: ('object', None,
    None) for a nested pickle, ('raw', nbytes, aligned) for raw array bytes,
    or (None, reason, None) when the state does not tell."""
    state = wrapper.state
    if state is None or state.kind != "dict" or state.val is None:
        return None, "the wrapper's state is not a readable dict", None
    d = state.val
    itemsize, hasobj = _dtype_info(d.get("dtype"))
    if hasobj:
        return "object", None, None
    if itemsize is None:
        return None, "the array's dtype or itemsize could not be read", None
    shape = d.get("shape")
    if shape is None or shape.kind not in ("tuple", "list") or shape.val is None:
        return None, "the array's shape could not be read", None
    count = 1
    for dim in shape.val:
        if dim.kind != "int" or dim.val < 0:
            return None, "the array's shape is not a tuple of sizes", None
        count *= dim.val
    align = d.get("numpy_array_alignment_bytes")
    aligned = align is not None and align.kind != "none"
    return "raw", count * itemsize, aligned


class _Walk(object):
    """State shared by the outer stream and the pickles nested in it."""

    def __init__(self, data, source):
        self.data = data
        self.end = len(data)
        self.source = source
        self.findings = []
        self.globals_found = []   # (module, name, pos, resolvable)
        self.exec_ops = 0
        self.stop = None          # byte offset of the outer STOP, if reached
        self.joblib_arrays = 0    # numeric arrays skipped
        self.nested_pickles = 0   # object arrays walked as nested pickles
        self.wrapper_class_seen = False
        self.symbolic_lost = False


def _read_wrapped_array(buf, walk, wrapper, pos):
    """Move past the array joblib wrote after this wrapper. Returns True to
    continue the outer walk, False when the rest cannot be analysed."""
    loc = "%s @ byte %d" % (walk.source, pos)
    kind, size, aligned = _wrapper_layout(wrapper)
    if kind is None:
        walk.findings.append(Finding(
            "PKL008", "MEDIUM", "joblib array data could not be sized",
            "This is a joblib.dump file. joblib.load reads array data right "
            "after each NumpyArrayWrapper, and here %s, so the scanner cannot "
            "tell where the array ends. The rest of the file was not "
            "analysed; treat it as unscanned." % size, loc))
        return False
    if kind == "object":
        walk.nested_pickles += 1
        # joblib reads an object array with a fresh unpickler on the same
        # file: a complete pickle with its own memo, then the outer stream
        # goes on after its STOP.
        return _walk_stream(buf, walk, joblib_mode=False, nested=True)
    if aligned:
        pad = buf.read(1)
        if len(pad) < 1:
            return _truncated(walk, loc)
        n = pad[0]
        if walk.end - buf.tell() < n:
            return _truncated(walk, loc)
        buf.seek(n, io.SEEK_CUR)
    if walk.end - buf.tell() < size:
        return _truncated(walk, loc)
    buf.seek(size, io.SEEK_CUR)
    walk.joblib_arrays += 1
    return True


def _truncated(walk, loc):
    walk.findings.append(Finding(
        "PKL000", "LOW", "Pickle stream could not be fully parsed",
        "The file ends inside the data of a joblib array, so it is truncated. "
        "Part of the stream was not analysed; treat the file with caution.",
        loc))
    return False


def _walk_stream(buf, walk, joblib_mode, nested=False):
    """Walk one pickle stream from buf's position to its STOP. Returns True
    when it reached STOP and the caller may go on."""
    # Each STACK_GLOBAL takes its module and name from the top two stack
    # items. Since 0.3.0 they are resolved when the two opcodes that pushed
    # them are string literals or memo fetches (GET/BINGET/LONG_BINGET) of a
    # memoized string literal, with nothing in between that changes the stack
    # (memo stores, FRAME and PROTO do not). Pickle protocols 4 and 5 write
    # exactly this when a module name repeats (numpy.ndarray, then
    # numpy.dtype). Any other operand stays unresolved (PKL007), as before.
    # Every stream, including a nested one, has its own memo.
    memo = {}            # memo index -> ('str', value) or ('other', None)
    pushes = []          # the last two stack pushes, same shape
    stack = []           # symbolic stack (joblib files only)
    vmemo = {}
    sym = joblib_mode
    broken = None
    try:
        for opcode, arg, pos in pickletools.genops(buf):
            name = opcode.name
            built = None
            if sym:
                try:
                    built = _sym_step(opcode, arg, stack, vmemo)
                except _Broken as exc:
                    sym = False
                    broken = (pos, str(exc))
                    walk.symbolic_lost = True
                    stack, vmemo = [], {}
            if name in EXEC_OPCODES:
                walk.exec_ops += 1
            if name == "STOP" and not nested:
                walk.stop = pos
            if name in ("FRAME", "PROTO"):
                continue
            if name in MEMO_PUT_OPCODES or name == "MEMOIZE":
                key = len(memo) if name == "MEMOIZE" else arg
                memo[key] = pushes[-1] if pushes else ("other", None)
                continue
            if name in ("GLOBAL", "INST"):
                mod, _, fn = (arg or "").partition(" ")
                walk.globals_found.append((mod, fn, pos, True))
                if mod in JOBLIB_WRAPPER_MODULES and fn == JOBLIB_WRAPPER_NAME:
                    walk.wrapper_class_seen = True
            elif name == "STACK_GLOBAL":
                last_two = pushes[-2:]
                if (len(last_two) == 2 and last_two[0][0] == "str"
                        and last_two[1][0] == "str"):
                    walk.globals_found.append((last_two[0][1], last_two[1][1], pos, True))
                    if (last_two[0][1] in JOBLIB_WRAPPER_MODULES
                            and last_two[1][1] == JOBLIB_WRAPPER_NAME):
                        walk.wrapper_class_seen = True
                else:
                    walk.globals_found.append((None, None, pos, False))
            if name in STRING_OPCODES:
                pushes.append(("str", arg))
            elif name in MEMO_GET_OPCODES:
                pushes.append(memo.get(arg, ("other", None)))
            else:
                pushes.append(("other", None))
            del pushes[:-2]
            if built is not None and _is_wrapper(built):
                if not _read_wrapped_array(buf, walk, built, pos):
                    return False
                # joblib.load swaps the wrapper for the array it just read.
                stack[-1] = _V("other")
    except Exception as exc:  # truncated / malformed stream
        walk.findings.append(Finding(
            "PKL000", "LOW", "Pickle stream could not be fully parsed",
            f"pickletools stopped reading at an opcode: {exc}. Part of the stream "
            "was not analysed; treat the file with caution.", walk.source))
        return False
    if broken is not None and walk.wrapper_class_seen:
        walk.findings.append(Finding(
            "PKL008", "MEDIUM", "joblib array data could not be sized",
            "This stream uses joblib's NumpyArrayWrapper, but its opcodes did "
            "not fit a consistent stack at byte %d (%s), so the scanner could "
            "not follow where joblib.load reads array data. Parts of the file "
            "may not have been analysed; treat it as unscanned."
            % (broken[0], broken[1]), walk.source))
    return True


# torch.save(..., _use_new_zipfile_serialization=False), the legacy format
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


def pickle_walk(data, source="<bytes>"):
    """Describe what the static walk of one pickle stream covered, without
    unpickling anything: the imports it resolved in stream order ('module
    name'), how many it could not resolve, the byte offset of the outer STOP
    (None if the walk did not reach it), and how many joblib arrays it
    skipped or walked as nested pickles."""
    walk = _walk_pickle(data, source)
    return {
        "imports": ["%s %s" % (m, n) for m, n, _p, ok in walk.globals_found
                    if ok],
        "unresolved": sum(1 for g in walk.globals_found if not g[3]),
        "stop": walk.stop,
        "length": len(data),
        "joblib_arrays": walk.joblib_arrays,
        "nested_pickles": walk.nested_pickles,
        "joblib_mode": _JOBLIB_MARKER in data,
        "symbolic_stack_lost": walk.symbolic_lost,
        "rules": sorted({f.rule for f in walk.findings}),
        "streams": walk.streams,
        "torch_legacy": walk.torch_legacy,
    }


def scan_pickle_bytes(data, source):
    """Disassemble a pickle opcode stream and flag dangerous patterns.

    Uses pickletools.genops, which reads opcodes without unpickling. Never
    imports, executes, or reconstructs any object from the data.
    """
    walk = _walk_pickle(data, source)
    findings = walk.findings
    exec_ops = walk.exec_ops

    for mod, fn, pos, resolvable in walk.globals_found:
        loc = f"{source} @ byte {pos}"
        if not resolvable:
            findings.append(Finding(
                "PKL007", "HIGH", "Unresolved STACK_GLOBAL operands",
                "A STACK_GLOBAL opcode's module/name could not be resolved from the "
                "two string literals pushed just before it, directly or as "
                "memoized copies (the operands come from other objects or are "
                "built at load time). This is a documented way to hide a dangerous "
                "import from naive scanners - treat the file as untrusted and do not "
                "load it without manual review.", loc, "GHSA-9gvj-pp9x-gcfr"))
            continue
        cls = _classify(mod, fn)
        ref = f"{mod}.{fn}" if fn else mod
        if cls == "dangerous":
            if exec_ops:
                findings.append(Finding(
                    "PKL001", "CRITICAL",
                    "Dangerous import with a code-execution opcode",
                    f"Pickle imports {ref} and the stream contains REDUCE/BUILD/NEWOBJ "
                    "opcodes, so loading this file can run arbitrary code.",
                    loc, "CWE-502"))
            else:
                findings.append(Finding(
                    "PKL002", "HIGH", "Dangerous import in pickle",
                    f"Pickle imports {ref}, a module/callable commonly used for code "
                    "execution. Review why a model file references it.", loc))
        elif cls == "rce_gadget":
            findings.append(Finding(
                "PKL005", "CRITICAL" if exec_ops else "HIGH",
                "Known code-execution gadget in a trusted package",
                f"Pickle imports {ref}, a helper under numpy.f2py that calls eval() "
                "on its argument; NumPy's security documentation treats the whole "
                "numpy.f2py as unsafe to reach from an untrusted pickle. Paired with "
                "a REDUCE/BUILD opcode this yields arbitrary code execution - a "
                "'numpy' import alone does not make it safe. Do not load this file.",
                loc, "CVE-2025-71339"))
        elif cls == "gadget":
            findings.append(Finding(
                "PKL004", "HIGH", "Deferred-call gadget in pickle",
                f"Pickle imports {ref}; this can wrap and defer a dangerous callable, "
                "a common way to hide reduce-based execution behind a benign-looking "
                "import.", loc))
        elif cls == "unknown":
            findings.append(Finding(
                "PKL003", "MEDIUM", "Import outside the known-safe allowlist",
                f"Pickle imports {ref}, which is not a recognised safe model "
                "reconstructor. Confirm this module belongs in a model file.", loc))
    return findings


def _descr_has_object(descr):
    """True if a NumPy dtype descr contains an object ('O') field -> pickled data."""
    if isinstance(descr, str):
        return descr == "O" or descr.endswith("O") or "|O" in descr or "O" in descr.lstrip("<>=|")[:1]
    if isinstance(descr, (list, tuple)):
        found = False
        for item in descr:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                found = found or _descr_has_object(item[1])
            else:
                found = found or _descr_has_object(item)
        return found
    return False


def _read_npy_header(data):
    """Return (is_object_dtype, data_offset, header_dict) for a .npy blob."""
    if data[:6] != b"\x93NUMPY":
        raise ValueError("not a .npy file")
    major = data[6]
    if major == 1:
        hlen = struct.unpack("<H", data[8:10])[0]
        start = 10
    else:
        hlen = struct.unpack("<I", data[8:12])[0]
        start = 12
    header_text = data[start:start + hlen].decode("latin1").strip()
    header = ast.literal_eval(header_text)
    return _descr_has_object(header.get("descr")), start + hlen, header


def scan_npy(data, source):
    findings = []
    try:
        is_object, end, _ = _read_npy_header(data)
    except Exception:
        return findings
    if is_object:
        findings.append(Finding(
            "PKL010", "HIGH", "NumPy object-dtype array (pickle payload)",
            "This .npy declares dtype=object, so its data section is a pickle. "
            "numpy.load(allow_pickle=True) would unpickle it, an arbitrary-code path. "
            "numpy.load defaults to allow_pickle=False; do not override that for "
            "untrusted files.", source))
        findings += scan_pickle_bytes(data[end:], source + " (npy object payload)")
    return findings


def scan_safetensors(data, source):
    if len(data) < 8:
        return [Finding("PKL021", "LOW", "Malformed safetensors header",
                        "File is too short to hold an 8-byte header length.", source)]
    n = struct.unpack("<Q", data[:8])[0]
    if n == 0 or 8 + n > len(data):
        return [Finding("PKL021", "LOW", "Malformed safetensors header",
                        f"Declared header length {n} is inconsistent with the file "
                        f"size {len(data)}.", source)]
    try:
        header = json.loads(data[8:8 + n].decode("utf-8"))
    except Exception as exc:
        return [Finding("PKL021", "LOW", "Malformed safetensors header",
                        f"Header is not valid JSON: {exc}", source)]
    return [Finding(
        "PKL020", "INFO", "safetensors - no code-execution surface",
        "This is the safetensors format: a JSON header plus raw tensor bytes, with no "
        f"pickle and no code. Header declares {len(header)} entries. This is the "
        "recommended safe format for sharing weights.", source)]


def _is_traversal(name):
    norm = name.replace("\\", "/")
    if norm.startswith("/") or norm.startswith("~"):
        return True
    if len(norm) >= 2 and norm[1] == ":":  # windows drive letter
        return True
    return any(part == ".." for part in norm.split("/"))


def scan_zip(data, source):
    findings = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:
        return [Finding("PKL098", "LOW", "Archive could not be opened",
                        f"zipfile could not read the archive: {exc}", source)]
    for name in zf.namelist():
        member_src = f"{source}!{name}"
        if _is_traversal(name):
            findings.append(Finding(
                "PKL030", "HIGH", "Archive member escapes the extraction directory",
                "A member path is absolute or contains '..', so extracting it could "
                "overwrite files outside the target directory (Zip Slip).", member_src))
        base = os.path.basename(name).lower()
        ext = os.path.splitext(name)[1].lower()
        try:
            member = zf.read(name)
        except Exception:
            continue
        if ext == ".npy":
            findings += scan_npy(member, member_src)
        elif ext in PICKLE_EXTS or base == "data.pkl" or member[:1] == b"\x80":
            findings += scan_pickle_bytes(member, member_src)
    return findings


# joblib's compressors (joblib/compressor.py): 'xz' writes the .xz container,
# 'lzma' the legacy .lzma ("alone") format, whose header starts 5d 00. No
# pickle starts with those two bytes (']' then an invalid opcode), and a blob
# that does not decompress falls through to the checks below.
_XZ_MAGIC = b"\xfd7zXZ\x00"
_LZMA_ALONE_MAGIC = b"\x5d\x00"


def scan_blob(data, source, assume_pickle=False):
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return scan_zip(data, source)
    if data[:6] == b"\x93NUMPY":
        return scan_npy(data, source)
    if data[:4] == b"GGUF":
        return [Finding("PKL022", "INFO", "GGUF - data-only format",
                        "GGUF stores tensors and metadata as typed binary data with no "
                        "pickle and no code; no code-execution surface.", source)]
    if data[:2] == b"\x1f\x8b":
        try:
            return scan_blob(gzip.decompress(data), source + " (gunzipped)", assume_pickle)
        except Exception as exc:
            return [Finding("PKL006", "LOW", "Could not decompress gzip container",
                            f"{exc}", source)]
    if data[:3] == b"BZh":
        try:
            return scan_blob(bz2.decompress(data), source + " (bunzipped)", assume_pickle)
        except Exception as exc:
            return [Finding("PKL006", "LOW", "Could not decompress bz2 container",
                            f"{exc}", source)]
    if data[:6] == _XZ_MAGIC:
        try:
            return scan_blob(lzma.decompress(data), source + " (unxz)", assume_pickle)
        except Exception as exc:
            return [Finding("PKL006", "LOW", "Could not decompress xz container",
                            f"{exc}", source)]
    if data[:2] == _LZMA_ALONE_MAGIC:
        try:
            inner = lzma.decompress(data, format=lzma.FORMAT_ALONE)
        except Exception:
            inner = None
        if inner is not None:
            return scan_blob(inner, source + " (unlzma)", assume_pickle)
    if data[:4] == b"\x04\x22\x4d\x18":
        return [Finding("PKL006", "LOW", "lz4-compressed container not scanned",
                        "File is lz4-compressed (common for compressed joblib). Static "
                        "scanning needs the optional lz4 dependency; decompress it first "
                        "or treat as unscanned.", source)]
    if data[:4] == b"\x28\xb5\x2f\xfd":
        return [Finding("PKL006", "LOW", "zstd-compressed container not scanned",
                        "File is zstandard-compressed. Static scanning needs the optional "
                        "zstandard dependency; decompress it first or treat as unscanned.",
                        source)]
    if data[:1] == b"\x78":  # zlib (compressed joblib)
        try:
            return scan_blob(zlib.decompress(data), source + " (inflated)", assume_pickle)
        except Exception:
            pass
    if data[:1] == b"\x80" or assume_pickle:
        return scan_pickle_bytes(data, source)
    return [Finding("PKL099", "INFO", "Unrecognised file format",
                    "No pickle or known model structure was recognised; nothing was "
                    "scanned.", source)]


def scan_file(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        return None
    ext = os.path.splitext(path)[1].lower()
    if ext == ".safetensors":
        return scan_safetensors(data, path)
    if ext == ".gguf":
        return scan_blob(data, path)
    return scan_blob(data, path, assume_pickle=ext in PICKLE_EXTS)


def format_report(path, findings):
    lines = [f"== {path} =="]
    if not findings:
        lines.append("  clean: no dangerous patterns found (not a guarantee of safety)")
        return "\n".join(lines)
    ordered = sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity])
    for f in ordered:
        cve = f" [{f.cve}]" if f.cve else ""
        lines.append(f"  [{f.severity}] {f.rule} {f.title}{cve}")
        lines.append(f"      {f.detail}")
        lines.append(f"      at: {f.location}")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pickle-model-scan",
        description="Static, no-execution scanner for pickle-based model files. "
                    "Never imports, unpickles, or runs the scanned file.")
    parser.add_argument("paths", nargs="+", help="model files to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--fail-on", default="medium",
                        choices=["critical", "high", "medium", "low", "info"],
                        help="minimum severity that makes the exit code 1 (default: medium)")
    parser.add_argument("--version", action="version",
                        version=f"pickle-model-scan {__version__}")
    args = parser.parse_args(argv)

    threshold = SEVERITY_ORDER[args.fail_on.upper()]
    missing = False
    worst = -1
    results = {}
    for path in args.paths:
        findings = scan_file(path)
        if findings is None:
            missing = True
            sys.stderr.write(f"error: no such file: {path}\n")
            continue
        results[path] = findings
        for f in findings:
            worst = max(worst, SEVERITY_ORDER[f.severity])

    if args.json:
        print(json.dumps(
            {p: [f.as_dict() for f in fs] for p, fs in results.items()}, indent=2))
    else:
        for path, findings in results.items():
            print(format_report(path, findings))

    if missing:
        return 2
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
