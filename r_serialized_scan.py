#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""r_serialized_scan - static scanner for R .rds and .RData files.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

R saves objects (models from glm, rpart, caret, ranger...) with saveRDS() and
save(). The file is R's own serialization: an optional ``RDX2``/``RDX3``
workspace line, a format line (``X`` big-endian XDR, ``B`` native binary,
``A`` ascii), then a tree of typed items. Some of those items are code:

- A promise holds an expression and runs it the first time its value is read.
  R's reader refuses a promise only when it is the object returned at the top
  level (checkNotPromise in src/main/serialize.c); a promise anywhere else,
  for example bound in a saved environment, is restored as written.
- An environment binding marked active (gp bit 15, ACTIVE_BINDING_MASK) calls
  its function each time the variable is read; ReadItem restores the bit.
- Functions, quoted calls and byte-compiled code run what they call when they
  are evaluated.
- An ALTREP object names a class and a package; when the class is not
  registered, R asks for that package's namespace (src/main/altrep.c), and a
  namespace reference loads the package the same way.

This module decodes the stream itself with the Python standard library (no R)
and reports:

- RDS001 high   CWE-502  Code that runs when a value is read: a promise not
                         yet evaluated whose code is a call or bytecode, or an
                         active binding.
- RDS002 high   CWE-94   Stored code calls a function that runs commands,
                         evaluates or loads code, opens connections or deletes
                         files (system, eval, dyn.load, download.file,
                         unlink...): in a function body, bytecode, a promise
                         or a quoted call, also by name through do.call, get,
                         match.fun or ``::``.
- RDS003 medium CWE-829  Reading the file reaches outside it: a namespace or
                         ALTREP class from a package that is not part of base
                         R (that package is loaded), or a persistent reference
                         that needs a hook.
- RDS004 medium CWE-693  Not decoded: not R serialization, unsupported
                         compression, truncated, nesting or size limits, or
                         findings capped.

gzip, bzip2 and xz files (saveRDS's choices) are decompressed in memory up to
a size limit. Static review only: nothing is loaded or executed.
"""

import bz2
import gzip
import io
import lzma
import os
import struct
import sys
import zlib

__version__ = "0.1.0"

MAX_FINDINGS = 1000
MAX_DEPTH = 180
MAX_ITEMS = 10000000
MAX_BYTES = 512 * 1024 * 1024

_RULES = {
    "RDS001": ("high", "CWE-502"),
    "RDS002": ("high", "CWE-94"),
    "RDS003": ("medium", "CWE-829"),
    "RDS004": ("medium", "CWE-693"),
}

# SEXPTYPEs (Rinternals.h) and the stream's own pseudo-types (serialize.c).
_SYM, _LIST, _CLO, _ENV, _PROM, _LANG = 1, 2, 3, 4, 5, 6
_SPECIAL, _BUILTIN, _CHAR = 7, 8, 9
_LGL, _INT, _REAL, _CPLX, _STR, _DOT = 10, 13, 14, 15, 16, 17
_VEC, _EXPR, _BCODE, _EXTPTR, _WEAKREF, _RAW, _OBJ = 19, 20, 21, 22, 23, 24, 25
_REF, _UNBOUNDVALUE = 255, 252
_NAMESPACE, _PACKAGE, _PERSIST = 249, 248, 247
_BCREPDEF, _BCREPREF, _ATTRLANG, _ATTRLIST, _ALTREP = 244, 243, 240, 239, 238
# NULL, global env, unbound marker, missing arg, base namespace, empty env,
# base env: nothing follows their flags.
_SINGLETONS = (254, 253, 252, 251, 250, 242, 241)
_CHAIN = (_LIST, _LANG, _CLO, _PROM, _DOT)
_BCCELL = (_LANG, _LIST, _ATTRLANG, _ATTRLIST)
_BCLANG = _BCCELL + (_BCREPDEF, _BCREPREF)

_HAS_ATTR = 1 << 9
_HAS_TAG = 1 << 10
_ACTIVE_BINDING = 1 << 15          # gp bit, Defn.h ACTIVE_BINDING_MASK

# Atomic vectors: (bytes, ascii words) per element.
_ATOMIC = {_LGL: (4, 1), _INT: (4, 1), _REAL: (8, 1), _CPLX: (16, 2),
           _RAW: (1, 1)}

_BASE_PACKAGES = frozenset((
    "base", "compiler", "datasets", "grDevices", "graphics", "grid",
    "methods", "parallel", "splines", "stats", "stats4", "tcltk", "tools",
    "utils"))

_RISKY = frozenset((
    # commands, processes and session state
    "system", "system2", "shell", "shell.exec", "pipe", "Sys.setenv",
    "Sys.chmod", "setwd", "quit", "reg.finalizer",
    # code from text, files or other objects
    "eval", "evalq", "eval.parent", "parse", "str2lang", "str2expression",
    "source", "sys.source", "unserialize", "readRDS", "load",
    # native code and packages
    "dyn.load", "library.dynam", "library", "require", "requireNamespace",
    "loadNamespace", "attachNamespace", "install.packages",
    # network
    "url", "download.file", "socketConnection", "socketAccept",
    "serverSocket", "make.socket",
    # deleting or moving files
    "unlink", "file.remove", "file.rename", "file.copy", "file.create",
))
# Calls that reach a function by name: do.call("system", ...), get("eval").
_INDIRECT = frozenset((
    "do.call", "match.fun", "get", "get0", "getExportedValue",
    "getFromNamespace", "call", "as.name", "as.symbol"))
_KEEP = 3                          # call arguments kept for the checks

_NONE = ("none",)
_UNBOUND = ("unbound",)
_BYTECODE = ("bytecode",)

_WORKSPACE = (b"RDX2\n", b"RDX3\n", b"RDA2\n", b"RDA3\n", b"RDB2\n",
              b"RDB3\n")
_SPACE = b" \t\n\r\x0b\x0c"
_ESCAPES = {ord("n"): 10, ord("t"): 9, ord("v"): 11, ord("b"): 8,
            ord("r"): 13, ord("f"): 12, ord("a"): 7}


class _Bad(Exception):
    pass


def _ascii(value, limit=300):
    text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit] + "..."


def _text(raw):
    return raw.decode("utf-8", "replace")


def _name(desc):
    if desc[0] in ("sym", "chr", "str", "prim"):
        return desc[1] or ""
    return ""


def _call_name(head):
    if head[0] in ("sym", "prim"):
        return head[1]
    if head[0] == "call" and head[1] in ("::", ":::") and len(head[2]) >= 2:
        return _name(head[2][1])
    return ""


class _Findings(object):
    def __init__(self):
        self.items = []
        self._seen = {}
        self.capped = False

    def add(self, rule, message, evidence, key=None):
        if key is not None and key in self._seen:
            self._seen[key][1] += 1
            return
        if len(self.items) >= MAX_FINDINGS:
            self.capped = True
            return
        severity, cwe = _RULES[rule]
        item = {"rule": rule, "severity": severity, "cve": "", "cwe": cwe,
                "message": _ascii(message), "evidence": _ascii(evidence)}
        self.items.append(item)
        if key is not None:
            self._seen[key] = [item, 1]

    def result(self):
        for item, count in self._seen.values():
            if count > 1:
                item["evidence"] += "; %d in total" % count
        if self.capped:
            severity, cwe = _RULES["RDS004"]
            self.items.append({
                "rule": "RDS004", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


# -- streams ------------------------------------------------------------------

class _Binary(object):
    """XDR (big-endian) or native (little-endian) binary stream."""

    def __init__(self, data, pos, fmt):
        self.data = data
        self.pos = pos
        self._int = struct.Struct(fmt)

    def int(self):
        if len(self.data) - self.pos < 4:
            raise _Bad("truncated at byte %d" % self.pos)
        value = self._int.unpack_from(self.data, self.pos)[0]
        self.pos += 4
        return value

    def skip(self, count, size, words):
        if count * size > len(self.data) - self.pos:
            raise _Bad("a vector of %d items runs past the end of the data"
                       % count)
        self.pos += count * size

    def string(self, length):
        if length > len(self.data) - self.pos:
            raise _Bad("a string of %d bytes runs past the end of the data"
                       % length)
        self.pos += length
        return self.data[self.pos - length:self.pos]


class _Ascii(object):
    """R's ascii format: whitespace-separated words, escaped strings."""

    def __init__(self, data, pos):
        self.data = data
        self.pos = pos

    def _word(self):
        data, pos, end = self.data, self.pos, len(self.data)
        while pos < end and data[pos] in _SPACE:
            pos += 1
        start = pos
        while pos < end and data[pos] not in _SPACE:
            pos += 1
        if start == pos:
            raise _Bad("truncated at byte %d" % pos)
        self.pos = pos
        return data[start:pos]

    def int(self):
        word = self._word()
        if word == b"NA":
            return -2147483648
        try:
            return int(word)
        except ValueError:
            raise _Bad("not an integer: %s" % _ascii(word, 40))

    def skip(self, count, size, words):
        if count * words > len(self.data) - self.pos:
            raise _Bad("a vector of %d items runs past the end of the data"
                       % count)
        for _ in range(count * words):
            self._word()

    def string(self, length):
        data, pos, end = self.data, self.pos, len(self.data)
        if length > end - pos:
            raise _Bad("a string of %d bytes runs past the end of the data"
                       % length)
        while length and pos < end and data[pos] in _SPACE:
            pos += 1
        out = bytearray()
        while len(out) < length:
            if pos >= end:
                raise _Bad("truncated string")
            c = data[pos]
            pos += 1
            if c != 92:                                  # backslash
                out.append(c)
                continue
            c = data[pos] if pos < end else -1
            pos += 1
            if 48 <= c <= 55:                            # up to 3 octal digits
                value = 0
                digits = 0
                while digits < 3 and 48 <= c <= 55:
                    value = value * 8 + c - 48
                    digits += 1
                    c = data[pos] if pos < end else -1
                    pos += 1
                pos -= 1
                out.append(value & 0xFF)
            elif c < 0:
                raise _Bad("truncated string")
            else:
                out.append(_ESCAPES.get(c, c))
        self.pos = pos
        return bytes(out)


def _decompress(data):
    if data[:2] == b"\x1f\x8b":
        stream = gzip.GzipFile(fileobj=io.BytesIO(data))
    elif data[:3] == b"BZh":
        stream = bz2.BZ2File(io.BytesIO(data))
    elif data[:6] == b"\xfd7zXZ\x00":
        stream = lzma.LZMAFile(io.BytesIO(data))
    elif data[:4] == b"\x28\xb5\x2f\xfd":
        raise _Bad("zstd-compressed; not decoded")
    else:
        return data
    try:
        with stream:
            raw = stream.read(MAX_BYTES + 1)
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error) as exc:
        raise _Bad("cannot decompress: %s" % exc)
    if len(raw) > MAX_BYTES:
        raise _Bad("more than %d bytes once decompressed; not checked"
                   % MAX_BYTES)
    return raw


def _open(data):
    pos = 5 if data[:5] in _WORKSPACE else 0
    if data[pos:pos + 3] == b"\nA\n":
        pos += 1
    line = data[pos:pos + 2]
    if line == b"X\n":
        reader = _Binary(data, pos + 2, ">i")
    elif line == b"B\n":
        reader = _Binary(data, pos + 2, "<i")
    elif line == b"A\n":
        reader = _Ascii(data, pos + 2)
    else:
        raise _Bad("no R serialization format line (X, B or A)")
    version = reader.int()
    if version not in (2, 3):
        raise _Bad("serialization version %d" % version)
    reader.int()                                         # R that wrote it
    reader.int()                                         # oldest R to read it
    if version == 3:
        length = reader.int()
        if not 0 <= length <= 63:
            raise _Bad("native encoding name of %d bytes" % length)
        reader.string(length)
    return reader


# -- items --------------------------------------------------------------------

class _Decoder(object):
    def __init__(self, reader, out):
        self.r = reader
        self.out = out
        self.refs = []
        self.count = 0

    def _enter(self, depth):
        self.count += 1
        if self.count > MAX_ITEMS:
            raise _Bad("more than %d items; the rest was not checked"
                       % MAX_ITEMS)
        if depth > MAX_DEPTH:
            raise _Bad("nesting deeper than %d levels; the rest was not "
                       "checked" % MAX_DEPTH)

    def item(self, depth, where):
        self._enter(depth)
        return self._dispatch(self.r.int(), depth, where)

    def _dispatch(self, flags, depth, where):
        kind = flags & 0xFF
        if kind in _SINGLETONS:
            return _UNBOUND if kind == _UNBOUNDVALUE else _NONE
        if kind == _REF:
            index = flags >> 8
            if index == 0:
                index = self.r.int()
            if not 1 <= index <= len(self.refs):
                raise _Bad("reference %d to an item not yet read" % index)
            return self.refs[index - 1]
        if kind in _CHAIN:
            return self._chain(flags, depth, where)
        if kind == _SYM:
            value = ("sym", _name(self.item(depth + 1, where)))
            self.refs.append(value)
            return value
        if kind == _ENV:
            value = ("env",)
            self.r.int()                                 # locked
            self.refs.append(value)
            for _ in range(4):           # enclosure, frame, hash table, attrs
                self.item(depth + 1, where + " > env")
            return value
        if kind in (_NAMESPACE, _PACKAGE, _PERSIST):
            self._outside(kind, self._strings(depth, where), where)
            value = ("other", kind)
            self.refs.append(value)
            return value
        if kind == _ALTREP:
            self._altrep(self.item(depth + 1, where), where)
            self.item(depth + 1, where)                  # state
            self.item(depth + 1, where)                  # attributes
            return ("other", kind)
        value = self._payload(kind, depth, where)
        if flags & _HAS_ATTR:
            self.item(depth + 1, where + " attr")
        return value

    def _length(self):
        length = self.r.int()
        if length < -1:
            raise _Bad("vector length %d" % length)
        if length == -1:
            upper = self.r.int()
            lower = self.r.int()
            if not 0 <= upper <= 65536:
                raise _Bad("long vector length")
            length = (upper << 32) + (lower & 0xFFFFFFFF)
        return length

    def _payload(self, kind, depth, where):
        if kind in _ATOMIC:
            size, words = _ATOMIC[kind]
            self.r.skip(self._length(), size, words)
            return ("other", kind)
        if kind == _CHAR:
            length = self.r.int()
            if length < -1:
                raise _Bad("string length %d" % length)
            if length == -1:                             # NA_character_
                return _NONE
            return ("chr", _text(self.r.string(length)))
        if kind in (_STR, _VEC, _EXPR):
            first = _NONE
            for index in range(self._length()):
                value = self.item(depth + 1, where if kind == _STR
                                  else "%s[[%d]]" % (where, index + 1))
                if index == 0:
                    first = value
            if kind == _STR and first[0] == "chr":
                return ("str", first[1])
            return ("other", kind)
        if kind in (_SPECIAL, _BUILTIN):
            length = self.r.int()
            if not 0 <= length <= 255:
                raise _Bad("primitive name of %d bytes" % length)
            return ("prim", _text(self.r.string(length)))
        if kind == _BCODE:
            self.r.int()                         # size of the shared-cell table
            self._bc1(depth + 1, where)
            return _BYTECODE
        if kind == _EXTPTR:
            self.refs.append(("other", kind))
            self.item(depth + 1, where)                  # protected value
            self.item(depth + 1, where)                  # tag
            return ("other", kind)
        if kind == _WEAKREF:
            self.refs.append(("other", kind))
            return ("other", kind)
        if kind == _OBJ:
            return ("other", kind)
        raise _Bad("item type %d is not one R reads" % kind)

    def _strings(self, depth, where):
        if self.r.int() != 0:
            raise _Bad("named persistent strings")
        count = self.r.int()
        if count < 0:
            raise _Bad("string count %d" % count)
        return [_name(self.item(depth + 1, where)) for _ in range(count)]

    def _chain(self, flags, depth, where):
        """Pairlist-like cells, read along the CDR without recursing."""
        first_kind = flags & 0xFF
        first_call = None
        cars = []
        call = None              # [head, args, where] of the call being read
        promise = None           # where of an unevaluated promise; code next
        while True:
            kind = flags & 0xFF
            if flags & _HAS_ATTR:
                self.item(depth + 1, where + " attr")
            tag = self.item(depth + 1, where) if flags & _HAS_TAG else _NONE
            if kind == _LANG:
                self._finish(call)
                call = [self.item(depth + 1, where), [], where]
                if first_call is None:
                    first_call = call
                if promise is not None:
                    self._promise(promise, "calls %s()" % (
                        _call_name(call[0]) or "a computed function"))
                    promise = None
            elif kind == _CLO:
                self._finish(call)
                call = promise = None
                where += " > function"
                self.item(depth + 1, where)              # formals
            elif kind == _PROM:
                self._finish(call)
                call = None
                value = self.item(depth + 1, where)
                promise = where if value == _UNBOUND else None
                where += " > promise"
            else:
                promise = None
                name = _name(tag)
                here = "%s$%s" % (where, name) if name else where
                if kind == _LIST and (flags >> 12) & _ACTIVE_BINDING:
                    self.out.add(
                        "RDS001", "an active binding: its function runs each "
                        "time the variable is read",
                        "%s: active binding" % here,
                        key=("RDS001", "active", here))
                car = self.item(depth + 1, here)
                if call is not None:
                    if len(call[1]) < _KEEP:
                        call[1].append(car)
                elif len(cars) < _KEEP:
                    cars.append(car)
            flags = self.r.int()
            if flags & 0xFF not in _CHAIN:
                break
            self._enter(depth)
        self._enter(depth + 1)
        tail = self._dispatch(flags, depth + 1, where)
        if promise is not None and tail == _BYTECODE:
            self._promise(promise, "is byte-compiled code")
        self._finish(call)
        if first_kind == _LANG:
            return ("call", _call_name(first_call[0]), first_call[1])
        if first_kind in (_LIST, _DOT):
            return ("list", cars)
        return ("other", first_kind)

    def _bc1(self, depth, where):
        self._enter(depth)
        self.item(depth + 1, where)                      # instructions
        count = self.r.int()
        if count < 0:
            raise _Bad("bytecode constant count %d" % count)
        for _ in range(count):
            kind = self.r.int()
            if kind == _BCODE:
                self._bc1(depth + 1, where)
            elif kind in _BCLANG:
                self._bclang(kind, depth + 1, where)
            else:
                self.item(depth + 1, where)

    def _bclang(self, kind, depth, where):
        self._enter(depth)
        if kind == _BCREPREF:
            self.r.int()
            return _NONE
        if kind == _BCREPDEF:
            self.r.int()                         # slot in the shared-cell table
            kind = self.r.int()
        if kind not in _BCCELL:                  # a 0 pad, then a full item
            return self.item(depth + 1, where)
        if kind in (_ATTRLANG, _ATTRLIST):
            self.item(depth + 1, where + " attr")
        self.item(depth + 1, where)                      # tag
        car = self._bclang(self.r.int(), depth + 1, where)
        cdr = self._bclang(self.r.int(), depth + 1, where)
        args = [car] + list(cdr[1] if cdr[0] == "args" else ())
        if kind in (_LIST, _ATTRLIST):
            return ("args", args[:_KEEP])
        call = [car, args[1:_KEEP + 1], where]
        self._finish(call)
        return ("call", _call_name(car), call[1])

    # -- findings -------------------------------------------------------------

    def _finish(self, call):
        if call is None:
            return
        head, args, where = call
        name = _call_name(head)
        if name in _RISKY:
            self._risky(name, "", where)
        elif name in _INDIRECT and args:
            target = _name(args[0])
            if target in _RISKY:
                self._risky(target, name, where)

    def _risky(self, name, via, where):
        what = "%s() through %s()" % (name, via) if via else "%s()" % name
        self.out.add("RDS002", "stored code calls a function that runs "
                     "commands, evaluates or loads code, opens connections or "
                     "deletes files; it runs if this code is ever evaluated",
                     "%s: calls %s" % (where, what),
                     key=("RDS002", what, where))

    def _promise(self, where, detail):
        self.out.add("RDS001", "an unevaluated promise: its code runs the "
                     "first time the value is read, and R's reader refuses "
                     "only a promise at the top level",
                     "%s: promise %s" % (where, detail),
                     key=("RDS001", "promise", where, detail))

    def _outside(self, kind, names, where):
        first = names[0] if names else ""
        if kind == _NAMESPACE and first not in _BASE_PACKAGES:
            self.out.add("RDS003", "reading the file loads the namespace of a "
                         "package that is not part of base R",
                         "%s: namespace %s" % (where, " ".join(names[:2])),
                         key=("RDS003", "namespace", first))
        elif kind == _PERSIST:
            self.out.add("RDS003", "a persistent reference: R needs a restore "
                         "hook from the caller to read it",
                         "%s: %s" % (where, " ".join(names[:3])),
                         key=("RDS003", "persist", first))

    def _altrep(self, info, where):
        if info[0] != "list" or len(info[1]) < 2:
            raise _Bad("ALTREP class information is not a class and package")
        cls, pkg = _name(info[1][0]), _name(info[1][1])
        if pkg not in _BASE_PACKAGES:
            self.out.add("RDS003", "an ALTREP object from a package that is "
                         "not part of base R: R loads that package to "
                         "rebuild it",
                         "%s: class %s from package %s" % (where, cls, pkg),
                         key=("RDS003", "altrep", cls, pkg))


# -- entry points -------------------------------------------------------------

def _scan_blob(data, where, out):
    try:
        reader = _open(_decompress(bytes(data)))
        _Decoder(reader, out).item(0, where)
    except _Bad as exc:
        out.add("RDS004", "not fully decoded as R serialization; findings "
                "before this point are kept", "%s: %s" % (where, _ascii(exc)))


def _guard(out, func, *args):
    """Run func(*args, out), turning a decoder crash into an RDS004 finding."""
    try:
        func(*args, out)
    except OSError:
        raise
    except Exception as exc:  # hostile input must never crash the scan
        out.add("RDS004", "the file could not be parsed; findings before "
                "this point are kept",
                "%s: %s" % (type(exc).__name__, _ascii(exc)))


def scan_bytes(data, name=""):
    """Scan an in-memory .rds or .RData file. Returns findings."""
    out = _Findings()
    _guard(out, _scan_blob, data, name or "object")
    return out.result()


def scan_file(path):
    """Scan an .rds or .RData file."""
    with open(path, "rb") as handle:
        data = handle.read()
    out = _Findings()
    _guard(out, _scan_blob, data, os.path.basename(path))
    return out.result()


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python r_serialized_scan.py FILE.rds|FILE.RData [...]",
              file=sys.stderr)
        return 2
    failed = high = False
    for path in args:
        try:
            findings = scan_file(path)
        except OSError as exc:
            print("%s: cannot read: %s" % (path, exc), file=sys.stderr)
            failed = True
            continue
        if not findings:
            print("%s: no findings" % path)
        for item in findings:
            print("%s: %s %s: %s [%s]" % (path, item["rule"], item["severity"],
                                          item["message"], item["evidence"]))
            high = high or item["severity"] == "high"
    if failed:
        return 2
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
