"""Static, dependency-free scanner for MessagePack weight files: Flax/JAX
``.msgpack`` checkpoints and msgpack-numpy payloads.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

Two common ways of storing arrays in MessagePack behave very differently on
load:

* Flax (``flax.serialization.msgpack_restore``) stores each array as extension
  type 1 (scalars as type 3) holding a packed ``(shape, dtype name, buffer)``
  triple, and rebuilds it with ``np.frombuffer``. Flax's own writer refuses
  object and structured dtypes, and the reader never unpickles.
* msgpack-numpy (``msgpack_numpy.decode``, used as an ``object_hook``) stores
  each array as a map with keys ``nd``, ``type``, ``kind``, ``shape`` and
  ``data``. When ``kind`` is ``O`` (an object array) it calls
  ``pickle.loads(data)``, so the file can run code when it is unpacked. The
  upstream fix (lebedov/msgpack-numpy PR #58, an ``allow_pickle`` switch that
  refuses by default) was still unmerged when this module was written.

This module parses the MessagePack bytes itself (no ``msgpack``, ``numpy`` or
``flax`` import), memory-maps files instead of reading them whole, and checks
every map and extension value as it is completed, the same order in which
``object_hook`` and ``ext_hook`` fire. A file that breaks off part-way still
gets findings for what came before the break. Object-array pickles are read
with ``pickletools`` (opcodes only, never executed) to list what they import.

Rules
-----
MPK001  high    CWE-502  msgpack-numpy object array whose pickle imports
                         something other than numpy's own array
                         reconstruction helpers (or an import the scanner
                         cannot resolve statically).
MPK002  medium  CWE-502  msgpack-numpy object array whose pickle imports only
                         numpy's reconstruction helpers. Still unpickled on
                         load; review where the file came from.
MPK003  medium  CWE-20   Flax array or scalar payload that Flax's own writer
                         would not produce: not a (shape, dtype, buffer)
                         triple, an object or structured dtype, or a buffer
                         whose size does not match shape x item size.
MPK004  medium  CWE-693  Content this scanner could not fully inspect: not
                         well-formed MessagePack, nested deeper than
                         MAX_DEPTH, more than one top-level value, or an
                         extension type Flax does not define.
"""

__version__ = "0.1.0"

# Caps so a huge or hostile file cannot exhaust the scanner.
MAX_DEPTH = 128
MAX_VALUES = 1000
MAX_FINDINGS = 1000
MAX_DIMS = 64

# Globals that numpy itself writes when it pickles an object array.
_NUMPY_GLOBALS = frozenset({
    "numpy.core.multiarray._reconstruct",
    "numpy._core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "numpy._core.multiarray.scalar",
    "numpy.ndarray",
    "numpy.dtype",
    "_codecs.encode",
})

# Item sizes for the dtype names Flax writes (arr.dtype.name). Names not
# listed here skip the size check.
_ITEMSIZE = {
    "bool": 1, "int8": 1, "uint8": 1,
    "float8_e4m3fn": 1, "float8_e5m2": 1,
    "int16": 2, "uint16": 2, "float16": 2, "bfloat16": 2,
    "int32": 4, "uint32": 4, "float32": 4,
    "int64": 8, "uint64": 8, "float64": 8, "complex64": 8,
    "complex128": 16,
}

_STR_OPS = frozenset({
    "STRING", "BINSTRING", "SHORT_BINSTRING",
    "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8",
})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})

_RULES = {
    "MPK001": ("high", "CWE-502",
               "msgpack-numpy object array: msgpack_numpy.decode passes its "
               "data to pickle.loads, and this pickle imports more than "
               "numpy's array helpers. Unpacking the file can run code. Do "
               "not load it with msgpack-numpy untrusted."),
    "MPK002": ("medium", "CWE-502",
               "msgpack-numpy object array: its data is a pickle that "
               "msgpack_numpy.decode unpickles on load. It imports only "
               "numpy's array helpers; still treat the file as a pickle."),
    "MPK003": ("medium", "CWE-20",
               "Flax array payload that Flax's own writer would not "
               "produce. The file was made or edited by something else; "
               "check where it came from."),
    "MPK004": ("medium", "CWE-693",
               "Part of the file could not be inspected, so it may hide "
               "content from this and other scanners. Inspect it by hand."),
}


class _Malformed(Exception):
    pass


class _Ext(object):
    __slots__ = ("code", "data")

    def __init__(self, code, data):
        self.code = code
        self.data = data


class _Map(object):
    __slots__ = ("pairs",)

    def __init__(self, pairs):
        self.pairs = pairs


class _Ctx(object):
    def __init__(self, label):
        self.label = label
        self.findings = []
        self.dropped = 0

    def add(self, rule, path, detail):
        if len(self.findings) >= MAX_FINDINGS:
            self.dropped += 1
            return
        self.findings.append(
            _report(rule, "%s:%s" % (self.label, path or "/"), detail))


def _finding(rule, severity, cve, cwe, message, evidence):
    return {
        "rule": rule,
        "severity": severity,
        "cve": cve,
        "cwe": cwe,
        "message": message,
        "evidence": evidence,
    }


def _ascii(s):
    return s.encode("ascii", "backslashreplace").decode("ascii")


def _report(rule, where, detail):
    severity, cwe, message = _RULES[rule]
    return _finding(rule, severity, "", cwe, message,
                    _ascii("%s: %s" % (where, detail)))


def _name(value):
    """A short str or bin value as text, else None."""
    if isinstance(value, str):
        return value if len(value) <= 64 else None
    if isinstance(value, (bytes, memoryview)) and len(value) <= 64:
        return bytes(value).decode("latin-1")
    return None


def _show(key):
    if isinstance(key, str):
        return key[:60]
    if isinstance(key, (bytes, memoryview)):
        return bytes(key[:60]).decode("latin-1")
    if key is None or isinstance(key, (bool, int, float)):
        return repr(key)
    return "<%s>" % type(key).__name__


def _as_bytes(value):
    """bin values as-is; str values back to their raw bytes (old raw mode)."""
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    if isinstance(value, (bytes, memoryview)):
        return value
    return None


# --- MessagePack parsing ----------------------------------------------------

def _take(buf, pos, n):
    end = pos + n
    if end > len(buf):
        raise _Malformed("data ends early at offset %d (%d more bytes needed)"
                         % (pos, end - len(buf)))
    return buf[pos:end], end


def _uint(buf, pos, size):
    raw, pos = _take(buf, pos, size)
    return int.from_bytes(raw, "big"), pos


def _parse_str(buf, pos, n):
    raw, pos = _take(buf, pos, n)
    return bytes(raw).decode("utf-8", "surrogateescape"), pos


def _parse_array(buf, pos, n, depth, path, ctx):
    if n > len(buf) - pos:
        raise _Malformed("array of %d items declared at offset %d, only %d "
                         "bytes left" % (n, pos, len(buf) - pos))
    items = []
    for i in range(n):
        item, pos = _parse(buf, pos, depth + 1, "%s[%d]" % (path, i), ctx)
        items.append(item)
    return items, pos


def _parse_map(buf, pos, n, depth, path, ctx):
    if 2 * n > len(buf) - pos:
        raise _Malformed("map of %d entries declared at offset %d, only %d "
                         "bytes left" % (n, pos, len(buf) - pos))
    pairs = []
    for _ in range(n):
        key, pos = _parse(buf, pos, depth + 1, path + "/<key>", ctx)
        value, pos = _parse(buf, pos, depth + 1,
                            "%s/%s" % (path, _show(key)), ctx)
        pairs.append((key, value))
    if ctx is not None:
        _check_map(pairs, path, ctx)
    return _Map(pairs), pos


def _parse_ext(buf, pos, n, path, ctx):
    raw, pos = _take(buf, pos, 1)
    code = int.from_bytes(raw, "big", signed=True)
    data, pos = _take(buf, pos, n)
    ext = _Ext(code, data)
    if ctx is not None:
        _check_ext(ext, path, ctx)
    return ext, pos


def _parse(buf, pos, depth, path, ctx):
    """Parse one MessagePack value at pos. Returns (value, next pos). Maps
    become _Map, bin values memoryview slices, ext values _Ext. ctx (or None)
    receives findings for maps and extension values as each one completes."""
    if depth > MAX_DEPTH:
        raise _Malformed("nested deeper than %d levels at offset %d"
                         % (MAX_DEPTH, pos))
    if pos >= len(buf):
        raise _Malformed("data ends early at offset %d" % pos)
    b = buf[pos]
    pos += 1
    if b <= 0x7F:
        return b, pos
    if b >= 0xE0:
        return b - 0x100, pos
    if b <= 0x8F:
        return _parse_map(buf, pos, b & 0x0F, depth, path, ctx)
    if b <= 0x9F:
        return _parse_array(buf, pos, b & 0x0F, depth, path, ctx)
    if b <= 0xBF:
        return _parse_str(buf, pos, b & 0x1F)
    if b == 0xC0:
        return None, pos
    if b == 0xC2:
        return False, pos
    if b == 0xC3:
        return True, pos
    if 0xC4 <= b <= 0xC6:
        n, pos = _uint(buf, pos, 1 << (b - 0xC4))
        return _take(buf, pos, n)
    if 0xC7 <= b <= 0xC9:
        n, pos = _uint(buf, pos, 1 << (b - 0xC7))
        return _parse_ext(buf, pos, n, path, ctx)
    if b == 0xCA or b == 0xCB:
        import struct

        raw, pos = _take(buf, pos, 4 if b == 0xCA else 8)
        return struct.unpack(">f" if b == 0xCA else ">d", raw)[0], pos
    if 0xCC <= b <= 0xCF:
        return _uint(buf, pos, 1 << (b - 0xCC))
    if 0xD0 <= b <= 0xD3:
        raw, pos = _take(buf, pos, 1 << (b - 0xD0))
        return int.from_bytes(raw, "big", signed=True), pos
    if 0xD4 <= b <= 0xD8:
        return _parse_ext(buf, pos, 1 << (b - 0xD4), path, ctx)
    if 0xD9 <= b <= 0xDB:
        n, pos = _uint(buf, pos, 1 << (b - 0xD9))
        return _parse_str(buf, pos, n)
    if b == 0xDC or b == 0xDD:
        n, pos = _uint(buf, pos, 2 if b == 0xDC else 4)
        return _parse_array(buf, pos, n, depth, path, ctx)
    if b == 0xDE or b == 0xDF:
        n, pos = _uint(buf, pos, 2 if b == 0xDE else 4)
        return _parse_map(buf, pos, n, depth, path, ctx)
    raise _Malformed("reserved byte 0xc1 at offset %d" % (pos - 1))


# --- checks -----------------------------------------------------------------

def _pickle_imports(data):
    """List the globals a pickle imports, from its opcodes only. Returns
    (imports, error type name or None). STACK_GLOBAL whose module and name
    are not the two string pushes right before it is '<computed>'."""
    import pickletools

    imports = []
    recent = []
    memo = {}
    error = None
    try:
        for op, arg, _pos in pickletools.genops(data):
            name = op.name
            if name in ("GLOBAL", "INST"):
                imports.append(str(arg).replace(" ", "."))
                recent.append(None)
            elif name == "STACK_GLOBAL":
                pair = recent[-2:]
                if len(pair) == 2 and all(isinstance(p, str) for p in pair):
                    imports.append("%s.%s" % (pair[0], pair[1]))
                else:
                    imports.append("<computed>")
                recent.append(None)
            elif name in _STR_OPS:
                recent.append(arg if isinstance(arg, str) else None)
            elif name in _GET_OPS:
                recent.append(memo.get(arg))
            elif name == "MEMOIZE":
                memo[len(memo)] = recent[-1] if recent else None
            elif name in _PUT_OPS:
                memo[arg] = recent[-1] if recent else None
            else:
                recent.append(None)
            if len(recent) > 16:
                del recent[:-2]
            if len(imports) >= 64:
                break
    except Exception as exc:  # hostile input must not crash the scan
        error = type(exc).__name__
    return imports, error


def _check_object_array(data, path, ctx):
    raw = _as_bytes(data)
    if raw is None:
        ctx.add("MPK004", path, "msgpack-numpy object array whose data is "
                "not a byte string")
        return
    imports, error = _pickle_imports(bytes(raw))
    risky = [i for i in imports if i not in _NUMPY_GLOBALS]
    detail = "msgpack-numpy object array (kind 'O'); data goes to pickle.loads"
    if imports:
        detail += "; imports " + ", ".join(sorted(set(imports))[:8])
    if error:
        detail += "; pickle stream breaks off (%s)" % error
    ctx.add("MPK001" if risky else "MPK002", path, detail)


def _check_map(pairs, path, ctx):
    fields = {}
    for key, value in pairs:
        name = _name(key)
        if name is not None:
            fields[name] = value  # last key wins, as in a dict
    if fields.get("nd") is True and _name(fields.get("kind")) == "O":
        _check_object_array(fields.get("data"), path, ctx)


def _object_dtype(name):
    n = name.strip().lstrip("<>=|")
    return (n.startswith("O") or n in ("object", "object_")
            or "," in n or n.startswith("("))


def _flax_array_problem(data, code):
    """Describe why a Flax ext payload is not what Flax writes, or None."""
    kind = "array" if code == 1 else "scalar"
    try:
        value, end = _parse(data, 0, 0, "", None)
    except _Malformed as exc:
        return "Flax %s payload is not MessagePack (%s)" % (kind, exc)
    if end != len(data) or not isinstance(value, list) or len(value) != 3:
        return "Flax %s payload is not a (shape, dtype, buffer) triple" % kind
    shape, dtype, buffer = value
    if not isinstance(shape, list) or not all(
            isinstance(d, int) and not isinstance(d, bool) and d >= 0
            for d in shape):
        return "Flax %s shape is not a list of non-negative integers" % kind
    if len(shape) > MAX_DIMS:
        return "Flax %s has %d dimensions (numpy allows at most %d)" % (
            kind, len(shape), MAX_DIMS)
    name = _name(dtype)
    if name is None:
        return "Flax %s dtype name is missing or too long" % kind
    buffer = _as_bytes(buffer)
    if buffer is None:
        return "Flax %s buffer is not a byte string" % kind
    if _object_dtype(name):
        return ("Flax %s has object or structured dtype %r; Flax's own "
                "writer refuses these" % (kind, name))
    itemsize = _ITEMSIZE.get(name)
    if itemsize is not None:
        count = 1
        for d in shape:
            count *= d
        if count * itemsize != len(buffer):
            return ("Flax %s of shape %s and dtype %s needs %d bytes but the "
                    "buffer holds %d" % (kind, shape, name, count * itemsize,
                                         len(buffer)))
    return None


def _check_ext(ext, path, ctx):
    if ext.code in (1, 3):
        problem = _flax_array_problem(ext.data, ext.code)
        if problem:
            ctx.add("MPK003", path, problem)
    elif ext.code not in (2, -1):  # 2: Flax complex, -1: msgpack timestamp
        ctx.add("MPK004", path, "extension type %d, which Flax does not "
                "define; another loader's ext_hook may decode it" % ext.code)


def _scan_view(buf, label):
    ctx = _Ctx(label)
    try:
        pos = 0
        count = 0
        while pos < len(buf):
            if count >= MAX_VALUES:
                ctx.add("MPK004", "", "stopped after %d top-level values; %d "
                        "bytes not read" % (MAX_VALUES, len(buf) - pos))
                break
            path = "" if count == 0 else "#%d" % (count + 1)
            _value, pos = _parse(buf, pos, 0, path, ctx)
            count += 1
        if count > 1:
            ctx.add("MPK004", "", "%d MessagePack values in one file; unpackb "
                    "refuses the extra data, a streaming Unpacker reads all "
                    "of it" % count)
    except _Malformed as exc:
        ctx.add("MPK004", "", "not well-formed MessagePack: %s" % exc)
    except Exception as exc:  # hostile input must not crash the scan
        ctx.add("MPK004", "", "parse stopped (%s)" % type(exc).__name__)
    findings = ctx.findings
    if ctx.dropped:
        findings.append(_report("MPK004", label,
                                "%d more findings not listed (limit %d)"
                                % (ctx.dropped, MAX_FINDINGS)))
    return findings


def scan_bytes(data, name=""):
    """Scan the bytes of a MessagePack weight file. Returns a list of finding
    dicts (possibly empty)."""
    if not data:
        return []
    return _scan_view(memoryview(bytes(data)), name or "<bytes>")


def scan_file(path):
    """Scan a MessagePack weight file on disk without reading it all into
    memory. Raises OSError if it cannot be read."""
    import mmap
    import os

    label = os.path.basename(path)
    with open(path, "rb") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            return []
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            return _scan_view(memoryview(mm), label)
        finally:
            try:
                mm.close()
            except BufferError:
                pass  # a view is still alive; the map closes when collected


def main(argv=None):
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: msgpack_weights_scan.py <file> [...]\n")
        return 2
    exit_code = 0
    for path in argv:
        try:
            findings = scan_file(path)
        except OSError as exc:
            sys.stderr.write("error: cannot read %s: %s\n" % (path, exc))
            return 2
        for f in findings:
            print("%s %s [%s] %s: %s | %s" % (
                f["severity"].upper(), f["rule"], f["cve"] or f["cwe"], path,
                f["message"], f["evidence"]))
            if f["severity"] == "high":
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    import sys

    sys.exit(main())
