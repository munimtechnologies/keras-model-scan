"""Static, dependency-free scanner for *compression-wrapped* pickle containers.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

Other scanners in this toolkit classify the opcodes of a raw *pickle stream*
(``pickle_model_scan.py``) or recognise an *archive* container such as a
``torch.save`` zip/tar (``pytorch_checkpoint_scan.py``). This module covers the
layer those both miss: a pickle that has been **compressed**, so the file no
longer begins with pickle magic and an opcode-only scanner stops at byte 0.

``joblib.dump(obj, "model.joblib", compress=("bz2", 4))`` -- the ordinary way a
scikit-learn model is saved -- writes the *compressor's* magic bytes (zlib
``78 9c``, gzip ``1f 8b``, bzip2 ``BZh``, xz ``fd 37 7a 58 5a 00``, lz4
``04 22 4d 18``) instead of the pickle ``PROTO`` opcode (``80 04``). joblib
integrates six decompression backends (zlib, gzip, bz2, lzma/xz, lz4) and peels
the wrapper transparently before unpickling, so ``joblib.load`` still executes a
``__reduce__`` payload -- while ``pickletools.genops`` fails at offset 0 and an
extension/magic router reports "no issues".

This exact evasion is documented and reproduced: a joblib-compressed
``__reduce__`` gadget bypassed picklescan 1.0.4 and ModelScan completely (0
detections) in public PoCs, and it is one of the 22 pickle loading paths
catalogued by "The Art of Hide and Seek" (USENIX Security '26, arXiv 2508.19774,
the PickleCloak framework), which chains zip/tar/gzip/zlib/bz2/lzma/xz/lz4
transforms ahead of the pickle deserialiser. ModelScan added transparent
decompression in PR #375 in response; this is the standalone equivalent for the
keras-model-scan toolkit.

The scanner peels up to ``MAX_LAYERS`` stdlib-decompressible wrappers in memory
(bounded by ``MAX_DECOMPRESSED_BYTES``), then disassembles the inner pickle with
the standard-library ``pickletools``. It never imports joblib, never writes to
disk, and never unpickles or executes anything.

Rules
-----
JLB001  high    CWE-502  A compression-wrapped stream (zlib/gzip/bz2/xz, possibly
                         nested) decompresses to a pickle that imports a
                         code-execution callable. Invisible to opcode-only
                         scanners; joblib.load would deserialise and run it.
JLB010  medium  CWE-502  A compression-wrapped stream decompresses to a real
                         pickled object graph that names nothing dangerous. Still
                         a hidden pickle a magic/extension router skips: treat the
                         compressed container as part of the threat model.
JLB012  medium  CWE-502  An lz4-frame-compressed container. lz4 is not in the
                         standard library, so this scanner cannot decompress it to
                         inspect, but joblib.load with the lz4 backend still
                         unpickles it. Decompress with lz4 and re-scan, or treat
                         the file as untrusted.

Scope note: a *bare* (uncompressed) pickle is out of scope here -- that is
``pickle_model_scan.py``'s job. This module only reports when at least one
compression wrapper was present, which is precisely the blind spot.
"""

__version__ = "0.1.0"

# Peel/size caps so a decompression bomb cannot blow up the scanner.
MAX_LAYERS = 4
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024

# Whole modules whose every attribute is a process/exec sink.
_DANGEROUS_MODULES = frozenset({
    "os", "posix", "nt", "pty", "runpy", "socket", "commands", "popen2",
})
# Modules dangerous at any sub-path depth.
_DANGEROUS_TOP = frozenset({"subprocess", "ctypes"})
# Specific (module, attribute) code-execution / deserialisation sinks.
_DANGEROUS_PAIRS = frozenset({
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"),
    ("builtins", "__import__"), ("builtins", "getattr"), ("builtins", "setattr"),
    ("builtins", "breakpoint"),
    ("__builtin__", "eval"), ("__builtin__", "exec"), ("__builtin__", "compile"),
    ("__builtin__", "__import__"), ("__builtin__", "getattr"), ("__builtin__", "apply"),
    ("importlib", "import_module"),
    ("pickle", "loads"), ("pickle", "load"),
    ("_pickle", "loads"), ("_pickle", "load"),
    ("numpy", "load"), ("numpy", "fromfile"),
    ("pandas", "read_pickle"),
    ("code", "interact"), ("code", "InteractiveInterpreter"),
    ("webbrowser", "open"),
    ("operator", "attrgetter"), ("operator", "methodcaller"),
    ("functools", "reduce"),
})

# opcodes that push a string we may later consume as a STACK_GLOBAL operand.
_STR_OPS = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})

_LZ4_MAGIC = b"\x04\x22\x4d\x18"


def _is_dangerous(module, name):
    module = module or ""
    name = name or ""
    if module in _DANGEROUS_MODULES:
        return True
    if module.split(".")[0] in _DANGEROUS_TOP:
        return True
    return (module, name) in _DANGEROUS_PAIRS


def _finding(rule, severity, cve, cwe, message, evidence):
    return {
        "rule": rule,
        "severity": severity,
        "cve": cve,
        "cwe": cwe,
        "message": message,
        "evidence": evidence,
    }


def _bounded(decompressor, data):
    """Run a stdlib incremental decompressor over data, capped at
    MAX_DECOMPRESSED_BYTES. Returns the (possibly partial) output, or None if the
    stream is not this codec."""
    try:
        try:
            out = decompressor.decompress(data, MAX_DECOMPRESSED_BYTES)
        except TypeError:
            # Older decompressor without a max_length parameter.
            out = decompressor.decompress(data)[:MAX_DECOMPRESSED_BYTES]
    except Exception:
        return None
    return out or None


def _decompress_one(data):
    """If data begins with a stdlib-decompressible compressor stream, peel one
    layer and return (codec, out_bytes); otherwise (None, None)."""
    if not data or len(data) < 2:
        return None, None
    b0, b1 = data[0], data[1]

    # gzip (RFC 1952): 1f 8b
    if b0 == 0x1F and b1 == 0x8B:
        import zlib
        out = _bounded(zlib.decompressobj(31), data)
        return ("gzip", out) if out is not None else (None, None)

    # bzip2: 'BZh'
    if data[:3] == b"BZh":
        import bz2
        out = _bounded(bz2.BZ2Decompressor(), data)
        return ("bz2", out) if out is not None else (None, None)

    # xz (unambiguous 6-byte magic; the 'alone' lzma format is not matched on
    # purpose, as its 0x5d first byte collides with the pickle EMPTY_LIST opcode)
    if data[:6] == b"\xfd7zXZ\x00":
        import lzma
        out = _bounded(lzma.LZMADecompressor(), data)
        return ("xz", out) if out is not None else (None, None)

    # zlib (RFC 1950): CM=deflate and a header checksum divisible by 31.
    if (b0 & 0x0F) == 0x08 and (((b0 << 8) | b1) % 31 == 0):
        import zlib
        out = _bounded(zlib.decompressobj(15), data)
        return ("zlib", out) if out is not None else (None, None)

    return None, None


def _peel(data):
    """Peel up to MAX_LAYERS compression wrappers. Returns (codecs, inner)."""
    codecs = []
    cur = data
    for _ in range(MAX_LAYERS):
        codec, out = _decompress_one(cur)
        if codec is None or out is None:
            break
        codecs.append(codec)
        cur = out
    return codecs, cur


def _scan_pickle_ops(data):
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


def _looks_like_pickle(data):
    if not data:
        return False
    import pickletools  # lazy; stdlib only

    n = 0
    try:
        for _op, _arg, _pos in pickletools.genops(data):
            n += 1
            if n >= 3:
                break
    except Exception:
        pass
    return n >= 2


def _evidence(chain, name, globals_list):
    imports = ", ".join(
        ("%s.%s" % (m, n)) if n else (m or "?") for m, n in globals_list[:8]
    )
    return "codec=%s; name=%s; imports=%s" % (
        chain, name or "<bytes>", imports or "(none)")


def scan_bytes(data, name=""):
    """Scan raw bytes. Returns a list of finding dicts (possibly empty)."""
    findings = []
    if not data:
        return findings

    # lz4 frame: not stdlib-decompressible, but joblib's lz4 backend reads it.
    if data[:4] == _LZ4_MAGIC:
        findings.append(_finding(
            "JLB012", "medium", "", "CWE-502",
            "lz4-frame-compressed container. lz4 is not in the standard library, "
            "so this scanner cannot decompress it to inspect, but joblib.load "
            "with the lz4 backend still unpickles it. Decompress with lz4 and "
            "re-scan the inner pickle, or treat this file as untrusted.",
            "codec=lz4-frame (not stdlib-decompressible); name=%s" % (name or "<bytes>")))
        return findings

    codecs, inner = _peel(data)
    if not codecs:
        # No compression wrapper present: a bare pickle is out of scope here.
        return findings

    chain = "+".join(codecs)
    dangerous, all_globals = _scan_pickle_ops(inner)
    if dangerous:
        findings.append(_finding(
            "JLB001", "high", "", "CWE-502",
            "Compression-wrapped pickle imports a code-execution callable. The "
            "file begins with compressor magic, not pickle magic, so opcode-only "
            "scanners stop at offset 0 and report nothing; joblib.load peels the "
            "wrapper and deserialises the pickle, executing it. Do not load this "
            "file.",
            _evidence(chain, name, dangerous)))
    elif _looks_like_pickle(inner) and all_globals:
        findings.append(_finding(
            "JLB010", "medium", "", "CWE-502",
            "Compression-wrapped pickle (a real pickled object graph with no "
            "dangerous import found). The compressor magic hides the pickle from "
            "a magic/extension router; joblib.load still unpickles it. Treat the "
            "compressed container as part of the threat model and prefer a "
            "non-executable format (e.g. safetensors).",
            _evidence(chain, name, all_globals)))
    return findings


def scan_file(path):
    """Read a file and scan it. Raises OSError if it cannot be read."""
    import os

    with open(path, "rb") as fh:
        data = fh.read()
    return scan_bytes(data, name=os.path.basename(path))


def main(argv=None):
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write(
            "usage: joblib_pickle_scan.py <file.joblib|.pkl.gz|.pkl.z> [<file> ...]\n")
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
