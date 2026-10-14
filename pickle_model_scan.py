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
import os
import pickletools
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass

__version__ = "0.1.1"

# Modules whose presence in a pickle is a direct code-execution concern.
DANGEROUS_MODULES = frozenset({
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

STRING_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})
MEMO_GET_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})
EXEC_OPCODES = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"})

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

PICKLE_EXTS = frozenset({
    ".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin", ".model", ".ckpt",
    ".dat", ".pck", ".pt2",
})


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
    """Return one of 'dangerous', 'gadget', 'benign', 'unknown' for a global ref."""
    module = module or ""
    name = name or ""
    top = module.split(".", 1)[0]
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


def scan_pickle_bytes(data, source):
    """Disassemble a pickle opcode stream and flag dangerous patterns.

    Uses pickletools.genops, which reads opcodes without unpickling. Never
    imports, executes, or reconstructs any object from the data.
    """
    findings = []
    recent = []          # operand candidates: ('str', value) or ('memo', None)
    globals_found = []   # (module, name, pos, resolvable)
    exec_ops = 0

    try:
        for opcode, arg, pos in pickletools.genops(data):
            name = opcode.name
            if name in STRING_OPCODES:
                recent.append(("str", arg))
            elif name in MEMO_GET_OPCODES:
                recent.append(("memo", None))
            if name in EXEC_OPCODES:
                exec_ops += 1
            if name in ("GLOBAL", "INST"):
                mod, _, fn = (arg or "").partition(" ")
                globals_found.append((mod, fn, pos, True))
            elif name == "STACK_GLOBAL":
                last_two = recent[-2:]
                if (len(last_two) == 2 and last_two[0][0] == "str"
                        and last_two[1][0] == "str"):
                    globals_found.append((last_two[0][1], last_two[1][1], pos, True))
                else:
                    globals_found.append((None, None, pos, False))
    except Exception as exc:  # truncated / malformed stream
        findings.append(Finding(
            "PKL000", "LOW", "Pickle stream could not be fully parsed",
            f"pickletools stopped reading at an opcode: {exc}. Part of the stream "
            "was not analysed; treat the file with caution.", source))

    for mod, fn, pos, resolvable in globals_found:
        loc = f"{source} @ byte {pos}"
        if not resolvable:
            findings.append(Finding(
                "PKL007", "HIGH", "Unresolved STACK_GLOBAL operands",
                "A STACK_GLOBAL opcode's module/name could not be resolved from the "
                "two preceding string literals (the operands come from the memo or are "
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
