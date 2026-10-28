#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Detect NumPy ``.npy`` / ``.npz`` object-array deserialization sinks.

Part of ``munimtechnologies/keras-model-scan`` (Apache-2.0). Static and
read-only: this module parses the NumPy array-file header and, for object
arrays, inspects the trailing pickle stream with :mod:`pickletools` opcode
disassembly only. It never imports ``numpy`` and never unpickles or executes
anything.

Why this matters
----------------
The ``.npy`` binary format stores plain numeric arrays as raw contiguous
bytes, but an *object* array (``dtype.hasobject is True``, e.g. ``descr`` of
``'|O'``) is serialized by writing a **Python pickle** of the array into the
data section. Loading such a file therefore requires ``numpy.load`` to be
called with ``allow_pickle=True`` -- and doing so on an untrusted file
unpickles attacker-controlled bytes, which is equivalent to running
``eval()`` on the file. ``.npz`` is a ZIP archive of ``.npy`` members, so the
same risk applies to any object-array member inside it.

This is tracked as **CVE-2019-6446** (CWE-502, CVSS 9.8): NumPy before 1.16.3
used pickle by default when loading, so a crafted ``.npy``/``.npz`` could
execute arbitrary code. NumPy 1.16.3 flipped ``allow_pickle`` to default
``False``, but any caller that re-enables it (or runs an old NumPy) is still
exposed. A model shipped as an object-array ``.npy``/``.npz`` can only be
loaded by re-enabling pickle, so flagging these files before they are loaded
is the point of this scanner.

Rules
-----
``NPY001`` (high): the file is an object-array ``.npy`` (or a ``.npz`` with an
object-array member). Its data section is an untrusted pickle; loading it
requires ``allow_pickle=True``. Object dtypes nested inside a *structured*
dtype (e.g. ``[('a', '<f8'), ('b', '|O')]``) are detected too.

``NPY002`` (high): the pickle data section of an object array contains
code-execution opcodes (``GLOBAL``/``STACK_GLOBAL``/``REDUCE``/``BUILD``/...).
The imported globals are reported, derived from opcode disassembly only; the
pickle is never executed.
"""

from __future__ import annotations

import struct
import sys
import zipfile
import ast
import io

__version__ = "0.1.0"

# Magic prefix of every NumPy array file (numpy.lib.format).
_NPY_MAGIC = b"\x93NUMPY"
# Local-file-header signature of a ZIP container (a .npz is a ZIP of .npy).
_ZIP_MAGIC = b"PK\x03\x04"

# Pickle opcodes that can drive code execution while a pickle is unpickled.
_EXEC_OPCODES = frozenset(
    {
        "GLOBAL",
        "STACK_GLOBAL",
        "REDUCE",
        "BUILD",
        "INST",
        "OBJ",
        "NEWOBJ",
        "NEWOBJ_EX",
    }
)

# Opcodes that push a string literal (candidate module/attr names for a
# following STACK_GLOBAL).
_STRING_OPCODES = frozenset(
    {
        "SHORT_BINUNICODE",
        "BINUNICODE",
        "BINUNICODE8",
        "SHORT_BINSTRING",
        "BINSTRING",
        "UNICODE",
        "STRING",
    }
)


def _finding(rule, severity, cve, cwe, message, evidence):
    """Build a finding dict in the shape the repo's scanners use."""
    return {
        "rule": rule,
        "severity": severity,
        "cve": cve,
        "cwe": cwe,
        "message": message,
        "evidence": evidence,
    }


def _is_object_descr(descr):
    """Return True if a NumPy ``descr`` carries an object (pickle) dtype.

    ``descr`` is either a dtype string (e.g. ``'<f8'``, ``'|O'``) or a list of
    ``(name, dtype[, shape])`` tuples for a structured dtype, which may nest.
    The object type character is ``'O'`` after any byte-order prefix.
    """
    if isinstance(descr, str):
        return descr.lstrip("<>=|")[:1] == "O"
    if isinstance(descr, (list, tuple)):
        for field in descr:
            # A structured field is (name, dtype) or (name, dtype, shape);
            # a bare nested descr list is handled by the recursion too.
            if isinstance(field, (list, tuple)) and len(field) >= 2:
                if _is_object_descr(field[1]):
                    return True
            elif _is_object_descr(field):
                return True
    return False


def _parse_npy_header(data):
    """Parse a ``.npy`` buffer's header.

    Returns ``(header_dict, data_offset)`` or ``None`` if ``data`` is not a
    parseable ``.npy`` buffer. Never raises on malformed input.
    """
    if len(data) < 10 or data[:6] != _NPY_MAGIC:
        return None
    major = data[6]
    try:
        if major == 1:
            (hlen,) = struct.unpack("<H", data[8:10])
            header_start = 10
        else:
            if len(data) < 12:
                return None
            (hlen,) = struct.unpack("<I", data[8:12])
            header_start = 12
    except struct.error:
        return None
    header_bytes = data[header_start:header_start + hlen]
    if len(header_bytes) < hlen:
        return None
    try:
        header = ast.literal_eval(header_bytes.decode("latin-1"))
    except (ValueError, SyntaxError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict):
        return None
    return header, header_start + hlen


def _pickle_report(data):
    """Disassemble a pickle stream without executing it.

    Returns ``(has_exec, globals_found)``: whether a code-execution opcode is
    present and the module/attr pairs referenced by GLOBAL/STACK_GLOBAL.
    """
    try:
        import pickletools  # local import: disassembly only, never executes
    except Exception:  # pragma: no cover - pickletools is stdlib
        return False, []
    has_exec = False
    globals_found = []
    recent = []
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            name = opcode.name
            if name in _STRING_OPCODES and isinstance(arg, (str, bytes)):
                recent.append(arg.decode("latin-1") if isinstance(arg, bytes) else arg)
                recent = recent[-4:]
            if name == "GLOBAL" and arg:
                globals_found.append(str(arg).replace("\n", "."))
            elif name == "STACK_GLOBAL":
                if len(recent) >= 2:
                    globals_found.append("%s.%s" % (recent[-2], recent[-1]))
                else:
                    globals_found.append("STACK_GLOBAL")
            if name in _EXEC_OPCODES:
                has_exec = True
    except Exception:
        # Truncated or invalid pickle stream: report what we saw so far.
        pass
    return has_exec, globals_found


def _scan_one_npy(data, name):
    """Scan a single ``.npy`` buffer; return a list of findings."""
    findings = []
    parsed = _parse_npy_header(data)
    if parsed is None:
        return findings
    header, offset = parsed
    descr = header.get("descr")
    if not _is_object_descr(descr):
        return findings
    findings.append(
        _finding(
            "NPY001",
            "high",
            "CVE-2019-6446",
            "CWE-502",
            "object-dtype array in %s: its data section is an untrusted Python "
            "pickle, so loading requires allow_pickle=True (equivalent to eval "
            "on the file)" % name,
            "descr=%r" % (descr,),
        )
    )
    has_exec, globals_found = _pickle_report(data[offset:])
    if has_exec:
        detail = "globals: %s" % (", ".join(globals_found) if globals_found else "(none decoded)")
        findings.append(
            _finding(
                "NPY002",
                "high",
                "CVE-2019-6446",
                "CWE-502",
                "pickle data section of object array in %s contains "
                "code-execution opcodes" % name,
                "exec opcode present; %s" % detail,
            )
        )
    return findings


def scan_bytes(data, name="<bytes>"):
    """Scan raw ``.npy`` or ``.npz`` bytes; return a list of findings."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data = bytes(data)
    if data[:6] == _NPY_MAGIC:
        return _scan_one_npy(data, name)
    if data[:4] == _ZIP_MAGIC:
        findings = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                members = [m for m in zf.namelist() if m.lower().endswith(".npy")]
                for member in members:
                    try:
                        member_bytes = zf.read(member)
                    except Exception:
                        continue
                    findings.extend(
                        _scan_one_npy(member_bytes, "%s::%s" % (name, member))
                    )
        except zipfile.BadZipFile:
            return findings
        return findings
    return []


def scan_file(path):
    """Read ``path`` and scan it; return a list of findings."""
    with open(path, "rb") as fh:
        data = fh.read()
    return scan_bytes(data, name=path)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: numpy_npy_scan.py FILE [FILE ...]\n")
        return 2
    worst = 0
    for path in argv:
        try:
            findings = scan_file(path)
        except OSError as exc:
            sys.stderr.write("error: %s: %s\n" % (path, exc))
            worst = max(worst, 2)
            continue
        if not findings:
            print("OK (no object-array pickle sink found): %s" % path)
            continue
        for f in findings:
            print(
                "%s %s %s %s - %s [%s]"
                % (
                    f["severity"].upper(),
                    f["rule"],
                    f["cve"],
                    f["cwe"],
                    f["message"],
                    f["evidence"],
                )
            )
        if any(f["severity"] == "high" for f in findings):
            worst = max(worst, 1)
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
