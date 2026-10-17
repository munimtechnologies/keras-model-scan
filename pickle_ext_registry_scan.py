#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Part of keras-model-scan. Made with AI by MV2 of Munim, Inc.
"""Static detector for the pickle *extension-registry redirect* vector.

Pickle protocol 2+ can resolve a global through the ``copyreg`` extension
registry using the opcodes ``EXT1`` / ``EXT2`` / ``EXT4``. These opcodes carry
only a small integer *code*; the module and qualified name they resolve to are
looked up at unpickle time in ``copyreg._extension_registry`` (populated by
``copyreg.add_extension`` or by mutating ``copyreg._inverted_registry``). The
resolved global's name therefore never appears as text in the pickle stream.

A scanner that flags dangerous *imports by name* (GLOBAL / STACK_GLOBAL operands)
is blind to this: an ``EXT`` opcode can resolve to ``os.system`` without the
string ``os`` or ``system`` ever being present. Published evaluations find that
every open-source pickle scanner tested (picklescan, ModelScan, fickling) misses
this vector -- ModelScan parses the stream but does not model the behaviour
(100% false-negative), and fickling can crash on the EXT opcodes
(DITTO, arXiv:2610.10735, "Context-aware Pickle-based Pre-Trained Model
Scanner", 2026). keras-model-scan's own pickle_model_scan did not inspect the
extension registry either; this module closes that gap.

Legitimate ML serializers (``torch.save``, numpy, scikit-learn / joblib) do not
emit EXT opcodes and do not mutate the extension registry, so their presence in
a model file is a strong signal and worth a human look before loading.

Detection is purely static: the stream is walked with ``pickletools.genops``,
which decodes opcodes **without executing** the pickle. No registry lookup is
performed; the mere *use* of the mechanism is what is reported.

Findings:
  PXR001  CRITICAL  pickle imports a copyreg extension-registry mutator
                    (add_extension / remove_extension / clear_extension_cache /
                    _inverted_registry / _extension_registry): it can rewire a
                    later EXT opcode to an arbitrary global at unpickle time.
  PXR002  HIGH      pickle uses an extension-registry opcode (EXT1/EXT2/EXT4):
                    the global it resolves is not named in the stream, so a
                    names-only scanner cannot see what it imports.
  PXR000  LOW       a file that looks like a pickle could not be fully parsed
                    (truncated or deliberately malformed to defeat scanning).

Usage:
    python pickle_ext_registry_scan.py MODEL.pkl [MORE ...]

Exit code is 1 if any finding is reported, else 0.
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
import zipfile
import pickletools

__version__ = "0.1.0"

# Opcodes whose decoded arg is a string we may later pair into a STACK_GLOBAL.
_STRING_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})

# copyreg names that read or mutate the extension registry.
_REGISTRY_NAMES = frozenset({
    "add_extension", "remove_extension", "clear_extension_cache",
    "_inverted_registry", "_extension_registry",
})

_COPYREG_MODULES = frozenset({"copyreg", "copy_reg"})

_EXT_OPCODES = frozenset({"EXT1", "EXT2", "EXT4"})

# A member of an archive is only treated as a pickle candidate if it looks like
# one, so we don't try to parse tensor/data blobs.
_PICKLE_SUFFIXES = (".pkl", ".pickle", ".pck", ".pt", ".bin", ".data")


def _as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1", "replace")
    return str(value)


def _looks_like_pickle(data: bytes, name: str = "") -> bool:
    if not data:
        return False
    # PROTO opcode (0x80) begins every protocol-2+ pickle.
    if data[0] == 0x80:
        return True
    lname = name.lower()
    return lname.endswith(_PICKLE_SUFFIXES)


def scan_pickle_bytes(data: bytes, source: str) -> list:
    """Return findings for a single pickle byte stream."""
    findings = []
    recent: list = []  # last string operands pushed, for STACK_GLOBAL pairing
    try:
        for opcode, arg, pos in pickletools.genops(data):
            name = opcode.name
            if name in _STRING_OPCODES:
                recent.append(_as_text(arg))
                if len(recent) > 4:
                    del recent[:-4]
                continue
            if name in _EXT_OPCODES:
                findings.append({
                    "id": "PXR002",
                    "severity": "HIGH",
                    "source": source,
                    "pos": pos,
                    "opcode": name,
                    "ext_code": arg,
                    "message": (
                        "pickle uses extension-registry opcode %s (code %s): the "
                        "global it resolves is looked up in the copyreg extension "
                        "registry and is not named in the stream; a names-only "
                        "scanner cannot see what it imports. Legitimate ML "
                        "serializers do not emit EXT opcodes." % (name, arg)
                    ),
                })
                continue
            module = qname = None
            if name == "GLOBAL":
                module, _, qname = _as_text(arg).partition(" ")
            elif name == "STACK_GLOBAL" and len(recent) >= 2:
                module, qname = recent[-2], recent[-1]
            if module in _COPYREG_MODULES and qname in _REGISTRY_NAMES:
                findings.append({
                    "id": "PXR001",
                    "severity": "CRITICAL",
                    "source": source,
                    "pos": pos,
                    "opcode": name,
                    "import": "%s.%s" % (module, qname),
                    "message": (
                        "pickle imports copyreg.%s, which reads or mutates the "
                        "extension registry; it can rewire a later EXT1/EXT2/EXT4 "
                        "opcode to resolve to an arbitrary global (e.g. os.system) "
                        "at unpickle time, with no dangerous name in the stream."
                        % qname
                    ),
                })
    except Exception as exc:  # pragma: no cover - defensive
        findings.append({
            "id": "PXR000",
            "severity": "LOW",
            "source": source,
            "pos": None,
            "opcode": None,
            "message": (
                "a file that looks like a pickle could not be fully parsed "
                "(%s: %s); it may be truncated or deliberately malformed to "
                "defeat static scanning." % (type(exc).__name__, exc)
            ),
        })
    return findings


def _iter_archive_members(path: str):
    """Yield (member_name, bytes) for pickle-looking members of a zip/tar."""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    try:
                        data = zf.read(info)
                    except Exception:
                        continue
                    if _looks_like_pickle(data, info.filename):
                        yield info.filename, data
            return
    except Exception:
        pass
    try:
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    try:
                        fh = tf.extractfile(member)
                        data = fh.read() if fh is not None else b""
                    except Exception:
                        continue
                    if _looks_like_pickle(data, member.name):
                        yield member.name, data
            return
    except Exception:
        pass


def scan_file(path: str) -> list:
    """Return findings for a file: a raw pickle, or pickle members of an archive."""
    findings = []
    is_archive = False
    try:
        is_archive = zipfile.is_zipfile(path) or tarfile.is_tarfile(path)
    except Exception:
        is_archive = False

    if is_archive:
        for name, data in _iter_archive_members(path):
            findings.extend(scan_pickle_bytes(data, "%s::%s" % (path, name)))
        return findings

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return [{
            "id": "PXR000", "severity": "LOW", "source": path, "pos": None,
            "opcode": None,
            "message": "could not read file (%s)." % exc,
        }]
    if _looks_like_pickle(data, path):
        findings.extend(scan_pickle_bytes(data, path))
    return findings


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    results = []
    any_finding = False
    for path in argv:
        findings = scan_file(path)
        if findings:
            any_finding = True
        results.append({"file": path, "findings": findings})
    print(json.dumps({
        "tool": "pickle_ext_registry_scan",
        "version": __version__,
        "results": results,
    }, indent=2))
    return 1 if any_finding else 0


if __name__ == "__main__":
    raise SystemExit(main())
