"""torch_storage_scan — static detector for the PyTorch ``weights_only`` checkpoint
bypass class, CVE-2026-24747 (NVD totalResults=1, CVSS 3.1 8.8 HIGH,
AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, CWE-94 + CWE-502, fixed in torch 2.10.0;
GHSA-63cw-57p8-fm3p).

CVE-2026-24747: PyTorch's ``weights_only=True`` unpickler "failed to properly
validate pickle opcodes and storage metadata." Two signals are present AT REST in
a crafted ``.pth``/``.pt`` checkpoint, independent of the dangerous-GLOBAL/REDUCE
import class that pickle_model_scan already covers (and which weights_only=True
already blocks):

  1. Storage size mismatch — a ``torch`` zip checkpoint stores each tensor's raw
     bytes in ``archive/data/<key>`` and declares the element count (numel) in the
     storage persistent_id tuple ``('storage', storage_type, key, location, numel)``
     inside ``data.pkl``. If the declared ``numel * element_size`` exceeds the real
     size of the backing zip member, the loader reads past the buffer (heap OOB).
  2. ``SETITEM`` / ``SETITEMS`` applied to a non-dict object — heap memory
     corruption. These opcodes are only legitimately emitted against dicts; a
     crafted stream points them at a list/tuple/other type.

This scanner reads bytes only. It parses the zip container and the ``data.pkl``
pickle *opcode stream* with ``pickletools.genops`` and a minimal, non-executing
stack simulator. It NEVER imports torch, NEVER unpickles, NEVER allocates the
declared storage, NEVER reads tensor data payloads. It flags a malformed/malicious
checkpoint that would trip the loader; it does not and cannot prove the C-level
corruption itself.

Rule IDs:
  TWS001 (HIGH)    storage declares numel*elem_size larger than its backing
                   ``data/<key>`` member — out-of-bounds read (CVE-2026-24747).
  TWS002 (MEDIUM)  storage persistent_id references a ``data/<key>`` member that
                   is absent from the archive — dangling/forged storage reference.
  TWS003 (HIGH)    SETITEM/SETITEMS targets a non-dict stack object — heap
                   corruption opcode misuse (CVE-2026-24747).
  TWS010 (INFO)    not a torch checkpoint we can fully analyze (not a zip with a
                   data.pkl, legacy non-zip pickle with storage check skipped, an
                   unmodeled opcode so simulation was aborted, or a parse error).
  TWS000 (INFO)    analyzed; no storage mismatch or opcode misuse found.

Apache-2.0. Made with AI agents working in the name of MV2, Munim, Inc.
"""

from __future__ import annotations

import io
import pickletools
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0"

# ``torch`` storage class name -> element size in bytes. Conservative: an unknown
# storage type means we skip the numel*size compare rather than risk a false
# positive. Covers the classic typed-storage classes torch still emits in pids.
_STORAGE_ELEM_SIZE: Dict[str, int] = {
    "DoubleStorage": 8,
    "FloatStorage": 4,
    "HalfStorage": 2,
    "BFloat16Storage": 2,
    "LongStorage": 8,
    "IntStorage": 4,
    "ShortStorage": 2,
    "CharStorage": 1,
    "ByteStorage": 1,
    "BoolStorage": 1,
    "ComplexDoubleStorage": 16,
    "ComplexFloatStorage": 8,
    "QInt8Storage": 1,
    "QUInt8Storage": 1,
    "QInt32Storage": 4,
    "Float8_e4m3fnStorage": 1,
    "Float8_e5m2Storage": 1,
}

# Cap simulator work so a crafted file cannot make us loop forever.
_MAX_OPS = 2_000_000


class _Mark:
    """MARK sentinel on the pickle stack."""

    __slots__ = ()


_MARK = _Mark()


@dataclass
class _Global:
    module: str
    name: str


@dataclass
class _Dict:
    """A stack object known to be a dict (SETITEM target is legitimate)."""

    __slots__ = ()


@dataclass
class _Obj:
    """An opaque stack object (REDUCE/NEWOBJ/BUILD result, or an item we don't
    model precisely). SETITEM against one of these is suspicious."""

    __slots__ = ()


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    detail: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "detail": self.detail,
        }


class _Aborted(Exception):
    """Raised when the stream uses an opcode we do not model; we stop simulating
    and report TWS010 rather than risk a desynchronized stack (false positives)."""


# Opcodes whose only stack effect is to push one literal value already decoded by
# genops into ``op.arg`` (strings, bytes, ints, floats).
_PUSH_ARG = {
    "BININT", "BININT1", "BININT2", "INT", "LONG", "LONG1", "LONG4",
    "BINFLOAT", "FLOAT",
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
    "SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "BYTEARRAY8",
}


def _pop_to_mark(stack: List[Any]) -> List[Any]:
    items: List[Any] = []
    while stack:
        top = stack.pop()
        if top is _MARK:
            items.reverse()
            return items
        items.append(top)
    raise _Aborted("stack underflow: no MARK")


def _simulate(data: bytes) -> Tuple[List[Tuple[Any, Any, Any, Any]], List[Finding]]:
    """Walk the pickle opcode stream without executing it.

    Returns (storages, findings) where ``storages`` is a list of
    (storage_type, key, location, numel) tuples recovered from BINPERSID, and
    ``findings`` holds any SETITEM/SETITEMS-on-non-dict findings. Raises
    ``_Aborted`` on an unmodeled opcode or structural underflow.
    """
    stack: List[Any] = []
    memo: Dict[int, Any] = {}
    storages: List[Tuple[Any, Any, Any, Any]] = []
    findings: List[Finding] = []
    n_ops = 0

    for op, arg, _pos in pickletools.genops(data):
        n_ops += 1
        if n_ops > _MAX_OPS:
            raise _Aborted("opcode budget exceeded")
        name = op.name

        if name in ("PROTO", "FRAME", "STOP"):
            if name == "STOP":
                break
            continue
        elif name == "MARK":
            stack.append(_MARK)
        elif name in _PUSH_ARG:
            stack.append(arg)
        elif name == "NONE":
            stack.append(None)
        elif name == "NEWTRUE":
            stack.append(True)
        elif name == "NEWFALSE":
            stack.append(False)
        elif name == "EMPTY_DICT":
            stack.append(_Dict())
        elif name == "DICT":
            _pop_to_mark(stack)
            stack.append(_Dict())
        elif name == "EMPTY_LIST":
            stack.append(_Obj())
        elif name == "LIST":
            _pop_to_mark(stack)
            stack.append(_Obj())
        elif name in ("EMPTY_SET",):
            stack.append(_Obj())
        elif name == "FROZENSET":
            _pop_to_mark(stack)
            stack.append(_Obj())
        elif name == "EMPTY_TUPLE":
            stack.append(())
        elif name == "TUPLE":
            items = _pop_to_mark(stack)
            stack.append(tuple(items))
        elif name == "TUPLE1":
            a = stack.pop()
            stack.append((a,))
        elif name == "TUPLE2":
            b = stack.pop(); a = stack.pop()
            stack.append((a, b))
        elif name == "TUPLE3":
            c = stack.pop(); b = stack.pop(); a = stack.pop()
            stack.append((a, b, c))
        elif name == "GLOBAL":
            mod, _, qn = (arg or "").partition(" ")
            stack.append(_Global(mod, qn))
        elif name == "STACK_GLOBAL":
            qn = stack.pop(); mod = stack.pop()
            stack.append(_Global(str(mod), str(qn)))
        elif name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST"):
            # Consume operands per opcode, push an opaque object.
            if name == "REDUCE":
                stack.pop()  # arg tuple
                stack.pop()  # callable
            elif name == "NEWOBJ":
                stack.pop(); stack.pop()
            elif name == "NEWOBJ_EX":
                stack.pop(); stack.pop(); stack.pop()
            elif name == "OBJ":
                _pop_to_mark(stack)
            elif name == "INST":
                _pop_to_mark(stack)
            stack.append(_Obj())
        elif name == "BUILD":
            stack.pop()  # state; obj stays on stack
        elif name == "APPEND":
            stack.pop()  # value; target stays
        elif name == "APPENDS":
            _pop_to_mark(stack)  # values; target stays
        elif name == "ADDITEMS":
            _pop_to_mark(stack)
        elif name == "SETITEM":
            stack.pop()  # value
            stack.pop()  # key
            target = stack[-1] if stack else None
            if not isinstance(target, _Dict):
                findings.append(Finding(
                    "TWS003", "HIGH",
                    "SETITEM applied to a non-dict object (heap corruption "
                    "opcode misuse, CVE-2026-24747)",
                    {"target_type": type(target).__name__},
                ))
        elif name == "SETITEMS":
            _pop_to_mark(stack)  # k/v pairs
            target = stack[-1] if stack else None
            if not isinstance(target, _Dict):
                findings.append(Finding(
                    "TWS003", "HIGH",
                    "SETITEMS applied to a non-dict object (heap corruption "
                    "opcode misuse, CVE-2026-24747)",
                    {"target_type": type(target).__name__},
                ))
        elif name in ("BINPUT", "PUT", "LONG_BINPUT"):
            if stack:
                memo[int(arg)] = stack[-1]
        elif name == "MEMOIZE":
            if stack:
                memo[len(memo)] = stack[-1]
        elif name in ("BINGET", "GET", "LONG_BINGET"):
            stack.append(memo.get(int(arg), _Obj()))
        elif name == "POP":
            if stack:
                stack.pop()
        elif name == "POP_MARK":
            _pop_to_mark(stack)
        elif name == "DUP":
            if stack:
                stack.append(stack[-1])
        elif name == "BINPERSID":
            pid = stack.pop() if stack else None
            _maybe_record_storage(pid, storages)
            stack.append(_Obj())  # BINPERSID leaves the loaded object on the stack
        elif name == "PERSID":
            # pid given as the opcode arg string; not a storage tuple form.
            stack.append(_Obj())
        elif name in ("EXT1", "EXT2", "EXT4"):
            stack.append(_Obj())
        else:
            raise _Aborted(f"unmodeled opcode {name}")

    return storages, findings


def _maybe_record_storage(pid: Any, storages: List) -> None:
    if not isinstance(pid, tuple) or len(pid) < 5:
        return
    if pid[0] != "storage":
        return
    storages.append((pid[1], pid[2], pid[3], pid[4]))


def _storage_elem_size(storage_type: Any) -> Optional[int]:
    """Element size in bytes for a storage type reference, or None if unknown."""
    name: Optional[str] = None
    if isinstance(storage_type, _Global):
        name = storage_type.name
    elif isinstance(storage_type, str):
        name = storage_type.rsplit(".", 1)[-1]
    if name is None:
        return None
    return _STORAGE_ELEM_SIZE.get(name)


def _find_data_member(names: List[str], key: Any) -> Optional[str]:
    """Return the zip member holding storage ``key`` (``.../data/<key>``)."""
    key_s = str(key)
    suffix = "/data/" + key_s
    for nm in names:
        if nm.endswith(suffix) or nm == "data/" + key_s:
            return nm
    return None


def scan_bytes(data: bytes) -> List[Dict[str, Any]]:
    """Scan raw checkpoint bytes. Returns a list of finding dicts."""
    # Case 1: a torch zip checkpoint (default torch.save format since 1.6).
    if zipfile.is_zipfile(io.BytesIO(data)):
        return _scan_zip(data)

    # Case 2: a legacy non-zip pickle (torch.save with _use_new_zipfile=False, or
    # a bare .pkl). We can still run the opcode-misuse check; no storage files
    # exist to size-check.
    if data[:1] == b"\x80" or (data[:1] in (b"(", b"c", b"]", b"}")):
        try:
            _storages, findings = _simulate(data)
        except _Aborted as exc:
            return [Finding("TWS010", "INFO",
                            "legacy pickle not fully analyzed: " + str(exc),
                            {}).as_dict()]
        if findings:
            return [f.as_dict() for f in findings]
        return [Finding("TWS010", "INFO",
                        "legacy non-zip pickle; opcode check clean, storage "
                        "size check not applicable", {}).as_dict()]

    return [Finding("TWS010", "INFO",
                    "not a torch checkpoint (not a zip and not a pickle stream)",
                    {}).as_dict()]


def _scan_zip(data: bytes) -> List[Dict[str, Any]]:
    findings: List[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception as exc:  # noqa: BLE001 - report, never raise
        return [Finding("TWS010", "INFO",
                        "could not open zip: " + str(exc), {}).as_dict()]

    pkl_name = None
    for nm in names:
        if nm.endswith("data.pkl") or nm.endswith(".pkl"):
            pkl_name = nm
            break
    if pkl_name is None:
        return [Finding("TWS010", "INFO",
                        "zip has no data.pkl; not a torch checkpoint",
                        {}).as_dict()]

    try:
        pkl = zf.read(pkl_name)
    except Exception as exc:  # noqa: BLE001
        return [Finding("TWS010", "INFO",
                        "could not read " + pkl_name + ": " + str(exc),
                        {}).as_dict()]

    try:
        storages, op_findings = _simulate(pkl)
    except _Aborted as exc:
        return [Finding("TWS010", "INFO",
                        "pickle not fully analyzed: " + str(exc), {}).as_dict()]

    findings.extend(op_findings)

    size_by_name = {zi.filename: zi.file_size for zi in zf.infolist()}
    for storage_type, key, _location, numel in storages:
        elem = _storage_elem_size(storage_type)
        if elem is None or not isinstance(numel, int) or numel < 0:
            continue
        declared = numel * elem
        member = _find_data_member(names, key)
        if member is None:
            findings.append(Finding(
                "TWS002", "MEDIUM",
                "storage key has no backing data member in the archive",
                {"key": str(key), "declared_bytes": declared},
            ))
            continue
        actual = size_by_name.get(member, 0)
        if declared > actual:
            findings.append(Finding(
                "TWS001", "HIGH",
                "storage declares more bytes than its backing data member holds "
                "(out-of-bounds read, CVE-2026-24747)",
                {"key": str(key), "member": member,
                 "declared_bytes": declared, "actual_bytes": actual,
                 "numel": numel, "elem_size": elem},
            ))

    if not findings:
        return [Finding("TWS000", "INFO",
                        "torch checkpoint analyzed; no storage mismatch or "
                        "opcode misuse found",
                        {"storages_checked": len(storages)}).as_dict()]
    return [f.as_dict() for f in findings]


def scan_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "rb") as fh:
        return scan_bytes(fh.read())


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    for p in sys.argv[1:]:
        print(p)
        print(json.dumps(scan_file(p), indent=2))
