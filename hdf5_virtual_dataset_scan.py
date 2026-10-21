# hdf5_virtual_dataset_scan.py
# Static detector for the Keras HDF5 Virtual Dataset (VDS) arbitrary-file-read class
# (CVE-2026-12480, CWE-73, keras <= 3.13.2; an incomplete fix of CVE-2026-1669). A
# crafted .keras / .h5 file can carry a dataset whose Data Layout message declares
# layout class 3 (virtual); the VDS mapping (global heap) names external HDF5 files on
# the victim's disk, which load_model() reads transparently because the code never
# checks dataset.is_virtual. This reads HDF5 / zip HEADER bytes only; it never imports
# keras/h5py, never calls load_model, never opens a dataset, and never reads a VDS
# source file. It flags a written-out virtual layout (version-4 Data Layout message,
# layout class 3) whose global-heap pointer resolves to a real GCOL collection (HIGH),
# or an unconfirmed candidate (INFO). Sibling of hdf5_external_storage_scan, which
# covers external-storage datasets and external links but explicitly not VDS.
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.
from __future__ import annotations
import io
import re
import zipfile
from typing import Any, Dict, List, Optional

__version__ = "0.1.0"

HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"
MAX_MEMBER_BYTES = 64 * 1024 * 1024
# A Data Layout message body begins with version (1 byte) then layout class (1 byte).
# Virtual layout is only defined for message version 4 (class 3), so the pair 04 03
# is the marker. The byte scan is anchored by a nearby message-type byte (0x08) and
# confirmed by the trailing Global Heap ID resolving to a GCOL collection.
_BODY = re.compile(rb"\x04\x03")


def _finding(rule: str, severity: str, cve: Optional[str], cwe: Optional[str],
             message: str, evidence: str) -> Dict[str, Any]:
    return {"rule": rule, "severity": severity, "cve": cve, "cwe": cwe,
            "message": message, "evidence": evidence}


def _byte(data: bytes, off: int) -> Optional[int]:
    return data[off] if 0 <= off < len(data) else None


def _uint(data: bytes, off: int, size: int) -> Optional[int]:
    if off < 0 or off + size > len(data):
        return None
    return int.from_bytes(data[off:off + size], "little")


def _superblock(data: bytes) -> Optional[int]:
    # Locate the HDF5 superblock (at 0, 512, 1024, ... doubling) and return the
    # "size of offsets" field (used to read the global-heap address), or None.
    positions = [0]
    p = 512
    while p < len(data):
        positions.append(p)
        p *= 2
    for pos in positions:
        if data[pos:pos + 8] != HDF5_SIGNATURE:
            continue
        ver = _byte(data, pos + 8)
        if ver in (0, 1):
            so = _byte(data, pos + 13)
        elif ver in (2, 3):
            so = _byte(data, pos + 9)
        else:
            continue
        if so in (2, 4, 8):
            return so
    return None


def _gcol(data: bytes, addr: Optional[int], so: int) -> Optional[str]:
    if addr is None:
        return None
    if addr == (1 << (8 * so)) - 1:      # all-0xFF = undefined address
        return None
    if 0 <= addr and addr + 4 <= len(data) and data[addr:addr + 4] == b"GCOL":
        return "GCOL@%d" % addr
    return None


def _scan_hdf5(data: bytes, label: str) -> Optional[List[Dict[str, Any]]]:
    so = _superblock(data)
    if so is None:
        return None
    out: List[Dict[str, Any]] = []
    for m in _BODY.finditer(data):
        body = m.start()                 # position of the version byte (0x04)
        if b"\x08" not in data[max(0, body - 10):body]:
            continue                     # no Data Layout message-type byte nearby
        gcol = _gcol(data, _uint(data, body + 2, so), so)
        if gcol is not None:
            out.append(_finding(
                "HVD001", "high", "CVE-2026-12480", "CWE-73",
                "HDF5 Data Layout message declares layout class 3 (Virtual Dataset) "
                "with a resolvable global-heap pointer; on load_model() Keras <=3.13.2 "
                "transparently reads the external files the VDS names, because it does "
                "not check dataset.is_virtual (CVE-2026-12480, incomplete fix of "
                "CVE-2026-1669).",
                "%s: version-4 class-3 layout at byte %d; global heap %s"
                % (label, body, gcol)))
        else:
            out.append(_finding(
                "HVD002", "info", "CVE-2026-12480", "CWE-73",
                "candidate HDF5 Virtual Dataset layout (version-4 class-3 Data Layout "
                "message) whose global-heap pointer is undefined or did not resolve to "
                "a GCOL collection; low-confidence, verify manually "
                "(CVE-2026-12480 class).",
                "%s: version-4 class-3 layout at byte %d; global-heap pointer "
                "unresolved" % (label, body)))
    return out


def _scan_zip(data: bytes, name: str, max_member_bytes: int) -> List[Dict[str, Any]]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        res = _scan_hdf5(data, name)
        if res is not None:
            return res
        return [_finding("HVD010", "info", None, None,
                         "input is not an HDF5 file and not a readable zip; nothing "
                         "was checked.", name)]
    out: List[Dict[str, Any]] = []
    try:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member_label = "%s!%s" % (name, info.filename)
            if info.file_size > max_member_bytes:
                out.append(_finding("HVD011", "info", None, None,
                                    "zip member too large to scan; skipped.",
                                    "%s (%d bytes)" % (member_label, info.file_size)))
                continue
            try:
                member = zf.read(info)
            except (zipfile.BadZipFile, OSError, RuntimeError):
                out.append(_finding("HVD011", "info", None, None,
                                    "zip member unreadable; skipped.", member_label))
                continue
            sub = _scan_hdf5(member, member_label)
            if sub:
                out.extend(sub)
    finally:
        zf.close()
    return out


def scan_bytes(data: bytes, name: str = "<bytes>",
               max_member_bytes: int = MAX_MEMBER_BYTES) -> List[Dict[str, Any]]:
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        return _scan_zip(data, name, max_member_bytes)
    res = _scan_hdf5(data, name)
    if res is not None:
        return res
    return [_finding("HVD010", "info", None, None,
                     "input is not an HDF5 file (no superblock signature) and not a "
                     "readable zip; nothing was checked.", name)]


def scan_file(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return [_finding("HVD010", "info", None, None,
                         "file could not be read: %r" % exc, path)]
    return scan_bytes(data, name=path)


def main(argv: Optional[List[str]] = None) -> int:
    import json
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: hdf5_virtual_dataset_scan.py FILE [FILE ...]")
        return 2
    worst = 0
    for p in args:
        findings = scan_file(p)
        print(json.dumps({"path": p, "findings": findings}, indent=2))
        if any(f["severity"] == "high" for f in findings):
            worst = 1
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
