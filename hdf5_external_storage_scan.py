"""hdf5_external_storage_scan.py -- static, no-execution detector for HDF5
weight files that make the loader read OTHER files on the host.

CVE-2026-1669 (GHSA-3m4q-jmj6-r34q, CWE-73): Keras 3.0.0 through 3.13.1 honour
HDF5 "external storage" and external links when reading weights, so a crafted
.weights.h5 (or a .keras archive that embeds one) makes load_weights() /
load_model() read an arbitrary readable host file into the model's tensors,
where it can be recovered through inference or a re-save. Keras safe_mode
guards object deserialization only, not weight I/O. Fixed in Keras 3.12.1 and
3.13.2.

Keras's own savers do not use either feature, so any occurrence in a weights
file is anomalous. This scanner reads bytes only (stdlib, no h5py, nothing is
loaded) and keys on the two on-disk records libhdf5 decodes for them:

  HES001 high  External Data Files message (object header message type 0x0007):
               a dataset's raw data lives in named files outside the HDF5 file.
               Found by its body (version 1, 3 reserved bytes, u16 allocated
               slots, u16 used slots, heap address) behind a version 1 or
               version 2 message header, and confirmed by the heap address
               pointing at a version-0 local heap ("HEAP"), which libhdf5
               requires. The external file names are read from that heap.
  HES002 high  Link message (type 0x0006) of link type 64 (external link): a
               group member resolves to an object inside another HDF5 file.
               Found by its body (version 1, flags with the link-type bit, type
               64) and confirmed by decoding the name and the user data
               "<version/flags byte><file>\\0<object path>\\0". Anchoring on the
               body finds the link in an object header and in an unfiltered
               dense-storage heap block alike.
  HES010 info  The input is not an HDF5 file (no superblock signature at 0,
               512, 1024, ...) or not a readable zip archive; nothing was checked.
  HES011 info  An HDF5 member of a .keras/zip archive was larger than the read
               limit or could not be read, and was skipped.

Field layouts follow libhdf5's own decoders (H5Oefl.c, H5HLcache.c, H5Olink.c,
H5Ocache.c). Reserved bytes are not required to be zero because libhdf5 skips
them without checking.

Limits: HDF5 virtual datasets (layout class 3; source file names live in the
global heap) are not decoded. A record inside a filtered (compressed) heap
block is invisible to a byte scan. Names and paths must be printable UTF-8 and
link names at most 1 MiB. A clean result is triage, not proof of safety.

Usage: python hdf5_external_storage_scan.py FILE [FILE ...]
Exit 0 = no high findings, 1 = at least one high finding, 2 = usage or I/O error.

Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""

import io
import re
import sys
import zipfile
import zlib

__version__ = "0.1.0"

HDF5_SIG = b"\x89HDF\r\n\x1a\n"
CVE = "CVE-2026-1669"
CWE = "CWE-73"
MAX_MEMBER_BYTES = 1 << 30  # largest .keras/zip member read into memory
MAX_LINK_NAME = 1 << 20

_H5_SUFFIXES = (".h5", ".hdf5", ".hdf", ".he5")

# A 0x07 byte that may start an External Data Files message header. Version 1
# object headers (u16 type, u16 size, flags, 3 reserved) put the body 8 bytes
# on; version 2 headers (u8 type, u16 size, flags[, u16 creation order]) put it
# 4 or 6 bytes on. The body starts with its version byte, 1.
_EFL_HEADER = re.compile(rb"\x07(?=\x00.{6}\x01|.{3}\x01|.{5}\x01)", re.S)
# A version 1 link message body whose flags store a link type (bit 0x08; libhdf5
# rejects flags above 0x1f), followed by link type 64 (external).
_EXT_LINK = re.compile(rb"\x01(?=[\x08-\x0f\x18-\x1f]\x40)", re.S)


def _finding(rule, severity, cve, cwe, message, evidence):
    return {"rule": rule, "severity": severity, "cve": cve, "cwe": cwe,
            "message": message, "evidence": evidence}


def _uint(data, off, size):
    if off < 0 or off + size > len(data):
        return None
    return int.from_bytes(data[off:off + size], "little")


def _is(data, off, value):
    return data[off:off + 1] == bytes((value,))


def _text(raw):
    """Printable UTF-8 text, or None. Host paths and link names are printable."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        return None
    return text


def _show(path):
    note = ""
    if path.startswith(("/", "\\")) or re.match(r"[A-Za-z]:[\\/]", path):
        note = " (absolute path)"
    elif ".." in re.split(r"[\\/]", path):
        note = " (parent-directory traversal)"
    return "'%s'%s" % (path[:200], note)


def _superblock(data):
    """Return (sizeof_offsets, sizeof_lengths, base_address), or None."""
    off = 0
    while off + 8 <= len(data):
        if data[off:off + 8] == HDF5_SIG:
            break
        off = 512 if off == 0 else off * 2
    else:
        return None
    version = _uint(data, off + 8, 1)
    if version in (0, 1):
        so, sl = _uint(data, off + 13, 1), _uint(data, off + 14, 1)
        base_at = off + (24 if version == 0 else 28)
    elif version in (2, 3):
        so, sl = _uint(data, off + 9, 1), _uint(data, off + 10, 1)
        base_at = off + 12
    else:
        return None
    if so not in (2, 4, 8) or sl not in (2, 4, 8):
        return None
    base = _uint(data, base_at, so)
    if base is None or base > len(data):
        base = off
    return so, sl, base


def _local_heaps(data, so, sl, base):
    """Map each version-0 local heap's relative address to its data segment."""
    heaps = {}
    pos = data.find(b"HEAP")
    while pos != -1:
        if pos >= base and _is(data, pos + 4, 0):
            size = _uint(data, pos + 8, sl)
            addr = _uint(data, pos + 8 + 2 * sl, so)
            if size and addr is not None and base + addr + size <= len(data):
                heaps[pos - base] = (base + addr, size)
        pos = data.find(b"HEAP", pos + 1)
    return heaps


def _efl_slots(data, body, size, so, sl, heaps):
    """Decode an External Data Files message body as libhdf5 does. Return
    [(name, offset, size)], or None where libhdf5 would reject the message."""
    nalloc, nused = _uint(data, body + 4, 2), _uint(data, body + 6, 2)
    heap = _uint(data, body + 8, so)
    if not nalloc or not nused or nused > nalloc or heap not in heaps:
        return None
    if size is None or size < 8 + so + nused * 3 * sl:
        return None
    seg_start, seg_size = heaps[heap]
    slots = []
    at = body + 8 + so
    for _ in range(nused):
        name_off, offset, length = (_uint(data, at + i * sl, sl) for i in range(3))
        at += 3 * sl
        if name_off is None or length is None or name_off >= seg_size:
            return None
        raw = data[seg_start + name_off:seg_start + seg_size]
        end = raw.find(b"\x00")
        raw = raw if end == -1 else raw[:end]
        if not raw:  # libhdf5 rejects an empty external file name
            return None
        slots.append((raw.decode("utf-8", "replace"), offset, length))
    return slots


def _external_files(data, so, sl, base, label):
    heaps = _local_heaps(data, so, sl, base)
    if not heaps:
        return []
    findings, seen = [], set()
    for m in _EFL_HEADER.finditer(data):
        at = m.start()
        candidates = []
        if _is(data, at + 1, 0) and _is(data, at + 8, 1):
            candidates.append((at + 8, _uint(data, at + 2, 2)))
        for skip in (4, 6):
            if _is(data, at + skip, 1):
                candidates.append((at + skip, _uint(data, at + 1, 2)))
        for body, size in candidates:
            if body in seen:
                continue
            slots = _efl_slots(data, body, size, so, sl, heaps)
            if not slots:
                continue
            seen.add(body)
            names = ", ".join(_show(n) for n, _, _ in slots)
            detail = "; ".join("%s offset=%d size=%d" % (_show(n), o, s)
                               for n, o, s in slots)
            findings.append(_finding(
                "HES001", "high", CVE, CWE,
                "dataset raw data is stored in external file(s) outside this "
                "HDF5 file: %s. Keras 3.0.0-3.13.1 reads them into the model's "
                "weights on load_weights()/load_model() even with safe_mode "
                "(fixed in 3.12.1 and 3.13.2); Keras's own savers do not use "
                "external storage." % names,
                "%s @0x%x: External Data Files message, %d slot(s): %s"
                % (label, body, len(slots), detail)))
    return findings


def _ext_link(data, at):
    """Decode a link message body as libhdf5 does. Return (link name, target
    file, target object) for a well-formed external link, else None."""
    flags = data[at + 1]
    p = at + 3
    if flags & 0x04:  # creation order
        p += 8
    if flags & 0x10:  # character set
        if _uint(data, p, 1) not in (0, 1):
            return None
        p += 1
    width = 1 << (flags & 0x03)
    length = _uint(data, p, width)
    p += width
    if not length or length > MAX_LINK_NAME or p + length > len(data):
        return None
    name = _text(data[p:p + length])
    p += length
    usize = _uint(data, p, 2)
    p += 2
    if name is None or usize is None or usize < 3 or p + usize > len(data):
        return None
    udata = data[p:p + usize]
    if udata[0] >> 4:  # external link version must be 0
        return None
    parts = udata[1:].split(b"\x00")
    if len(parts) < 3:  # needs "<file>\0<object>\0"
        return None
    target_file, target_obj = _text(parts[0]), _text(parts[1])
    if target_file is None or target_obj is None:
        return None
    return name, target_file, target_obj


def _external_links(data, label):
    findings = []
    for m in _EXT_LINK.finditer(data):
        link = _ext_link(data, m.start())
        if not link:
            continue
        name, target_file, target_obj = link
        findings.append(_finding(
            "HES002", "high", CVE, CWE,
            "group member '%s' is an HDF5 external link to object '%s' in file "
            "%s. Keras 3.0.0-3.13.1 follows external links when reading "
            "weights, so loading opens that host file (fixed in 3.12.1 and "
            "3.13.2); Keras's own savers do not write external links."
            % (name[:200], target_obj[:200], _show(target_file)),
            "%s @0x%x: external link '%s' -> file '%s', object '%s'"
            % (label, m.start(), name[:200], target_file[:200], target_obj[:200])))
    return findings


def _scan_hdf5(data, label):
    sb = _superblock(data)
    if sb is None:
        return None
    so, sl, base = sb
    return _external_files(data, so, sl, base, label) + _external_links(data, label)


def _scan_zip(data, name, max_member_bytes):
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                label = "%s!%s" % (name, info.filename)
                try:
                    with zf.open(info) as fh:
                        head = fh.read(8)
                    if head != HDF5_SIG and not info.filename.lower().endswith(_H5_SUFFIXES):
                        continue
                    if info.file_size > max_member_bytes:
                        findings.append(_finding(
                            "HES011", "info", None, None,
                            "archive member larger than %d bytes was not read"
                            % max_member_bytes, label))
                        continue
                    member = zf.read(info)
                except (zipfile.BadZipFile, NotImplementedError, RuntimeError,
                        EOFError, zlib.error) as exc:
                    findings.append(_finding(
                        "HES011", "info", None, None,
                        "archive member could not be read: %s" % exc, label))
                    continue
                findings.extend(_scan_hdf5(member, label) or [])
    except zipfile.BadZipFile:
        return [_finding("HES010", "info", None, None,
                         "not a readable zip archive; nothing was checked", name)]
    return findings


def scan_bytes(data, name="<bytes>", max_member_bytes=MAX_MEMBER_BYTES):
    """Return a list of findings for the given file bytes: an HDF5 file
    (.h5/.hdf5/.weights.h5) or a .keras/zip archive holding HDF5 members."""
    if not isinstance(data, bytes):
        data = bytes(data)
    if data[:4] == b"PK\x03\x04":
        return _scan_zip(data, name, max_member_bytes)
    findings = _scan_hdf5(data, name)
    if findings is None:
        return [_finding("HES010", "info", None, None,
                         "no HDF5 superblock of a supported version found; "
                         "nothing was checked", name)]
    return findings


def scan_file(path):
    with open(path, "rb") as fh:
        return scan_bytes(fh.read(), name=path)


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args:
        print("usage: python hdf5_external_storage_scan.py FILE [FILE ...]",
              file=sys.stderr)
        return 2
    worst = 0
    for path in args:
        try:
            findings = scan_file(path)
        except OSError as exc:
            print("%s: error: %s" % (path, exc), file=sys.stderr)
            worst = max(worst, 2)
            continue
        if not findings:
            print("%s: no HDF5 external storage or external links found" % path)
        for f in findings:
            print("%s: %s %s: %s" % (path, f["severity"].upper(), f["rule"], f["message"]))
            print("    %s" % f["evidence"])
            if f["severity"] == "high":
                worst = max(worst, 1)
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
