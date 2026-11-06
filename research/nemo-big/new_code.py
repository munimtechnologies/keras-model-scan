# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Replacement code for nemo_container_scan 0.2.0, read by patch_nemo.py.

HELPERS is inserted before ``def scan_bytes(``; SCAN_BYTES and SCAN_FILE
replace those two top-level functions whole. _pickles_in_payload is kept as
it is (it still handles small bare-pickle members).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

HELPERS = '''def _is_pickle_head(head):
    """True if bytes start like a pickle of protocol 2-5 (the PROTO opcode)."""
    return len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _pickles_in_zip(fileobj, member_name, unchecked):
    """Pickles in a nested torch-save zip, read from a seekable file object.

    Only the zip directory and the ``*.pkl`` entries are read, whatever the
    checkpoint's size (0.2.0; up to 0.1.0 a member larger than
    MAX_MEMBER_BYTES was skipped with no finding). A ``*.pkl`` entry larger
    than MAX_MEMBER_BYTES is added to ``unchecked`` instead of being skipped.
    """
    import zipfile

    results = []
    try:
        zf = zipfile.ZipFile(fileobj)
    except Exception:
        return results
    try:
        read = 0
        for info in zf.infolist():
            nm = info.filename
            if not (nm.endswith(".pkl") or nm.rsplit("/", 1)[-1] == "data.pkl"):
                continue
            where = "tar:%s>zip:%s" % (member_name, nm)
            if read >= MAX_ZIP_ENTRIES:
                unchecked.append((where, "more than %d pickle entries"
                                  % MAX_ZIP_ENTRIES))
                break
            read += 1
            if info.file_size > MAX_MEMBER_BYTES:
                unchecked.append((where, "%d bytes" % info.file_size))
                continue
            try:
                inner = zf.read(nm)
            except Exception:
                continue
            dang, allg = _scan_pickle_ops(inner)
            if allg or dang:
                results.append((where, dang, allg))
    finally:
        try:
            zf.close()
        except Exception:
            pass
    return results


def _member_pickles(tar, member, unchecked):
    """Pickles in one regular tar member. A nested zip is opened in place
    (seekable), so a multi-GB checkpoint is never read into memory."""
    fh = tar.extractfile(member)
    if fh is None:
        return []
    head = fh.read(8)
    if not head:
        return []
    if head[:4] == _ZIP_MAGIC:
        fh.seek(0)
        return _pickles_in_zip(fh, member.name, unchecked)
    if member.size > MAX_MEMBER_BYTES:
        if _is_pickle_head(head):
            unchecked.append(("tar:%s" % member.name,
                              "%d bytes" % member.size))
        return []
    fh.seek(0)
    payload = fh.read(MAX_MEMBER_BYTES + 1)
    if not payload or len(payload) > MAX_MEMBER_BYTES:
        return []
    return _pickles_in_payload(payload, member.name)


def _scan_tar(tar, findings):
    """Walk an open tar one member at a time (scan_bytes and scan_file).
    Closes the tar."""
    try:
        count = 0
        while True:
            try:
                member = tar.next()
            except Exception:
                break
            if member is None:
                break
            if count >= MAX_MEMBERS:
                findings.append(_finding(
                    "NEMO031", "medium", "", "CWE-502",
                    "The .nemo container has more members than the scan limit "
                    "(MAX_MEMBERS), so the rest were not checked for path "
                    "traversal or pickles. Treat the file as not fully "
                    "scanned.",
                    "more than %d members; first unchecked=%r"
                    % (MAX_MEMBERS, member.name)))
                break
            count += 1

            # (1) extraction-time path traversal / escaping links (CVE-2024-0129)
            if _escapes(member.name):
                findings.append(_finding(
                    "NEMO020", "high", "CVE-2024-0129", "CWE-22",
                    "Tar member name escapes the extraction root. NeMo's "
                    "restore_from untars with tar.extractall() without sanitising "
                    "names (CVE-2024-0129, fixed r2.0.0rc0), so this member is "
                    "written outside the output directory -- arbitrary file write "
                    "on load. Do not restore this file.",
                    "member=%r (absolute or contains '..')" % member.name))
            if (member.issym() or member.islnk()) and _escapes(member.linkname or ""):
                findings.append(_finding(
                    "NEMO021", "medium", "CVE-2024-0129", "CWE-22",
                    "Tar member is a symlink/hardlink whose target escapes the "
                    "archive. Extraction follows it to write or overwrite a file "
                    "outside the output directory.",
                    "member=%r -> %r" % (member.name, member.linkname)))

            # (2) a pickle hidden one container deep (PickleCloak .nemo path)
            if not member.isfile():
                continue
            unchecked = []
            try:
                hits = _member_pickles(tar, member, unchecked)
            except Exception:
                hits = []
            for where, dang, allg in hits:
                if dang:
                    findings.append(_finding(
                        "NEMO001", "high", "", "CWE-502",
                        "A pickle inside the .nemo tar container imports a "
                        "code-execution callable. A scanner that does not untar "
                        "the .nemo never sees it; restore_from torch.load-s the "
                        "weights and executes it. Do not load this file.",
                        _evidence(where, dang)))
                else:
                    findings.append(_finding(
                        "NEMO010", "medium", "", "CWE-502",
                        "The .nemo container holds a pickle-bearing checkpoint "
                        "with no dangerous import found. It is still a pickle that "
                        "a non-unpacking scanner skips and that restore_from "
                        "unpickles; prefer a non-executable weights format.",
                        _evidence(where, allg)))
            for where, detail in unchecked:
                findings.append(_finding(
                    "NEMO030", "medium", "", "CWE-502",
                    "A pickle inside the .nemo container is larger than the "
                    "scan limit (MAX_MEMBER_BYTES), so it was not checked. "
                    "restore_from still unpickles it. Treat the file as not "
                    "scanned (up to 0.1.0 such members were skipped with no "
                    "finding).",
                    "%s (%s); limit=%d bytes" % (where, detail,
                                                 MAX_MEMBER_BYTES)))
    finally:
        try:
            tar.close()
        except Exception:
            pass


'''

SCAN_BYTES = '''def scan_bytes(data, name=""):
    """Scan the bytes of a .nemo container. Returns a list of finding dicts
    (possibly empty). Returns [] for input that is not a tar container."""
    findings = []
    if not _looks_like_tar(data):
        return findings

    import io
    import tarfile

    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except Exception:
        return findings
    _scan_tar(tar, findings)
    return findings
'''

SCAN_FILE = '''def scan_file(path):
    """Scan a .nemo file by path. Raises OSError if it cannot be read.

    0.2.0 streams the tar from disk member by member; 0.1.0 read the whole
    file into memory first (a multi-GB model needed that much RAM)."""
    import tarfile

    findings = []
    with open(path, "rb") as fh:
        head = fh.read(512)
        if not _looks_like_tar(head):
            return findings
        fh.seek(0)
        try:
            tar = tarfile.open(fileobj=fh, mode="r:*")
        except Exception:
            return findings
        _scan_tar(tar, findings)
    return findings
'''
