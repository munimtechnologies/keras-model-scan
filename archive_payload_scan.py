"""Static, dependency-free scanner for executables and scripts hidden inside
model archives.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

Many model formats are archives: PyTorch checkpoints and TorchScript (zip),
Keras v3 ``.keras`` (zip), NumPy ``.npz`` (zip), NeMo ``.nemo`` (tar), and the
``.zip`` / ``.tar.gz`` bundles shared on model hubs. None of them needs native
code or scripts to hold weights, yet an archive can carry a shared library, an
executable or a script next to the weights, often under a harmless name like
``model.bin``. Custom-op loaders that take a library path, ``trust_remote_code``
style loading, or a user who unpacks the bundle and runs what is in it can then
execute it. Opcode-level pickle scanners and config walkers never look at these
members.

This module lists every member of a zip or tar archive (gzip/bzip2/xz tars
included), reads only the first ``HEAD_BYTES`` of each, and checks the bytes,
not the file name: ELF, PE (the ``PE\\0\\0`` signature is verified, not just
``MZ``) and Mach-O headers, ``#!/`` scripts, Java class files, and script or
Python file extensions. Nested archives (a zip inside a ``.nemo`` tar, a tar
inside a zip) are opened up to ``MAX_DEPTH`` levels. It never extracts to disk,
never runs anything, and never imports a model library.

Rules
-----
ARC001  high    CWE-829  A member (or the file itself) is a native executable
                         or shared library (ELF, PE, Mach-O). The evidence says
                         when the file name hides it.
ARC002  medium  CWE-829  A member is a script or code: ``#!/`` shebang, Python
                         source/bytecode, shell/batch/PowerShell/VBS, Java class
                         or jar, or a name like ``libop.so`` with no native
                         header. TorchScript's own ``code/**/*.py`` is exempt.
ARC003  medium  CWE-693  A member this scanner could not inspect: encrypted,
                         7z/RAR, unreadable, nested deeper than MAX_DEPTH, or a
                         nested archive larger than MAX_NESTED_BYTES.

Scope note: member path traversal and symlinks in tars are handled by
``nemo_container_scan.py``; pickle members by the pickle scanners in this repo.
"""

__version__ = "0.1.0"

# Caps so a huge or hostile archive cannot exhaust the scanner.
HEAD_BYTES = 4096
MAX_MEMBERS = 100000
MAX_DEPTH = 3
MAX_NESTED_BYTES = 128 * 1024 * 1024

_MACHO_MAGICS = frozenset({
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
})
_SCRIPT_EXTS = frozenset({
    ".py", ".pyc", ".pyo", ".pyw", ".pyz",
    ".sh", ".bash", ".zsh", ".ksh", ".command",
    ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".wsf", ".hta",
    ".jar", ".class",
})
_NATIVE_NAME = r"\.(so(\.\d+)*|dll|dylib|exe|pyd)$"

_RULES = {
    "ARC001": ("high", "CWE-829",
               "Model archive carries a native executable or shared library. "
               "Weights never need native code; a custom-op loader, remote-code "
               "loading or a user unpacking the bundle can run it. Do not load "
               "or unpack this archive untrusted."),
    "ARC002": ("medium", "CWE-829",
               "Model archive carries a script or code file next to the "
               "weights. It does not run by itself, but check what loads or "
               "invokes it before trusting the archive."),
    "ARC003": ("medium", "CWE-693",
               "Part of the archive could not be inspected, so it may hide "
               "content from this and other scanners. Inspect it by hand."),
}


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


def _basename(name):
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def _native_kind(head):
    """Name the native executable format of a header, or None."""
    if head[:4] == b"\x7fELF" and len(head) >= 6 \
            and head[4] in (1, 2) and head[5] in (1, 2):
        return "ELF"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        off = int.from_bytes(head[0x3C:0x40], "little")
        if off >= 0x40 and head[off:off + 4] == b"PE\x00\x00":
            return "PE"
    if head[:4] in _MACHO_MAGICS:
        return "Mach-O"
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        # Fat Mach-O and Java class files share this magic: a fat header
        # holds a small arch count, a class file its version (>= 45).
        if 0 < int.from_bytes(head[4:8], "big") < 32:
            return "Mach-O universal"
    return None


def _archive_kind(head):
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[257:262] == b"ustar":
        return "tar"
    if head[:3] == b"\x1f\x8b\x08" or head[:6] == b"\xfd7zXZ\x00" \
            or (len(head) > 3 and head[:3] == b"BZh"
                and head[3:4] in b"123456789"):
        return "compressed"
    if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:6] == b"Rar!\x1a\x07":
        return "opaque"
    return None


def _shebang(head):
    if not (head.startswith(b"#!/") or head.startswith(b"#! /")):
        return None
    line = head[:256].split(b"\n", 1)[0].rstrip(b"\r")
    if all(0x20 <= b < 0x7F for b in line):
        return line.decode("ascii")
    return None


def _is_torchscript(names):
    return any(_basename(n) == "constants.pkl" for n in names)


def _native_named(name):
    import re

    return re.search(_NATIVE_NAME, _basename(name)) is not None


def _script_kind(name, head, torchscript):
    """Describe a script/code member, or return None."""
    line = _shebang(head)
    if line:
        return "shebang script %r" % line[:80]
    if head[:4] == b"\xca\xfe\xba\xbe":
        return "Java class file"
    base = _basename(name)
    ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    if ext in _SCRIPT_EXTS:
        segments = name.replace("\\", "/").split("/")[:-1]
        if ext == ".py" and torchscript and "code" in segments:
            return None  # TorchScript's own serialized code
        return "%s file" % ext
    if _native_named(base):
        return "named like a native library or executable, no native header"
    return None


def _check_member(where, name, head, size, depth, torchscript, read_all,
                  findings):
    native = _native_kind(head)
    if native:
        detail = native
        if not _native_named(name):
            detail += "; the file name does not say so"
        findings.append(_report("ARC001", where, detail))
        return
    kind = _archive_kind(head)
    if kind == "opaque":
        findings.append(_report("ARC003", where,
                                "7z or RAR container; not opened"))
        return
    if kind is not None:
        if depth + 1 > MAX_DEPTH:
            findings.append(_report(
                "ARC003", where,
                "nested archive deeper than %d levels; not opened" % MAX_DEPTH))
            return
        if size > MAX_NESTED_BYTES:
            findings.append(_report(
                "ARC003", where,
                "nested archive of %d bytes; not opened (limit %d)"
                % (size, MAX_NESTED_BYTES)))
            return
        try:
            inner = read_all()
        except Exception as exc:  # hostile input must not crash the scan
            findings.append(_report("ARC003", where,
                                    "nested archive unreadable (%s)"
                                    % type(exc).__name__))
            return
        if len(inner) > MAX_NESTED_BYTES:
            findings.append(_report(
                "ARC003", where,
                "nested archive over %d bytes; not opened" % MAX_NESTED_BYTES))
            return
        import io

        _scan_container(io.BytesIO(inner), where, depth + 1, findings)
        return
    script = _script_kind(name, head, torchscript)
    if script:
        findings.append(_report("ARC002", where, script))


def _scan_zip(fh, label, depth, findings):
    import zipfile

    try:
        zf = zipfile.ZipFile(fh)
        infos = zf.infolist()[:MAX_MEMBERS]
    except Exception as exc:
        findings.append(_report("ARC003", label,
                                "zip could not be opened (%s)"
                                % type(exc).__name__))
        return
    with zf:
        torchscript = _is_torchscript(i.filename for i in infos)
        for info in infos:
            if info.is_dir():
                continue
            where = "%s!%s" % (label, info.filename)
            if info.flag_bits & 0x1:
                findings.append(_report("ARC003", where,
                                        "encrypted member; not inspected"))
                continue
            try:
                with zf.open(info) as member:
                    head = member.read(HEAD_BYTES)
            except Exception as exc:
                findings.append(_report("ARC003", where,
                                        "member unreadable (%s)"
                                        % type(exc).__name__))
                continue

            def read_all(info=info):
                with zf.open(info) as member:
                    return member.read(MAX_NESTED_BYTES + 1)

            _check_member(where, info.filename, head, info.file_size, depth,
                          torchscript, read_all, findings)


def _scan_compressed_blob(fh, label, findings):
    """A gzip/bzip2/xz stream that is not a tar: check what it unpacks to."""
    fh.seek(0)
    magic = fh.read(3)
    fh.seek(0)
    try:
        if magic[:2] == b"\x1f\x8b":
            import gzip

            head = gzip.GzipFile(fileobj=fh).read(HEAD_BYTES)
        elif magic == b"BZh":
            import bz2

            head = bz2.BZ2File(fh).read(HEAD_BYTES)
        else:
            import lzma

            head = lzma.LZMAFile(fh).read(HEAD_BYTES)
    except Exception:
        return
    where = label + "!<decompressed>"
    native = _native_kind(head)
    if native:
        findings.append(_report("ARC001", where,
                                native + "; hidden in a compressed stream"))
    elif _archive_kind(head) is not None:
        findings.append(_report("ARC003", where,
                                "compressed stream holds an archive; "
                                "not opened"))


def _scan_tar(fh, label, depth, findings, kind):
    import tarfile

    try:
        tf = tarfile.open(fileobj=fh, mode="r:*")
    except Exception as exc:
        if kind == "compressed":
            _scan_compressed_blob(fh, label, findings)
        else:
            findings.append(_report("ARC003", label,
                                    "tar could not be opened (%s)"
                                    % type(exc).__name__))
        return
    with tf:
        members = []
        try:
            for m in tf:
                members.append(m)
                if len(members) >= MAX_MEMBERS:
                    break
        except Exception as exc:
            findings.append(_report("ARC003", label,
                                    "tar listing stopped early (%s)"
                                    % type(exc).__name__))
        torchscript = _is_torchscript(m.name for m in members)
        for m in members:
            if not m.isfile():
                continue
            where = "%s!%s" % (label, m.name)
            try:
                member = tf.extractfile(m)
                head = member.read(HEAD_BYTES) if member is not None else b""
            except Exception as exc:
                findings.append(_report("ARC003", where,
                                        "member unreadable (%s)"
                                        % type(exc).__name__))
                continue

            def read_all(m=m):
                return tf.extractfile(m).read(MAX_NESTED_BYTES + 1)

            _check_member(where, m.name, head, m.size, depth, torchscript,
                          read_all, findings)


def _scan_container(fh, label, depth, findings):
    head = fh.read(HEAD_BYTES)
    fh.seek(0)
    kind = _archive_kind(head)
    if kind == "zip":
        _scan_zip(fh, label, depth, findings)
    elif kind in ("tar", "compressed"):
        _scan_tar(fh, label, depth, findings, kind)
    elif kind == "opaque":
        findings.append(_report("ARC003", label,
                                "7z or RAR container; not opened"))
    else:
        native = _native_kind(head)
        if native:
            findings.append(_report("ARC001", label,
                                    native + "; the whole file is a program"))


def scan_bytes(data, name=""):
    """Scan the bytes of a model file or archive. Returns a list of finding
    dicts (possibly empty)."""
    import io

    if not data:
        return []
    findings = []
    _scan_container(io.BytesIO(bytes(data)), name or "<bytes>", 0, findings)
    return findings


def scan_file(path):
    """Scan a model file or archive on disk without loading it all into
    memory. Raises OSError if it cannot be read."""
    import os

    findings = []
    with open(path, "rb") as fh:
        _scan_container(fh, os.path.basename(path), 0, findings)
    return findings


def main(argv=None):
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: archive_payload_scan.py <file> [...]\n")
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
