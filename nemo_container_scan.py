"""Static, dependency-free scanner for NVIDIA NeMo ``.nemo`` tar containers.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

A ``.nemo`` checkpoint is a **tar archive** (uncompressed, or gzip/bz2/xz for
older releases) that bundles a ``model_config.yaml`` with the model weights --
``model_weights.ckpt`` (a ``torch.save`` of the state dict) and often other
artifacts. ``torch.save`` writes either a zip container holding ``data.pkl``
(torch >= 1.6) or, for the legacy format, a bare pickle; either way the weights
file is a **pickle**. NeMo's ``SaveRestoreConnector.restore_from`` untars the
archive and ``torch.load``-s the weights, so an attacker who ships a crafted
``.nemo`` gets two distinct wins:

1. **A pickle hidden one container deep.** Opcode-only pickle scanners and
   magic/extension routers operate on a ``.pkl``/``.pt`` *file*; they do not
   untar the ``.nemo`` first, so the ``__reduce__`` gadget inside
   ``model_weights.ckpt`` is never disassembled. ``.nemo`` is one of the 22
   pickle loading paths catalogued by "The Art of Hide and Seek" (USENIX
   Security '26, arXiv 2508.19774, the PickleCloak framework). The sibling
   ``keras-model-scan`` detectors read config text only and, by their own
   documented limit, "do not unpack ``.nemo`` or ``.ckpt`` files" -- this module
   closes that gap by actually opening the tar.

2. **Arbitrary file write on extraction (CVE-2024-0129, CWE-22).**
   ``_unpack_nemo_file`` in ``nemo/core/connectors/save_restore_connector.py``
   calls ``tar.extractall()`` without sanitising member names, so a member whose
   name contains ``../`` (or is absolute) escapes the output directory and
   overwrites host files on restore. Present before NeMo r2.0.0rc0; CVSS 6.3
   (HiddenLayer) / 7.8 (NVD). NVD notes a successful exploit may lead to code
   execution and data tampering.

The scanner opens the tar **in memory** (bounded by ``MAX_MEMBER_BYTES`` and
``MAX_MEMBERS``), reads each regular member without extracting to disk, peels a
nested ``torch.save`` zip if present, and disassembles the inner pickle with the
standard-library ``pickletools``. It never imports torch, tarfile's extractall,
NeMo, or joblib; it never writes to disk, and it never unpickles or executes
anything.

Since 0.3.0 a bare-pickle member is walked the way the loader reads it.
torch.save(..., _use_new_zipfile_serialization=False) -- the legacy
format, the default before PyTorch 1.6, which torch.load still reads --
writes five pickles back to back (magic number, protocol version,
sys_info, the object, the storage keys) and then raw tensor bytes;
torch.load unpickles all five. Up to 0.2.0 only the first (the magic
number) was walked, so a legacy model_weights.ckpt got no finding at all.
A torch zip's data.pkl is still read as one pickle, as torch reads it.
STACK_GLOBAL also resolves a module name fetched back from the memo
(protocol 4+), in addition to the pair 0.2.0 reported.

Rules
-----
NEMO001  high    CWE-502  A pickle inside the .nemo container (``model_weights
                          .ckpt`` or a nested torch-save zip entry) imports a
                          code-execution callable. Invisible to a scanner that
                          does not untar; torch.load during restore would run it.
NEMO010  medium  CWE-502  The .nemo container holds a pickle-bearing checkpoint
                          that names nothing dangerous. Still a pickle a
                          non-unpacking scanner skips; restore_from unpickles it.
NEMO020  high    CWE-22   A tar member name escapes the extraction root (absolute
                          path or a ``..`` component). This is CVE-2024-0129:
                          restore_from's tar.extractall writes it outside the
                          intended folder -- arbitrary file write.
NEMO021  medium  CWE-22   A tar member is a symlink/hardlink whose target escapes
                          the archive (absolute or ``..``). Extraction follows it
                          to write or overwrite a file outside the output folder.

Scope note: a bare ``.pkl``/``.pt`` file is out of scope here -- that is
``pickle_model_scan.py`` / ``pytorch_checkpoint_scan.py``'s job. This module
reports only when it successfully opened a tar container, which is the blind
spot documented above.
"""

__version__ = "0.3.0"

# Size/count caps so a tar/zip/decompression bomb cannot blow up the scanner.
MAX_MEMBERS = 10000
MAX_ZIP_ENTRIES = 5000
MAX_MEMBER_BYTES = 256 * 1024 * 1024

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

# Compressor / archive magic used only to decide "is this plausibly a tar".
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_ZIP_MAGIC = b"PK\x03\x04"
_USTAR_MAGIC = b"ustar"  # at offset 257 of a tar header block


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


def _escapes(name):
    """True if a tar member/link name would resolve outside the extraction root:
    an absolute path (POSIX or Windows drive/UNC) or any ``..`` component."""
    if not name:
        return False
    n = name.replace("\\", "/")
    if n.startswith("/"):
        return True
    # Windows drive (C:\...) or UNC (\\host\...): isabs catches these too.
    import os
    if os.path.isabs(name):
        return True
    if len(name) >= 2 and name[1] == ":":  # drive-letter path, e.g. C:foo
        return True
    parts = n.split("/")
    return ".." in parts


def _looks_like_tar(data):
    """Cheap sniff: plausibly a tar or compressed-tar container."""
    if not data:
        return False
    if data[:2] == _GZIP_MAGIC or data[:3] == _BZ2_MAGIC or data[:6] == _XZ_MAGIC:
        return True  # may be a compressed tar; tarfile r:* confirms.
    # plain tar: ustar magic in the first header block.
    return len(data) >= 265 and data[257:262] == _USTAR_MAGIC


# torch.save(..., _use_new_zipfile_serialization=False), the legacy format
# (the default before PyTorch 1.6) that torch.load still reads, writes five
# pickles back to back and then the raw tensor bytes (torch/serialization.py,
# _legacy_save / _legacy_load): this magic number, the protocol version 1001,
# a sys_info dict, the object itself and the sorted storage keys. torch.load
# unpickles all five. Up to 0.2.0 only the first was walked.
_TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
_TORCH_LEGACY_STREAMS = 5
# Several pickle.dump calls into one file: each starts with PROTO <n>.
_MAX_STREAMS = 4096

_INT_OPS = frozenset({"INT", "BININT", "BININT1", "BININT2", "LONG",
                      "LONG1", "LONG4"})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})


def _opens_pickle(data, pos):
    """True when data[pos:] starts with a PROTO 2-5 header."""
    return len(data) >= pos + 2 and data[pos] == 0x80 and 2 <= data[pos + 1] <= 5


def _add_global(pair, dangerous, all_globals):
    all_globals.append(pair)
    if _is_dangerous(pair[0], pair[1]):
        dangerous.append(pair)


def _walk_one(buf, dangerous, all_globals):
    """Walk one pickle from the file object ``buf`` up to and including its
    STOP, leaving ``buf`` just after it. Returns (complete, first_int):
    whether STOP was reached, and the integer the pickle starts with (None
    unless its first value is an integer).

    STACK_GLOBAL records the pair 0.2.0 recorded (the last two string
    literals) and, when different, the two values pushed right before it --
    which may be strings fetched back from the memo, as protocol 4+ does
    when a second class comes from an already-named module."""
    import pickletools  # lazy; stdlib only

    strings = []   # 0.2.0: string literals only, last 8
    recent = []    # values pushed, as far as they are strings, else None
    memo = {}
    first_int = None
    seen_value = False
    complete = False
    try:
        for opcode, arg, _pos in pickletools.genops(buf):
            opname = opcode.name
            if opname == "STOP":
                complete = True
                break
            if not seen_value and opname not in ("PROTO", "FRAME"):
                seen_value = True
                if opname in _INT_OPS and isinstance(arg, int):
                    first_int = arg
            if opname in _STR_OPS:
                strings.append(arg if isinstance(arg, str) else "")
                if len(strings) > 8:
                    strings.pop(0)
                recent.append(arg if isinstance(arg, str) else None)
            elif opname in _GET_OPS:
                recent.append(memo.get(arg))
            elif opname in _PUT_OPS:
                memo[arg] = recent[-1] if recent else None
            elif opname == "MEMOIZE":
                memo[len(memo)] = recent[-1] if recent else None
            elif opname == "GLOBAL":
                mod, _, nm = (arg or "").partition(" ")
                _add_global((mod, nm), dangerous, all_globals)
                recent.append(None)
            elif opname == "STACK_GLOBAL":
                old = (strings[-2] if len(strings) >= 2 else "",
                       strings[-1] if strings else "")
                _add_global(old, dangerous, all_globals)
                top = recent[-2:]
                if (len(top) == 2 and all(isinstance(x, str) and x for x in top)
                        and tuple(top) != old):
                    _add_global(tuple(top), dangerous, all_globals)
                recent.append(None)
            elif opcode.stack_after:
                recent.append(None)
            if len(recent) > 64:
                del recent[:-8]
    except Exception:
        pass
    return complete, first_int


def _scan_pickle_ops(data, all_streams=False, info=None):
    """Disassemble pickles without executing. Returns (dangerous, all_globals).

    One pickle by default. With ``all_streams`` every pickle the loader reads
    is walked, each with its own memo: exactly five for a legacy torch.save
    file (raw tensor bytes follow; torch reads them raw), otherwise while the
    next bytes open a protocol 2-5 pickle, up to _MAX_STREAMS. A dict passed
    as ``info`` receives ``streams``, ``torch_legacy`` and ``truncated``.
    Parsing stops gracefully at the first malformed byte."""
    import io

    dangerous = []
    all_globals = []
    if not isinstance(info, dict):
        info = {}
    info.update(streams=0, torch_legacy=False, truncated=False)
    buf = io.BytesIO(data)
    end = len(data)
    while True:
        complete, first_int = _walk_one(buf, dangerous, all_globals)
        if not complete:
            if info["torch_legacy"]:
                info["truncated"] = True
            return dangerous, all_globals
        info["streams"] += 1
        if info["streams"] == 1:
            info["torch_legacy"] = first_int == _TORCH_LEGACY_MAGIC
        if not all_streams:
            return dangerous, all_globals
        pos = buf.tell()
        if info["torch_legacy"]:
            if info["streams"] >= _TORCH_LEGACY_STREAMS:
                return dangerous, all_globals
            if pos >= end:
                info["truncated"] = True
                return dangerous, all_globals
            continue
        if pos >= end or not _opens_pickle(data, pos):
            return dangerous, all_globals
        if info["streams"] >= _MAX_STREAMS:
            info["truncated"] = True
            return dangerous, all_globals


def _where_bare(member_name, info):
    """Location text for a bare-pickle member, with how much was read."""
    where = "tar:%s" % member_name
    if info.get("torch_legacy"):
        where += " (legacy torch.save, %d of %d pickles%s)" % (
            info.get("streams", 0), _TORCH_LEGACY_STREAMS,
            "; truncated" if info.get("truncated") else "")
    elif info.get("streams", 0) > 1:
        where += " (%d pickles%s)" % (
            info["streams"], "; more not read" if info.get("truncated") else "")
    return where


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


def _evidence(where, globals_list):
    imports = ", ".join(
        ("%s.%s" % (m, n)) if n else (m or "?") for m, n in globals_list[:8]
    )
    return "%s; imports=%s" % (where, imports or "(none)")


def _pickles_in_payload(payload, member_name):
    """Yield (where, dangerous, all_globals) for each pickle found in a member's
    bytes -- either a nested torch-save zip's ``*.pkl`` entries or a bare
    pickle. Bounded and exception-safe."""
    results = []
    if not payload:
        return results

    if payload[:4] == _ZIP_MAGIC:
        import io
        import zipfile
        try:
            zf = zipfile.ZipFile(io.BytesIO(payload))
        except Exception:
            return results
        try:
            for i, info in enumerate(zf.infolist()):
                if i >= MAX_ZIP_ENTRIES:
                    break
                nm = info.filename
                if not (nm.endswith(".pkl") or nm.rsplit("/", 1)[-1] == "data.pkl"):
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    continue
                try:
                    inner = zf.read(nm)
                except Exception:
                    continue
                dang, allg = _scan_pickle_ops(inner)
                if allg or dang:
                    results.append(("tar:%s>zip:%s" % (member_name, nm), dang, allg))
        finally:
            try:
                zf.close()
            except Exception:
                pass
        return results

    if _looks_like_pickle(payload):
        info = {}
        dang, allg = _scan_pickle_ops(payload, True, info)
        if allg or dang or info.get("torch_legacy"):
            results.append((_where_bare(member_name, info), dang, allg))
    return results


def _is_pickle_head(head):
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


def scan_bytes(data, name=""):
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


def scan_file(path):
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


def main(argv=None):
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write("usage: nemo_container_scan.py <file.nemo> [<file> ...]\n")
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
