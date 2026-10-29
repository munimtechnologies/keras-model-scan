"""Static, dependency-free scanner for PyTorch checkpoint *containers*.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

Other scanners in this toolkit (``pickle_model_scan.py``) classify the opcodes of
a *pickle stream*. This module adds the layer underneath: it recognises the
**container** a real ``torch.save`` checkpoint ships in, pulls the embedded
pickle(s) out, and reports code-execution imports with the container in mind.
That distinction matters for one specific, confirmed vulnerability.

``torch.load`` has two deserialisation paths:

* **Modern zip** (``torch.save`` since PyTorch 1.6, the default): a ZIP archive
  whose ``archive/data.pkl`` member is the object graph. The restricted
  ``weights_only`` unpickler is wired into this path, so a dangerous import is
  only reached when the caller passes ``weights_only=False``.
* **Legacy** (an old tar layout, or a bare non-zip pickle stream such as a
  Hugging Face ``pytorch_model.bin``): handled by ``_legacy_load``.

CVE-2025-32434 (published 2025-04-17, CWE-502, CVSS 9.3/9.8, GHSA-53q9-r3pm-6pq6)
is exactly this seam: on torch <= 2.5.1 the ``_legacy_load`` path did **not**
apply the restricted unpickler, so ``torch.load(path, weights_only=True)`` --
the call everyone reached for to load untrusted checkpoints safely -- still
executed whatever callable a legacy-format file named. Fixed in torch 2.6.0,
which also flipped the default to ``weights_only=True``.

So the container is a security signal in its own right:

* a code-execution import in a **legacy-format** file is reachable even under the
  "safe" ``weights_only=True`` on affected torch -> ``PTC001`` (CVE-2025-32434);
* the same import in a **modern-zip** file needs ``weights_only=False`` ->
  ``PTC002`` (CWE-502, the general deserialisation class);
* a legacy-format file that holds a real pickled object graph but names nothing
  dangerous is still the format CVE-2025-32434 abuses -> ``PTC010`` (advisory).

Rules
-----
PTC001  high    CVE-2025-32434  legacy-format checkpoint (tar or non-zip pickle)
                                imports a code-execution callable; executed even
                                by torch.load(weights_only=True) on torch<=2.5.1.
PTC002  high    CWE-502         modern zip-format checkpoint imports a
                                code-execution callable; executed by
                                torch.load(weights_only=False).
PTC010  medium  CVE-2025-32434  legacy-format checkpoint detected (real pickled
                                object graph, no dangerous import found): the
                                container itself bypasses weights_only=True on
                                torch<=2.5.1. Prefer safetensors or re-saving in
                                the modern zip format and torch>=2.6.0.

This scanner never imports ``torch``, never extracts an archive member to disk,
and never unpickles or executes anything. It reads bytes and parses opcodes with
the standard-library ``pickletools`` disassembler only.
"""

__version__ = "0.1.0"

# Caps so a hostile archive cannot blow up the scanner (archive_bomb_scan.py
# covers decompression-bomb detection separately).
MAX_MEMBERS = 64
MAX_MEMBER_BYTES = 64 * 1024 * 1024

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

# pickle opcodes that construct/mutate an object (where a reduce callable runs).
_EXEC_OPS = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"})
# opcodes that push a string we may later consume as a STACK_GLOBAL operand.
_STR_OPS = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
})


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


def _scan_pickle_ops(data):
    """Disassemble a pickle (or several concatenated frames) without executing.

    Returns (dangerous_globals, all_globals). Parsing stops gracefully at the
    first malformed byte, which is expected for a legacy torch stream whose raw
    tensor storage trails the structural pickles.
    """
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
                # arg is "module name", joined by a single space by pickletools.
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
        # truncated / trailing non-pickle bytes: keep what we parsed.
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


def _extract_pickles(data):
    """Return (container, [(member_name, pickle_bytes), ...]).

    container is one of 'zip', 'tar', 'pickle', 'unknown'. Nothing is written to
    disk; archive members are only read into memory.
    """
    import io

    bio = io.BytesIO(data)

    # Modern torch.save: a ZIP whose data.pkl holds the object graph.
    import zipfile
    try:
        if zipfile.is_zipfile(bio):
            pickles = []
            try:
                with zipfile.ZipFile(bio) as zf:
                    names = [
                        n for n in zf.namelist()
                        if n.endswith((".pkl", ".pickle"))
                        or n.rsplit("/", 1)[-1] == "data.pkl"
                    ]
                    for n in names[:MAX_MEMBERS]:
                        try:
                            with zf.open(n) as fh:
                                pickles.append((n, fh.read(MAX_MEMBER_BYTES)))
                        except Exception:
                            continue
            except Exception:
                pass
            return "zip", pickles
    except Exception:
        pass

    # Very old torch.save / _legacy_load tar layout (members 'pickle', ...).
    import tarfile
    try:
        bio.seek(0)
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            pickles = []
            for m in tf.getmembers():
                if len(pickles) >= MAX_MEMBERS:
                    break
                if not m.isfile():
                    continue
                base = m.name.rsplit("/", 1)[-1]
                if base in ("pickle", "data.pkl") or m.name.endswith((".pkl", ".pickle")):
                    try:
                        fh = tf.extractfile(m)
                        if fh is not None:
                            pickles.append((m.name, fh.read(MAX_MEMBER_BYTES)))
                    except Exception:
                        continue
            if pickles:
                return "tar", pickles
    except tarfile.TarError:
        pass
    except Exception:
        pass

    # Legacy non-zip pickle stream (e.g. a Hugging Face pytorch_model.bin).
    if _looks_like_pickle(data):
        return "pickle", [("", data)]

    return "unknown", []


def _evidence(container, member, globals_list):
    labels = {
        "zip": "modern zip (torch.save >=1.6)",
        "tar": "legacy tar (_legacy_load)",
        "pickle": "legacy non-zip pickle (_legacy_load)",
    }
    imports = ", ".join(
        ("%s.%s" % (m, n)) if n else (m or "?") for m, n in globals_list[:8]
    )
    where = member or "<root pickle>"
    return "container=%s; member=%s; imports=%s" % (
        labels.get(container, container), where, imports or "(none)")


def scan_bytes(data, name=""):
    """Scan raw checkpoint bytes. Returns a list of finding dicts (possibly empty)."""
    findings = []
    container, pickles = _extract_pickles(data)
    for member, pdata in pickles:
        dangerous, all_globals = _scan_pickle_ops(pdata)
        if dangerous:
            if container in ("tar", "pickle"):
                findings.append(_finding(
                    "PTC001", "high", "CVE-2025-32434", "CWE-502",
                    "Legacy-format PyTorch checkpoint imports a code-execution "
                    "callable. torch.load(weights_only=True) on torch<=2.5.1 "
                    "routes legacy files through _legacy_load, which bypasses "
                    "the restricted unpickler and executes it (CVE-2025-32434); "
                    "upgrade to torch>=2.6.0 and do not load this file.",
                    _evidence(container, member or name, dangerous)))
            else:
                findings.append(_finding(
                    "PTC002", "high", "", "CWE-502",
                    "PyTorch checkpoint (modern zip format) imports a "
                    "code-execution callable; torch.load(weights_only=False) "
                    "deserialises and runs it. Load with weights_only=True on "
                    "torch>=2.6.0, or do not load this file.",
                    _evidence(container, member or name, dangerous)))
        elif container in ("tar", "pickle") and all_globals:
            findings.append(_finding(
                "PTC010", "medium", "CVE-2025-32434", "CWE-502",
                "Legacy-format PyTorch checkpoint (a real pickled object graph "
                "with no dangerous import found). The legacy container itself is "
                "the surface CVE-2025-32434 abuses: on torch<=2.5.1 it is "
                "deserialised even under weights_only=True. Prefer safetensors, "
                "or re-save in the modern zip format and use torch>=2.6.0.",
                _evidence(container, member or name, all_globals)))
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
            "usage: pytorch_checkpoint_scan.py <file.pt|.pth|.bin> [<file> ...]\n")
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
