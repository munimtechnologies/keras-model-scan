# pickle_eval_global_scan.py
#
# Static detector for the "benign-prefix bypass" class in Python pickles:
# a pickle references a global (via GLOBAL or STACK_GLOBAL) whose function
# reaches eval()/exec()/os despite living UNDER a top-level package that a
# scanner would otherwise allowlist as benign (notably numpy). Pairing such
# a global with a code-execution opcode (REDUCE/BUILD/NEWOBJ...) is arbitrary
# code execution at unpickle time. Class: CWE-502.
#
# Motivating real CVEs (picklescan detection-bypasses, OSV-verified):
#   CVE-2025-71362  numpy.f2py.crackfortran functions call eval() on strings
#   CVE-2025-71365  numpy.f2py.crackfortran.myeval reached via __reduce__
#   CVE-2025-71355  numpy.testing._private.utils.runstring (a synonym for exec)
# picklescan added numpy.f2py and numpy.testing._private.utils to its unsafe
# globals in 0.0.25/0.0.33; a scanner that allowlists the "numpy" top level
# silently suppresses exactly these. This module overrides that allowlist for
# the known eval/exec-reaching sub-globals.
#
# Reads the pickle OPCODE STREAM only (pickletools.genops); never unpickles,
# never imports the referenced modules, never executes anything.
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.

from __future__ import annotations

import pickletools
from typing import Any, Dict, List, Tuple

__version__ = "0.1.0"

# (dotted prefix, primary OSV-verified CVE) - eval/exec-reaching globals that
# hide under an otherwise-trusted top-level package. CVE-backed core.
_CVE_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("numpy.f2py", "CVE-2025-71365"),
    ("numpy.testing._private.utils", "CVE-2025-71355"),
)

# Defense-in-depth: other eval/exec/os-reaching modules picklescan denylists.
# No single CVE; mirrors picklescan's unsafe-globals list so a numpy-style
# allowlist can never suppress them.
_EXTRA_PREFIXES: Tuple[str, ...] = (
    "pydoc", "bdb", "asyncio", "runpy", "pty",
    "timeit", "profile", "cProfile", "webbrowser",
)

_STRING_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "STRING", "BINSTRING", "SHORT_BINSTRING",
}
_EXEC_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}


def _finding(rule: str, level: str, module: str, qualname: str,
             cwe: str, cve: str, message: str) -> Dict[str, Any]:
    return {
        "rule": rule,
        "level": level,
        "global": (module + "." + qualname).strip("."),
        "cwe": cwe,
        "cve": cve,
        "message": message,
    }


def _match_cve_prefix(dotted: str):
    for pref, cve in _CVE_PREFIXES:
        if dotted == pref or dotted.startswith(pref + "."):
            return cve
    return None


def _match_extra_prefix(dotted: str) -> bool:
    for pref in _EXTRA_PREFIXES:
        if dotted == pref or dotted.startswith(pref + "."):
            return True
    return False


def _iter_globals(data: bytes):
    """Return (list of (module, qualname), exec_op_count) from one pickle."""
    strings: List[str] = []
    globals_found: List[Tuple[str, str]] = []
    exec_ops = 0
    for opcode, arg, _pos in pickletools.genops(data):
        name = opcode.name
        if name in _STRING_OPS:
            strings.append(arg if isinstance(arg, str) else "")
        elif name == "GLOBAL":
            mod, _, qn = (arg or "").partition(" ")
            globals_found.append((mod, qn))
        elif name == "STACK_GLOBAL":
            qn = strings[-1] if len(strings) >= 1 else ""
            mod = strings[-2] if len(strings) >= 2 else ""
            globals_found.append((mod, qn))
        elif name in _EXEC_OPS:
            exec_ops += 1
    return globals_found, exec_ops


def scan(path: str) -> List[Dict[str, Any]]:
    """Scan one pickle file. Returns a list of finding dicts (possibly empty)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return [_finding("PEG000", "ERROR", "", "", "", "",
                         f"file could not be read: {exc!r}")]
    try:
        globals_found, exec_ops = _iter_globals(data)
    except Exception as exc:  # malformed / truncated pickle
        return [_finding("PEG000", "ERROR", "", "", "", "",
                         f"pickle stream could not be parsed: {exc!r}")]

    out: List[Dict[str, Any]] = []
    has_exec = exec_ops > 0
    for module, qualname in globals_found:
        cve = _match_cve_prefix(module)
        if cve:
            if has_exec:
                out.append(_finding(
                    "PEG001", "CRITICAL", module, qualname, "CWE-502", cve,
                    "pickle references an eval/exec-reaching global under the "
                    "'numpy' top level together with a code-execution opcode; "
                    "picklescan-bypass class (CVE-2025-71355 / CVE-2025-71362 "
                    "/ CVE-2025-71365)."))
            else:
                out.append(_finding(
                    "PEG003", "MEDIUM", module, qualname, "CWE-502", cve,
                    "pickle references an eval/exec-reaching numpy global but "
                    "no code-execution opcode was seen in the stream."))
        elif _match_extra_prefix(module):
            out.append(_finding(
                "PEG002", "HIGH" if has_exec else "MEDIUM", module, qualname,
                "CWE-502", "",
                "pickle references an eval/exec/os-reaching module on the "
                "picklescan denylist" + (" with a code-execution opcode."
                if has_exec else " (no exec opcode seen)."))
            )
    return out


if __name__ == "__main__":
    import json
    import sys
    for p in sys.argv[1:]:
        print(json.dumps({"path": p, "findings": scan(p)}, indent=2))
