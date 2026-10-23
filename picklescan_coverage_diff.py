# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made with AI agents working in MV2's name.
"""Reproducible module-level coverage differential: picklescan denylist vs a
top-level-package pickle classifier (keras-model-scan).

Why this exists
---------------
keras-model-scan's pickle scanner classifies a pickled ``GLOBAL`` / ``STACK_GLOBAL``
operand by its *top-level package* (``module.split(".", 1)[0]``) instead of matching
the fully-qualified ``module.name`` pair against an exact denylist the way picklescan
does. Top-package classification has one proven advantage -- it is immune to the
submodule-import bypass class (CVE-2025-10157), because importing ``asyncio.unix_events``
still has top package ``asyncio``. But resilience is not the same as breadth: a
top-package classifier can only flag a package it has actually been told about.

This module answers one question with data, not opinion: of the modules picklescan
marks *entirely* unsafe (its wildcard ``"*"`` entries, i.e. every attribute of the
module is a gadget), how many does keras-model-scan's top-package classifier cover,
and which does it miss? As far as a prior-art search shows (picklescan, fickling and
modelscan ship no such comparison), this is the first published module-by-module
coverage differential between the two classification strategies.

Provenance (both fetched live 2026-10-23)
-----------------------------------------
* picklescan ``_unsafe_globals`` wildcard modules: mmaitre314/picklescan,
  ``src/picklescan/scanner.py`` (``main``). Only the ``"*"`` (whole-module) entries are
  used here; picklescan's specific-name entries are discussed in the notes but excluded
  from the count because they are name-dependent, not a clean module-level comparison.
* keras-model-scan classifier: munimtechnologies/keras-model-scan,
  ``pickle_model_scan.py`` v0.2.1 -- ``DANGEROUS_MODULES`` (29 entries) and
  ``GADGET_MODULE_PREFIXES`` ``("numpy.f2py",)``, matched with the scanner's own
  expression ``module == p or module.startswith(p + ".")``.

These two sets are frozen snapshots recorded for a reproducible comparison; re-run
against the live files to refresh. Pure standard library, no third-party imports.
"""
from __future__ import annotations

# --- picklescan: modules whose EVERY global is unsafe (the "*" wildcard entries) ----
# Snapshot of mmaitre314/picklescan src/picklescan/scanner.py _unsafe_globals, 2026-10-23.
PICKLESCAN_WILDCARD_UNSAFE = frozenset({
    "aiohttp",
    "asyncio",
    "bdb",
    "commands",
    "ctypes",
    "httplib",
    "numpy.f2py",
    "numpy.testing._private.utils",
    "nt",
    "posix",
    "os",
    "requests.api",
    "runpy",
    "shutil",
    "socket",
    "ssl",
    "subprocess",
    "sys",
    "cProfile",
    "distutils.file_util",
    "pdb",
    "pickle",
    "_pickle",
    "pip",
    "pty",
    "profile",
    "pydoc",
    "test",
    "timeit",
    "urllib.request",
    "uuid",
    "venv",
    "webbrowser",
    "_osx_support",
    "_aix_support",
    "_pyrepl",
})

# --- keras-model-scan: pickle_model_scan.py v0.2.1 classifier snapshot --------------
KMS_DANGEROUS_MODULES = frozenset({
    "idlelib", "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "platform", "ctypes", "multiprocessing", "runpy", "importlib", "code", "codeop",
    "webbrowser", "pdb", "bdb", "commands", "popen2", "timeit", "asyncio", "signal",
    "resource", "fcntl", "pickle", "dill", "cloudpickle",
})
KMS_GADGET_MODULE_PREFIXES = ("numpy.f2py",)

# Detectors queued but not yet live at snapshot time (so the differential can show the
# roadmap without pretending they already ship). cProfile/profile -> v0.48.0; pip -> the
# follow-up DANGEROUS_MODULES bump (CVE-2025-1716). Kept separate on purpose.
KMS_PENDING_MODULES = frozenset({"cProfile", "profile", "pip"})


def kms_top_package(module: str) -> str:
    """Top-level package exactly as keras-model-scan derives it."""
    return module.split(".", 1)[0]


def kms_covers(module: str, *, include_pending: bool = False) -> bool:
    """True iff keras-model-scan's top-package classifier flags ``module``.

    Mirrors pickle_model_scan.py v0.2.1: a module is flagged when its top-level
    package is in DANGEROUS_MODULES, or it matches a gadget prefix with the scanner's
    own ``module == p or module.startswith(p + ".")`` test.
    """
    dangerous = KMS_DANGEROUS_MODULES | (KMS_PENDING_MODULES if include_pending else frozenset())
    if kms_top_package(module) in dangerous:
        return True
    return any(module == p or module.startswith(p + ".") for p in KMS_GADGET_MODULE_PREFIXES)


def differential(*, include_pending: bool = False) -> dict:
    """Partition picklescan's wildcard-unsafe modules into covered vs gap."""
    covered, gaps = [], []
    for module in PICKLESCAN_WILDCARD_UNSAFE:
        (covered if kms_covers(module, include_pending=include_pending) else gaps).append(module)
    return {
        "total": len(PICKLESCAN_WILDCARD_UNSAFE),
        "covered": sorted(covered),
        "gaps": sorted(gaps),
        "covered_count": len(covered),
        "gap_count": len(gaps),
    }


def markdown_table(*, include_pending: bool = False) -> str:
    d = differential(include_pending=include_pending)
    lines = [
        "| picklescan wildcard-unsafe module | keras-model-scan top-package coverage |",
        "|---|---|",
    ]
    for module in sorted(PICKLESCAN_WILDCARD_UNSAFE):
        covered = kms_covers(module, include_pending=include_pending)
        if covered and not kms_covers(module):  # only true with pending detectors
            status = "pending (queued detector)"
        elif covered:
            status = "covered"
        else:
            status = "GAP"
        lines.append("| `{}` | {} |".format(module, status))
    lines.append("")
    lines.append(
        "**{covered_count} of {total} covered, {gap_count} gaps** (live snapshot).".format(**d)
    )
    return "\n".join(lines)


def main() -> None:  # pragma: no cover - thin CLI wrapper
    print(markdown_table())
    print()
    print("With queued detectors (cProfile/profile/pip) applied:")
    print(markdown_table(include_pending=True))


if __name__ == "__main__":  # pragma: no cover
    main()
