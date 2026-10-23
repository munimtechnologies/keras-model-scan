# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made with AI agents working in MV2's name.
"""The *other* axis of the picklescan / keras-model-scan comparison: picklescan's
specific-name denylist entries, and how a top-level-package classifier treats them.

Why this exists
---------------
The companion module ``picklescan_coverage_diff`` compared the two scanners on
picklescan's *wildcard* entries (modules whose every attribute is unsafe) and found
keras-model-scan's top-package classifier covers 18 of 36. But picklescan's
``_unsafe_globals`` has a second half: entries mapped to a *specific set of names*
rather than ``"*"``. These are the framework- and helper-specific gadgets picklescan
has learned about one CVE at a time (``functools.partial``, ``types.CodeType``,
``torch.serialization`` internals, the ``idlelib.*`` submodules, and so on).

A top-package classifier handles this axis very differently, and the result is not
flattering in one spot. keras-model-scan resolves a global's *top-level package* and
routes it to one of a few buckets: a gadget prefix (``numpy.f2py``) -> CRITICAL; a
``DANGEROUS_MODULES`` package -> dangerous; ``functools``/``operator`` gadget names ->
gadget; a package on its ``BENIGN_TOP`` allowlist -> **benign (not flagged at all)**;
anything else -> an ``"unknown import"`` finding at MEDIUM. The allowlist is the catch:
``torch`` is on ``BENIGN_TOP`` and is *not* in ``DANGEROUS_MODULES``, so every one of
picklescan's nine denylisted ``torch.*`` gadget paths is classified benign and passes
clean. PyTorch is the most common real-world pickle-based model format, so this is a
material blind spot in the toolkit, discovered by reading upstream picklescan's own
maintained denylist.

As far as a prior-art search shows (picklescan, fickling and modelscan ship no such
comparison, and the wildcard-axis census does not touch the specific-name entries),
this is the first published mapping of picklescan's specific-name denylist onto a
top-package classifier's buckets.

Provenance (both fetched live 2026-10-23)
-----------------------------------------
* picklescan ``_unsafe_globals`` specific-name (non-``"*"``) module keys:
  mmaitre314/picklescan ``src/picklescan/scanner.py`` (``main``).
* keras-model-scan classifier: munimtechnologies/keras-model-scan
  ``pickle_model_scan.py`` v0.2.1 -- ``DANGEROUS_MODULES`` (29),
  ``GADGET_MODULE_PREFIXES`` ``("numpy.f2py",)``, ``DANGEROUS_BUILTINS`` (14),
  ``BENIGN_TOP`` (19), and the ``functools``/``operator`` gadget-name rule, matched to
  the ordering in the scanner's own ``_classify``.

This is a static reproduction of both tools' *published classification rules*; it does
not execute either scanner. Pure standard library, no third-party imports. Re-fetch the
two source files to refresh the snapshots below.
"""
from __future__ import annotations

# --- picklescan: the specific-name (non-"*") entries of _unsafe_globals --------------
# Snapshot of mmaitre314/picklescan src/picklescan/scanner.py, 2026-10-23. These keys map
# to a set of unsafe names in picklescan (not the whole module); only the module key is
# needed to ask how keras-model-scan's top-package classifier would route them.
PICKLESCAN_SPECIFIC_MODULES = (
    "__builtin__",
    "builtins",
    "cloudpickle.cloudpickle",
    "types",
    "functools",
    "logging",
    "_io",
    "_operator",
    "operator",
    "code",
    "doctest",
    "ensurepip",
    "idlelib.autocomplete",
    "idlelib.calltip",
    "idlelib.debugobj",
    "idlelib.pyshell",
    "idlelib.run",
    "imaplib",
    "lib2to3.pgen2.grammar",
    "lib2to3.pgen2.pgen",
    "pkgutil",
    "torch._dynamo.guards",
    "torch._inductor.codecache",
    "torch.fx.experimental.symbolic_shapes",
    "torch.jit.unsupported_tensor_ops",
    "torch.serialization",
    "torch.utils._config_module",
    "torch.utils.bottleneck.__main__",
    "torch.utils.collect_env",
    "torch.utils.data.datapipes.utils.decoder",
    "trace",
)

# --- keras-model-scan: pickle_model_scan.py v0.2.1 classifier snapshot ---------------
KMS_DANGEROUS_MODULES = frozenset({
    "idlelib", "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "platform", "ctypes", "multiprocessing", "runpy", "importlib", "code", "codeop",
    "webbrowser", "pdb", "bdb", "commands", "popen2", "timeit", "asyncio", "signal",
    "resource", "fcntl", "pickle", "dill", "cloudpickle",
})
KMS_GADGET_MODULE_PREFIXES = ("numpy.f2py",)
KMS_DANGEROUS_BUILTINS = frozenset({
    "eval", "exec", "compile", "open", "__import__", "input", "breakpoint",
    "getattr", "setattr", "globals", "vars", "memoryview", "exit", "quit",
})
# The allowlist that makes torch.* benign. Snapshot of BENIGN_TOP, 2026-10-23.
KMS_BENIGN_TOP = frozenset({
    "numpy", "torch", "collections", "scipy", "sklearn", "pandas", "joblib",
    "_codecs", "copyreg", "copy_reg", "array", "decimal", "datetime", "torchvision",
    "transformers", "keras", "tensorflow", "xgboost", "lightgbm",
})
# Name-driven gadget rule (fires only for these exact top/name pairs).
KMS_NAME_GADGETS = {
    "functools": frozenset({"partial", "reduce"}),
    "operator": frozenset({"attrgetter", "methodcaller"}),
}
_BUILTINS_TOPS = ("builtins", "__builtin__", "__builtins__")


def kms_top_package(module: str) -> str:
    """Top-level package exactly as keras-model-scan derives it."""
    return module.split(".", 1)[0]


def kms_classify(module: str, name: str | None = None) -> str:
    """Reproduce pickle_model_scan.py v0.2.1 ``_classify``, in its own order.

    Returns one of: ``"rce_gadget"``, ``"dangerous"``, ``"gadget"``, ``"benign"``,
    ``"unknown"``. ``name`` is the pickled attribute (needed only for the builtins and
    functools/operator branches); pass the name picklescan actually denies to get
    keras-model-scan's best-case routing for that entry.
    """
    for p in KMS_GADGET_MODULE_PREFIXES:
        if module == p or module.startswith(p + "."):
            return "rce_gadget"
    top = kms_top_package(module)
    if top in _BUILTINS_TOPS:
        return "dangerous" if (name is not None and name in KMS_DANGEROUS_BUILTINS) else "benign"
    if top in KMS_DANGEROUS_MODULES:
        return "dangerous"
    if top in KMS_NAME_GADGETS and name is not None and name in KMS_NAME_GADGETS[top]:
        return "gadget"
    if top in KMS_BENIGN_TOP:
        return "benign"
    return "unknown"


# The finding a classification produces in keras-model-scan, as (rule, severity).
# "unknown" is still surfaced (PKL003, MEDIUM); "benign" produces no finding.
_OUTCOME = {
    "rce_gadget": ("PKL005", "CRITICAL"),
    "dangerous": ("PKL001/PKL002", "CRITICAL/HIGH"),
    "gadget": ("PKL004", "HIGH"),
    "unknown": ("PKL003", "MEDIUM"),
    "benign": (None, None),
}

# Best-case name keras-model-scan would see for each specific-name module, so the
# functools/operator gadget rule and the builtins rule are given their fair chance.
_BEST_CASE_NAME = {
    "functools": "partial",
    "operator": "attrgetter",
    "builtins": "eval",
    "__builtin__": "eval",
}


def classify_specific_axis() -> dict:
    """Route every picklescan specific-name module through keras-model-scan's buckets.

    Buckets:
    * ``strong``  -- keras-model-scan recognises it as a dangerous/gadget import.
    * ``weak``    -- surfaced only as an "unknown import" (PKL003, MEDIUM).
    * ``blind``   -- allowlisted as benign, so NOT flagged at all (the torch.* gap).
    """
    strong, weak, blind = [], [], []
    rows = []
    for module in PICKLESCAN_SPECIFIC_MODULES:
        cls = kms_classify(module, _BEST_CASE_NAME.get(module))
        rule, severity = _OUTCOME[cls]
        rows.append({"module": module, "classification": cls, "rule": rule, "severity": severity})
        if cls == "benign":
            blind.append(module)
        elif cls == "unknown":
            weak.append(module)
        else:
            strong.append(module)
    return {
        "total": len(PICKLESCAN_SPECIFIC_MODULES),
        "strong": sorted(strong),
        "weak": sorted(weak),
        "blind": sorted(blind),
        "strong_count": len(strong),
        "weak_count": len(weak),
        "blind_count": len(blind),
        "rows": rows,
    }


def markdown_table() -> str:
    d = classify_specific_axis()
    lines = [
        "| picklescan specific-name module | keras-model-scan routing | finding |",
        "|---|---|---|",
    ]
    label = {"strong": "recognised (dangerous/gadget)", "weak": "unknown import only",
             "blind": "BENIGN -- not flagged"}
    bucket_of = {}
    for m in d["strong"]:
        bucket_of[m] = "strong"
    for m in d["weak"]:
        bucket_of[m] = "weak"
    for m in d["blind"]:
        bucket_of[m] = "blind"
    for row in sorted(d["rows"], key=lambda r: r["module"]):
        rule = row["rule"] if row["rule"] else "(none)"
        lines.append("| `{}` | {} | {} |".format(
            row["module"], label[bucket_of[row["module"]]], rule))
    lines.append("")
    lines.append(
        "**{strong_count} recognised, {weak_count} unknown-only, {blind_count} "
        "BENIGN (blind spot)** of {total} picklescan specific-name entries.".format(**d))
    return "\n".join(lines)


def main() -> None:  # pragma: no cover - thin CLI wrapper
    d = classify_specific_axis()
    print(markdown_table())
    print()
    print("Blind spot (allowlisted benign, NOT flagged):")
    for module in d["blind"]:
        print("  - {}".format(module))


if __name__ == "__main__":  # pragma: no cover
    main()
