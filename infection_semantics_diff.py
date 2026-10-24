# infection_semantics_diff.py
#
# Copyright 2026 Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Made with AI agents working in the name of MV2 of Munim, Inc. Source review only;
# no code is executed against any live or hosted system by this file.
#
# WHAT THIS IS
# ------------
# A third, previously-unpublished axis of the keras-model-scan vs picklescan
# comparison: the "infection / pass" axis. The earlier two axes compared *which*
# globals each tool knows (PICKLESCAN_COVERAGE_DIFF.md = whole-module wildcard
# entries; PICKLESCAN_SPECIFIC_AXIS.md = specific-name entries). This axis compares
# what each tool DOES with a global that lands *outside both of its lists* -- the
# case that actually decides whether a model file is reported as a problem.
#
# Both classifiers below are faithful, source-derived MODELS (not the live tools),
# pinned to the sources read on 2026-10-24:
#   * picklescan @ github.com/mmaitre314/picklescan (src/picklescan/scanner.py, main)
#   * keras-model-scan @ github.com/munimtechnologies/keras-model-scan
#         (pickle_model_scan.py 0.2.1, main)
# The exhaustive per-real-module enumeration is deferred to a compute job that
# introspects the pip-installed picklescan (picklescan-dangerous-diff-v1); this file
# asserts only the structural/semantic invariants that hold regardless of exact set
# membership.

from __future__ import annotations

# --- picklescan source snapshot (scanner.py @ main, read 2026-10-24) ------------
# module -> "*" (whole module unsafe) or a set of specific unsafe names.
# This is a dated snapshot used for illustration; the authoritative, complete set is
# introspected by the compute job. The invariants asserted by the test do NOT depend
# on this snapshot being complete (they use "os", "collections" and a synthetic
# never-listed module only).
PS_UNSAFE = {
    "os": "*", "posix": "*", "nt": "*", "subprocess": "*", "sys": "*",
    "socket": "*", "shutil": "*", "pty": "*", "ctypes": "*", "runpy": "*",
    "webbrowser": "*", "pdb": "*", "bdb": "*", "commands": "*", "timeit": "*",
    "asyncio": "*", "pickle": "*", "_pickle": "*", "aiohttp": "*", "httplib": "*",
    "requests.api": "*", "ssl": "*", "cProfile": "*", "profile": "*", "pydoc": "*",
    "pip": "*", "uuid": "*", "venv": "*", "test": "*", "urllib.request": "*",
    "distutils.file_util": "*", "numpy.f2py": "*", "numpy.testing._private.utils": "*",
    "_osx_support": "*", "_aix_support": "*", "_pyrepl": "*",
    "builtins": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},
    "__builtin__": {"eval", "compile", "getattr", "apply", "exec", "open", "breakpoint"},
    "functools": {"partial"}, "operator": {"attrgetter", "itemgetter", "methodcaller"},
    "_operator": {"attrgetter", "itemgetter", "methodcaller"},
    "types": {"CodeType"}, "logging": {"FileHandler"}, "_io": {"FileIO"},
    "code": {"InteractiveInterpreter"}, "pkgutil": {"resolve_name"},
    "cloudpickle.cloudpickle": {"loads", "load"},
}

PS_SAFE = {
    "collections": {"OrderedDict"},
    "numpy": {"dtype", "ndarray"},
    "numpy._core.multiarray": {"_reconstruct"},
    "numpy.core.multiarray": {"_reconstruct"},
    "torch._utils": {"_rebuild_tensor_v2"},
}


def picklescan_classify(module, name, strict=False):
    """Model of picklescan's per-global classification cascade.

    Verified from scanner.py (main, 2026-10-24):
      1. "unknown" in module/name -> Dangerous (STACK_GLOBAL evasion guard)
      2. exact module match in _unsafe_globals, or inherited "*" from a dotted parent
      3. _safe_globals exact-name match -> Innocuous
      4. otherwise -> Suspicious  (non-strict, the DEFAULT: strict=False in every
         scan entry point: scan_pickle_bytes/scan_bytes/scan_file_path/
         scan_directory_path all default strict=False)

    Only the non-strict (default) path is modelled/asserted here; strict-mode
    behaviour is being confirmed by the compute job and is intentionally not relied
    upon. Returns one of "dangerous" | "innocuous" | "suspicious".
    """
    module = module or ""
    name = name or ""
    if "unknown" in module or "unknown" in name:
        return "dangerous"
    unsafe = PS_UNSAFE.get(module)
    if unsafe is None and "." in module:
        parts = module.split(".")
        for i in range(1, len(parts)):
            if PS_UNSAFE.get(".".join(parts[:i])) == "*":
                unsafe = "*"
                break
    safe = PS_SAFE.get(module)
    if unsafe is not None and (unsafe == "*" or name in unsafe):
        return "dangerous"
    if safe is not None and (safe == "*" or name in safe):
        return "innocuous"
    return "suspicious"  # default non-strict fallthrough


def picklescan_outcome(module, name):
    """What a default picklescan scan reports for a file whose only global is this.

    KEY SEMANTIC (verified from scanner.py): only Dangerous globals increment
    issues_count and therefore set infected_files; Suspicious globals increment a
    separate suspicious_count and do NOT mark the file infected. So `infected` below
    tracks the standard pass/fail signal (ScanResult.infected_files > 0).
    """
    c = picklescan_classify(module, name)
    return {
        "safety": c,
        "infected": c == "dangerous",          # sets ScanResult.infected_files
        "surfaced": c in ("dangerous", "suspicious"),  # appears in result.globals
    }


# --- keras-model-scan source snapshot (pickle_model_scan.py 0.2.1, 2026-10-24) ---
GADGET_MODULE_PREFIXES = ("numpy.f2py",)
DANGEROUS_BUILTINS = {
    "eval", "exec", "compile", "open", "__import__", "input", "breakpoint",
    "getattr", "setattr", "globals", "vars", "memoryview", "exit", "quit",
}
DANGEROUS_MODULES = {
    "idlelib", "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "platform", "ctypes", "multiprocessing", "runpy", "importlib", "code", "codeop",
    "webbrowser", "pdb", "bdb", "commands", "popen2", "timeit", "asyncio", "signal",
    "resource", "fcntl", "pickle", "dill", "cloudpickle",
}
BENIGN_TOP = {
    "numpy", "torch", "collections", "scipy", "sklearn", "pandas", "joblib",
    "_codecs", "copyreg", "copy_reg", "array", "decimal", "datetime", "torchvision",
    "transformers", "keras", "tensorflow", "xgboost", "lightgbm",
}


def keras_classify(module, name):
    """Verbatim model of keras-model-scan's _classify (pickle_model_scan.py 0.2.1).

    Returns "rce_gadget" | "dangerous" | "gadget" | "benign" | "unknown".
    """
    module = module or ""
    name = name or ""
    top = module.split(".", 1)[0]
    if any(module == p or module.startswith(p + ".") for p in GADGET_MODULE_PREFIXES):
        return "rce_gadget"
    if top in ("builtins", "__builtin__", "__builtins__"):
        return "dangerous" if name in DANGEROUS_BUILTINS else "benign"
    if top in DANGEROUS_MODULES:
        return "dangerous"
    if module == "functools" and name in ("partial", "reduce"):
        return "gadget"
    if module == "operator" and name in ("attrgetter", "methodcaller"):
        return "gadget"
    if top in BENIGN_TOP:
        return "benign"
    return "unknown"


def keras_outcome(module, name):
    """What keras-model-scan reports. Non-benign classifications all produce a
    surfaced Finding; an "unknown" global is PKL003 MEDIUM ("Import outside the
    known-safe allowlist"), never dropped."""
    label = keras_classify(module, name)
    finding = {
        "rce_gadget": "PKL001/CRITICAL",
        "dangerous": "PKL001-or-PKL002 (CRITICAL/HIGH)",
        "gadget": "PKL00x (flagged)",
        "unknown": "PKL003/MEDIUM",
        "benign": None,
    }[label]
    return {"label": label, "finding": finding, "surfaced": label != "benign"}


# --- representative set: provenance-labelled, for the matrix & tests --------------
REPRESENTATIVE = [
    # (module, name, note)
    ("os", "system", "known-dangerous, both tools flag"),
    ("collections", "OrderedDict", "legit model allowlist, both tools clear"),
    ("numpy", "ndarray", "legit model allowlist, both tools clear"),
    ("numpy.f2py", "compile", "numpy submodule code-exec gadget, both tools flag"),
    ("importlib", "import_module", "keras DANGEROUS_MODULES; picklescan: job-verified"),
    ("multiprocessing", "Process", "keras DANGEROUS_MODULES; picklescan: job-verified"),
    ("zz_never_listed_mod", "run", "synthetic unknown code-exec gadget"),
]


def build_matrix():
    rows = []
    for module, name, note in REPRESENTATIVE:
        ps = picklescan_outcome(module, name)
        km = keras_outcome(module, name)
        rows.append({
            "module": module, "name": name, "note": note,
            "picklescan_safety": ps["safety"],
            "picklescan_infected": ps["infected"],
            "keras_label": km["label"],
            "keras_finding": km["finding"],
            "keras_surfaced": km["surfaced"],
            "divergence_on_infection": km["surfaced"] and not ps["infected"],
        })
    return rows


if __name__ == "__main__":
    import json
    import sys

    out_dir = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--out-dir" and i + 1 < len(args):
            out_dir = args[i + 1]

    matrix = build_matrix()
    payload = {
        "name": "infection-semantics-diff",
        "made_with": "AI agents working in the name of MV2 of Munim, Inc.",
        "sources_read": "2026-10-24",
        "picklescan_strict_default": False,
        "note": ("picklescan infected_files is set only by Dangerous globals; "
                 "Suspicious globals do not infect. keras-model-scan surfaces every "
                 "non-benign global, including 'unknown' as PKL003 MEDIUM."),
        "matrix": matrix,
    }
    text = json.dumps(payload, indent=2)
    print(text)
    if out_dir:
        import os
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "infection_semantics_diff.json"), "w") as fh:
            fh.write(text)
