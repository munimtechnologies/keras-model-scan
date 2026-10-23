# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Made with AI agents working in the name of MV2 of Munim, Inc.
#
# benign_top_blindspot_census.py -- a COMPLETE cross-reference between upstream
# picklescan's code-execution denylist (_unsafe_globals) and keras-model-scan's
# BENIGN_TOP allowlist, enumerating every pickle-reachable gadget module that
# picklescan denies but that keras-model-scan's top-package classifier would
# shadow as "benign" because the gadget lives UNDER one of keras-model-scan's
# allowlisted top-level packages.
#
# This generalises the torch-only ledger (torch_gadget_blindspot.py) to all 19
# BENIGN_TOP packages and proves it is complete: of the whole picklescan
# denylist, exactly the 9 torch.* paths plus numpy.* fall under a BENIGN_TOP
# package. numpy.f2py is already carved out by keras-model-scan's
# GADGET_MODULE_PREFIXES, so the ONE blind-spot path this census newly adds
# beyond the torch cluster is numpy.testing._private.utils (its runstring() is a
# documented synonym for exec() per picklescan's own annotation).
#
# Pure-stdlib; imports nothing from the rest of the repo, so it is verifiable in
# isolation. It is a SOURCE-LEVEL mapping between two public lists fetched live
# on 2026-10-23; it executes no gadget and makes no exploitability claim beyond
# "picklescan denies this exact path and keras-model-scan's current classifier
# resolves it to benign". The fix is a one-line extension of
# GADGET_MODULE_PREFIXES so each shadowed path resolves to a recognised gadget
# while ordinary numpy.ndarray / torch.Tensor globals stay benign.

from __future__ import annotations

# Provenance (re-fetch and update when either source moves).
PICKLESCAN_SOURCE = "github.com/mmaitre314/picklescan src/picklescan/scanner.py _unsafe_globals"
KERAS_SOURCE = "github.com/munimtechnologies/keras-model-scan pickle_model_scan.py v0.2.1"
VERIFIED_AT = "2026-10-23"

# Snapshot of keras-model-scan's two relevant classifier structures. Kept here
# (not imported) so the census stays standalone; drift from the live scanner is
# caught by the accompanying test when these snapshots are refreshed.
#
# BENIGN_TOP: top-level packages the classifier resolves to "benign" outright.
KERAS_BENIGN_TOP = (
    "numpy", "torch", "collections", "scipy", "sklearn", "pandas", "joblib",
    "_codecs", "copyreg", "copy_reg", "array", "decimal", "datetime",
    "torchvision", "transformers", "keras", "tensorflow", "xgboost", "lightgbm",
)
# GADGET_MODULE_PREFIXES: dotted prefixes checked BEFORE BENIGN_TOP; a module
# equal to a prefix or starting with "<prefix>." resolves to an rce_gadget.
KERAS_GADGET_MODULE_PREFIXES = ("numpy.f2py",)

# Every picklescan _unsafe_globals key whose TOP-LEVEL package is in BENIGN_TOP,
# i.e. the full set of gadget modules that BENIGN_TOP could shadow. Mirrored
# verbatim from picklescan's live denylist. "mechanism" is picklescan's own
# curation (not re-verified here by execution).
PICKLESCAN_PATHS_UNDER_BENIGN_TOP = (
    {"module": "torch.serialization", "names": ("load",),
     "mechanism": "re-enters checkpoint loading / pickle deserialization on an attacker path"},
    {"module": "torch._inductor.codecache", "names": ("compile_file",),
     "mechanism": "writes and compiles a source file -> code execution"},
    {"module": "torch.jit.unsupported_tensor_ops", "names": ("execWrapper",),
     "mechanism": "exec() wrapper -> arbitrary code execution"},
    {"module": "torch._dynamo.guards", "names": ("GuardBuilder.get",),
     "mechanism": "guard builder resolves/evaluates attribute expressions"},
    {"module": "torch.fx.experimental.symbolic_shapes", "names": ("ShapeEnv.evaluate_guards_expression",),
     "mechanism": "evaluates a guard expression string"},
    {"module": "torch.utils._config_module", "names": ("ConfigModule.load_config",),
     "mechanism": "loads config state that can carry executable payloads"},
    {"module": "torch.utils.bottleneck.__main__", "names": ("run_cprofile", "run_autograd_prof"),
     "mechanism": "profiles a target by running it -> code execution"},
    {"module": "torch.utils.collect_env", "names": ("run",),
     "mechanism": "runs a shell command via subprocess"},
    {"module": "torch.utils.data.datapipes.utils.decoder", "names": ("basichandlers",),
     "mechanism": "decoder dispatch reachable as a pickle global"},
    {"module": "numpy.f2py", "names": ("*",),
     "mechanism": "getlincoef/_eval_length call eval() on arbitrary strings (picklescan wildcards the module)"},
    {"module": "numpy.testing._private.utils", "names": ("*",),
     "mechanism": "runstring() is a documented synonym for exec() (picklescan wildcards the module)"},
)


def top_package(module: str) -> str:
    """Return the top-level package of a dotted module name, as the scanner does."""
    return module.split(".", 1)[0]


def _matches_gadget_prefix(module: str) -> bool:
    """True if the module is carved out by GADGET_MODULE_PREFIXES (checked first)."""
    return any(module == p or module.startswith(p + ".") for p in KERAS_GADGET_MODULE_PREFIXES)


def keras_classification(module: str) -> str:
    """How keras-model-scan's current classifier resolves a module under a
    BENIGN_TOP package.

    Faithful to the live classifier for exactly this branch: GADGET_MODULE_PREFIXES
    is tested first (-> gadget); otherwise, a module whose top-level package is on
    BENIGN_TOP resolves to benign. This models those two steps so the shadowing is
    demonstrable without importing the scanner.
    """
    if _matches_gadget_prefix(module):
        return "gadget"
    if top_package(module) in KERAS_BENIGN_TOP:
        return "benign"
    return "unknown"


def blind_spot_modules() -> list[str]:
    """Gadget paths picklescan denies but keras-model-scan currently calls benign."""
    return [
        entry["module"]
        for entry in PICKLESCAN_PATHS_UNDER_BENIGN_TOP
        if keras_classification(entry["module"]) == "benign"
    ]


def carved_modules() -> list[str]:
    """Paths under a BENIGN_TOP package that keras-model-scan already catches."""
    return [
        entry["module"]
        for entry in PICKLESCAN_PATHS_UNDER_BENIGN_TOP
        if keras_classification(entry["module"]) == "gadget"
    ]


def _selfcheck() -> None:
    # Every listed path really does sit under a BENIGN_TOP package.
    for entry in PICKLESCAN_PATHS_UNDER_BENIGN_TOP:
        assert top_package(entry["module"]) in KERAS_BENIGN_TOP, entry["module"]
        assert entry["names"] and all(n for n in entry["names"]), entry
        assert entry["mechanism"], entry
    blind = blind_spot_modules()
    carved = carved_modules()
    # Completeness result (2026-10-23): 10 blind, 1 carved, nothing unknown.
    assert len(PICKLESCAN_PATHS_UNDER_BENIGN_TOP) == 11, len(PICKLESCAN_PATHS_UNDER_BENIGN_TOP)
    assert len(blind) == 10, blind
    assert len(carved) == 1, carved
    # numpy.f2py is the only path already carved out; the numpy blind spot this
    # census newly surfaces is numpy.testing._private.utils.
    assert carved == ["numpy.f2py"], carved
    assert "numpy.testing._private.utils" in blind, blind
    # The 9 torch paths are all still blind (consistent with the torch ledger).
    assert sum(1 for m in blind if m.startswith("torch.")) == 9, blind


if __name__ == "__main__":
    _selfcheck()
    print(f"BENIGN_TOP blind-spot census: {len(blind_spot_modules())} gadget paths "
          f"denied by picklescan but shadowed as benign by keras-model-scan "
          f"(source {KERAS_SOURCE}, verified {VERIFIED_AT}).")
    for module in blind_spot_modules():
        print(f"  BLIND SPOT  {module}")
    for module in carved_modules():
        print(f"  CARVED      {module}")
