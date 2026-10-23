# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Made with AI agents working in the name of MV2 of Munim, Inc.
#
# torch_gadget_blindspot.py -- standalone ledger of the torch.* code-execution
# gadget paths that upstream picklescan (the Hugging Face-standard pickle
# scanner) denies by exact dotted path, but that keras-model-scan's
# top-package pickle classifier currently resolves to "benign" because the
# whole ``torch`` package is on its BENIGN_TOP allowlist.
#
# This module is pure-stdlib and imports nothing from the rest of the repo, so
# it can be verified in isolation. It is a SOURCE-LEVEL mapping between two
# public denylists/allowlists fetched live on 2026-10-23; it does not execute
# any gadget and makes no exploitability claim beyond "picklescan denies this
# exact path". PyTorch ``.bin`` checkpoints are the most common pickle-based
# model format in the wild, so a whole-``torch`` allowlist is the single most
# material coverage gap in the scanner. The planned fix adds an exact-match
# ``GADGET_MODULE_PATHS`` set (these 9 paths) checked BEFORE the BENIGN_TOP
# allowlist, so these paths resolve to a recognised gadget while an ordinary
# ``torch.Tensor`` global stays benign.

from __future__ import annotations

# Provenance of both lists (re-fetch and update these when either source moves).
PICKLESCAN_SOURCE = "github.com/mmaitre314/picklescan src/picklescan/scanner.py _unsafe_globals"
KERAS_SOURCE = "github.com/munimtechnologies/keras-model-scan pickle_model_scan.py v0.2.1"
VERIFIED_AT = "2026-10-23"

# The torch.* entries picklescan denies by exact dotted module path, mirrored
# verbatim from its live ``_unsafe_globals``. Each entry:
#   module    -- the dotted module picklescan keys on
#   names     -- the specific callables picklescan denies within that module
#   mechanism -- one-line summary of why picklescan treats the path as a
#                code-execution / unsafe-deserialization gadget (picklescan's
#                curation; not re-verified here by execution)
TORCH_GADGET_PATHS = (
    {
        "module": "torch.serialization",
        "names": ("load",),
        "mechanism": "re-enters checkpoint loading / pickle deserialization on an attacker path",
    },
    {
        "module": "torch._inductor.codecache",
        "names": ("compile_file",),
        "mechanism": "writes and compiles a source file -> code execution",
    },
    {
        "module": "torch.jit.unsupported_tensor_ops",
        "names": ("execWrapper",),
        "mechanism": "exec() wrapper -> arbitrary code execution",
    },
    {
        "module": "torch._dynamo.guards",
        "names": ("GuardBuilder.get",),
        "mechanism": "guard builder resolves/evaluates attribute expressions",
    },
    {
        "module": "torch.fx.experimental.symbolic_shapes",
        "names": ("ShapeEnv.evaluate_guards_expression",),
        "mechanism": "evaluates a guard expression string",
    },
    {
        "module": "torch.utils._config_module",
        "names": ("ConfigModule.load_config",),
        "mechanism": "loads config state that can carry executable payloads",
    },
    {
        "module": "torch.utils.bottleneck.__main__",
        "names": ("run_cprofile", "run_autograd_prof"),
        "mechanism": "profiles a target by running it -> code execution",
    },
    {
        "module": "torch.utils.collect_env",
        "names": ("run",),
        "mechanism": "runs a shell command via subprocess",
    },
    {
        "module": "torch.utils.data.datapipes.utils.decoder",
        "names": ("basichandlers",),
        "mechanism": "decoder dispatch reachable as a pickle global",
    },
)

# Snapshot of the two keras-model-scan classifier facts that cause the gap.
# Kept here (not imported) so this ledger stays standalone and can be checked
# in isolation; a drift between these and the live scanner is caught by the
# accompanying test when the snapshot is refreshed.
KERAS_TORCH_IN_BENIGN_TOP = True        # "torch" is on the BENIGN_TOP allowlist
KERAS_TORCH_IN_DANGEROUS_MODULES = False
KERAS_HAS_GADGET_MODULE_PATHS = False   # no exact-match path layer exists yet


def top_package(module: str) -> str:
    """Return the top-level package of a dotted module name, as the scanner does."""
    return module.split(".", 1)[0]


def keras_classification(module: str) -> str:
    """How keras-model-scan's current classifier resolves a torch.* path.

    Faithful to the live classifier for the ``torch`` package only: because
    ``torch`` is on BENIGN_TOP and absent from DANGEROUS_MODULES, and because
    there is no exact-match gadget-path layer, every ``torch`` / ``torch.*``
    global resolves to "benign". This function models exactly that branch so
    the blind spot is demonstrable without importing the scanner.
    """
    if top_package(module) == "torch":
        if KERAS_TORCH_IN_DANGEROUS_MODULES:
            return "dangerous"
        if KERAS_HAS_GADGET_MODULE_PATHS and _is_ledger_path(module):
            return "gadget"
        if KERAS_TORCH_IN_BENIGN_TOP:
            return "benign"
    return "unknown"


def _is_ledger_path(module: str) -> bool:
    return any(entry["module"] == module for entry in TORCH_GADGET_PATHS)


def blind_spot_modules() -> list[str]:
    """torch gadget paths picklescan denies but keras currently calls benign."""
    return [
        entry["module"]
        for entry in TORCH_GADGET_PATHS
        if keras_classification(entry["module"]) == "benign"
    ]


def _selfcheck() -> None:
    assert len(TORCH_GADGET_PATHS) == 9, len(TORCH_GADGET_PATHS)
    for entry in TORCH_GADGET_PATHS:
        assert entry["module"].startswith("torch."), entry["module"]
        assert entry["names"] and all(n for n in entry["names"]), entry
        assert entry["mechanism"], entry
    # The whole point: under the current classifier all 9 are a blind spot.
    assert blind_spot_modules() == [e["module"] for e in TORCH_GADGET_PATHS]


if __name__ == "__main__":
    _selfcheck()
    print(f"torch gadget blind-spot ledger: {len(TORCH_GADGET_PATHS)} paths "
          f"denied by picklescan, classified benign by keras-model-scan "
          f"(source {KERAS_SOURCE}, verified {VERIFIED_AT}).")
    for module in blind_spot_modules():
        print(f"  BLIND SPOT  {module}")
