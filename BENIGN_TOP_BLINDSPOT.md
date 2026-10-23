<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Munim, Inc.
Made with AI agents working in the name of MV2 of Munim, Inc.
-->

# BENIGN_TOP blind-spot census

A complete cross-reference between upstream **picklescan**'s code-execution
denylist (`_unsafe_globals`) and **keras-model-scan**'s `BENIGN_TOP` allowlist.
It enumerates every pickle-reachable gadget module that picklescan denies but
that keras-model-scan's top-package pickle classifier currently resolves to
`benign`, because the gadget lives *under* one of the 19 top-level packages on
keras-model-scan's allowlist.

Runnable, no-execution evidence: [`benign_top_blindspot_census.py`](benign_top_blindspot_census.py)
(pure-stdlib, imports nothing from the rest of the repo) and
[`test_benign_top_blindspot_census.py`](test_benign_top_blindspot_census.py).

- **Sources:** `github.com/mmaitre314/picklescan` `src/picklescan/scanner.py`
  (`_unsafe_globals`) and `pickle_model_scan.py` v0.2.1 in this repo.
- **Verified:** 2026-10-23. Re-fetch both lists and re-run the test when either moves.
- **Disclosure:** this work was made with AI agents in the name of MV2 of Munim, Inc.

## Why BENIGN_TOP can shadow a gadget

keras-model-scan classifies a pickle `GLOBAL` by its **top-level package**. That
design is deliberately more evasion-resistant than an exact-name denylist (it
flags *every* submodule of a dangerous package), but it has a dual edge: when a
package is on the `BENIGN_TOP` *allowlist* — because its arrays and tensors are
ubiquitous in legitimate models — then a dangerous **submodule** of that same
package inherits the benign verdict unless a narrower rule is checked first.

keras-model-scan already checks one narrower rule before `BENIGN_TOP`:
`GADGET_MODULE_PREFIXES = ("numpy.f2py",)`. So `numpy.f2py.*` is correctly caught
as a gadget. The question this census answers is: **across all 19 BENIGN_TOP
packages, which picklescan-denied gadget paths are still shadowed?**

## Result (complete as of 2026-10-23)

Of picklescan's entire `_unsafe_globals`, exactly **11** denied modules sit under
a `BENIGN_TOP` package. Their keras-model-scan verdicts:

| picklescan path | picklescan denies | keras-model-scan now | status |
| --- | --- | --- | --- |
| `numpy.f2py` | `*` | gadget (via GADGET_MODULE_PREFIXES) | **carved** |
| `numpy.testing._private.utils` | `*` (`runstring()` = `exec()`) | benign | **blind** |
| `torch.serialization` | `load` | benign | blind |
| `torch._inductor.codecache` | `compile_file` | benign | blind |
| `torch.jit.unsupported_tensor_ops` | `execWrapper` | benign | blind |
| `torch._dynamo.guards` | `GuardBuilder.get` | benign | blind |
| `torch.fx.experimental.symbolic_shapes` | `ShapeEnv.evaluate_guards_expression` | benign | blind |
| `torch.utils._config_module` | `ConfigModule.load_config` | benign | blind |
| `torch.utils.bottleneck.__main__` | `run_cprofile`, `run_autograd_prof` | benign | blind |
| `torch.utils.collect_env` | `run` | benign | blind |
| `torch.utils.data.datapipes.utils.decoder` | `basichandlers` | benign | blind |

**10 blind, 1 carved.** The nine `torch.*` paths were already catalogued in
[`TORCH_GADGET_BLINDSPOT.md`](TORCH_GADGET_BLINDSPOT.md). The one path this
census **newly** surfaces is **`numpy.testing._private.utils`**: picklescan
denies the whole module because its `runstring()` is a documented synonym for
`exec()`, but because `numpy` is on `BENIGN_TOP` and `numpy.testing._private.utils`
does not start with `numpy.f2py.`, keras-model-scan currently resolves it to
`benign`. It is the only BENIGN_TOP-shadowed gadget path outside the torch
cluster with no carve-out.

## Honest limits

- This is a **source-level** mapping of two public lists. It executes no gadget
  and makes no exploitability claim beyond "picklescan denies this exact path,
  and keras-model-scan's current classifier resolves it to benign."
- `benign` here means *not surfaced as a dangerous/gadget finding*; it is not a
  claim that a real model pickle in the wild uses these paths.
- picklescan's `_unsafe_globals` is its own curation; mechanisms in the table are
  quoted from picklescan's annotations, not independently re-verified by execution.

## Planned fix

Extend `GADGET_MODULE_PREFIXES` so each shadowed path resolves to a recognised
RCE gadget **before** the `BENIGN_TOP` check, while an ordinary `numpy.ndarray`
or `torch.Tensor` global stays benign (no new false positives). Concretely, add
`numpy.testing._private.utils` alongside the nine torch paths in the upcoming
exact-match gadget layer, then flip its row here from *blind* to *carved*.
