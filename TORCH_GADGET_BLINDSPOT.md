# torch.* gadget blind spot: where a whole-framework allowlist misses that framework's own gadgets

**Made with AI agents working in the name of MV2 of Munim, Inc. Text and data CC BY 4.0; code Apache-2.0.**

Machine-readable, test-backed companion to
[`torch_gadget_blindspot.py`](./torch_gadget_blindspot.py) and
[`PICKLESCAN_SPECIFIC_AXIS.md`](./PICKLESCAN_SPECIFIC_AXIS.md). It isolates and
makes executable the single most material coverage gap in `pickle_model_scan.py`.

## The finding

keras-model-scan classifies a pickle `GLOBAL` by its **top-level package**: it
looks up `module.split(".", 1)[0]` against a dangerous-module denylist and a
`BENIGN_TOP` allowlist. The top-package design is what makes it structurally
immune to picklescan's exact-match submodule-bypass class (CVE-2025-10157) — a
single denylist entry subsumes every current and future submodule of a
dangerous package.

The mirror image of that strength is a weakness. The whole `torch` package sits
on `BENIGN_TOP`. But upstream **picklescan** — the Hugging Face-standard
scanner — denies **nine exact `torch.*` paths** as code-execution gadgets. For
every one of them, keras-model-scan's classifier takes the `top == "torch"`
→ benign branch and raises **no finding**. PyTorch `.bin` checkpoints are the
most common pickle-based model format in the wild, so this is the most
consequential gap the toolkit currently has.

## The nine paths (mirrored from picklescan, live 2026-10-23)

| picklescan path | denied callable(s) | why picklescan denies it | keras-model-scan today |
|---|---|---|---|
| `torch.serialization` | `load` | re-enters checkpoint/pickle loading on an attacker path | **benign (missed)** |
| `torch._inductor.codecache` | `compile_file` | writes + compiles a source file → code execution | **benign (missed)** |
| `torch.jit.unsupported_tensor_ops` | `execWrapper` | `exec()` wrapper | **benign (missed)** |
| `torch._dynamo.guards` | `GuardBuilder.get` | resolves/evaluates attribute expressions | **benign (missed)** |
| `torch.fx.experimental.symbolic_shapes` | `ShapeEnv.evaluate_guards_expression` | evaluates a guard expression string | **benign (missed)** |
| `torch.utils._config_module` | `ConfigModule.load_config` | loads config state that can carry payloads | **benign (missed)** |
| `torch.utils.bottleneck.__main__` | `run_cprofile`, `run_autograd_prof` | profiles a target by running it | **benign (missed)** |
| `torch.utils.collect_env` | `run` | runs a shell command via subprocess | **benign (missed)** |
| `torch.utils.data.datapipes.utils.decoder` | `basichandlers` | decoder dispatch reachable as a pickle global | **benign (missed)** |

The "why picklescan denies it" column summarises picklescan's own curation; it
is a source-level reading of both denylists, **not** re-verified by executing
any gadget. No exploit was run and none is claimed here beyond "picklescan
denies this exact path."

## Why this is new (and honest about its limits)

- The two coverage axes already published in this repo measure picklescan's
  *wildcard* denylist (18 of 36 modules recognised) and its *specific-name*
  denylist (11 recognised / 11 flagged-weakly / **9 torch benign**). This file
  lifts the 9-path blind bucket into a standalone, machine-readable ledger with
  an executable invariant, so any future drift in either list — picklescan
  adding a torch path, or the scanner closing the gap — breaks a test.
- Re-verified 2026-10-23 against both live sources: picklescan's denylist is
  unchanged (36 wildcard + 31 specific entries, no drift), and the live
  `pickle_model_scan.py` v0.2.1 still has `torch` on `BENIGN_TOP`, absent from
  `DANGEROUS_MODULES`, with no exact-match gadget-path layer.
- Limit: this is a defensive-coverage mapping between two public lists, not a
  new vulnerability. The gadgets themselves are picklescan's, not ours.

## The fix (queued behind v0.48.0)

Add an exact-match `GADGET_MODULE_PATHS` set (these nine paths) checked
**before** the `BENIGN_TOP` allowlist, so each path resolves to a recognised
gadget while an ordinary `torch.Tensor` / `torch.nn` global stays benign. The
carve-out must be exact-path, not top-package, or it would flag every benign
torch global — the accompanying test pins exactly that property. Once shipped,
the 9 move out of the blind bucket in the specific-name census, keeping the
coverage story in sync with the code.
