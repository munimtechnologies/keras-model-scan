# `BENIGN_TOP` submodule-shadow audit: 10 pristine-library gadget paths `pickle_model_scan` 0.2.1 silently clears

Source-review audit of `pickle_model_scan.py` (`__version__ = "0.2.1"`, release
v0.47.0). No code was executed; every claim below is read from source and is
flagged for confirmation by a sealed proof-of-concept job (spec at the end).
Work made with AI agents in MV2's name.

## TL;DR

`pickle_model_scan`'s global classifier `_classify(module, name)` keys its
benign allowlist on the **top-level package only**, and clears the entire
package tree of anything in `BENIGN_TOP` (`numpy`, `torch`, `scipy`, `sklearn`,
`pandas`, `joblib`, `transformers`, `keras`, `tensorflow`, `torchvision`,
`xgboost`, `lightgbm`, plus stdlib helpers). The one exception is a single
carve-out, `GADGET_MODULE_PREFIXES = ("numpy.f2py",)`, checked before the
benign check.

As a result, **10 dangerous callables that the de-facto reference scanner
`picklescan` flags in its `_unsafe_globals` list — all of which live in
*unmodified, pip-installed* `torch` and `numpy` submodules — are classified
`"benign"` and produce no Finding at all.** Nine are under `torch.*`; one is
`numpy.testing._private.utils`.

This is not the ShadowPickle "Overwritten" miss already documented in
[`SHADOWPICKLE_COVERAGE.md`](SHADOWPICKLE_COVERAGE.md). That one requires the
attacker to have replaced a legitimate library's *code* and is argued to be
statically uncatchable. The gap here is the opposite: the gadget lives in the
**pristine** library, the full dotted path is **present in the pickle opcode
stream**, so it is statically visible and statically fixable — and a widely-used
peer scanner already catches it.

## How the clear happens (verified from source)

`_classify(module, name)` computes `top = module.split(".", 1)[0]` and runs its
checks in this order:

1. `GADGET_MODULE_PREFIXES` (only `numpy.f2py`) → `"rce_gadget"`.
2. `builtins` / `__builtin__` / `__builtins__` → dangerous iff name in `DANGEROUS_BUILTINS`.
3. `top in DANGEROUS_MODULES` → `"dangerous"`. (`DANGEROUS_MODULES` is a set of
   **top-level** names: `os`, `subprocess`, `sys`, `socket`, `ctypes`,
   `asyncio`, `idlelib`, … — it does **not** contain `torch` or `numpy`.)
4. `functools.partial/reduce`, `operator.attrgetter/methodcaller` → `"gadget"`.
5. **`top in BENIGN_TOP` → `"benign"`.**  ← the shadow
6. else → `"unknown"`.

In the scan loop, a resolvable global whose class is `"benign"` matches none of
the finding branches (PKL001/002 need `"dangerous"`, PKL005 needs
`"rce_gadget"`, PKL004 needs `"gadget"`, PKL003 needs `"unknown"`; PKL007 needs
`not resolvable`). The only opcode-driven signal, `exec_ops` (REDUCE / BUILD /
STACK_GLOBAL counting), **only raises severity inside the dangerous/rce_gadget
branches** — it never promotes a `"benign"` import to a finding. So the path is
silently cleared regardless of the surrounding opcodes.

Because these 10 modules are importable in a normal torch/numpy install, they
are **resolvable**, so PKL007 does not catch them either.

## The 10 shadowed paths (reference: `picklescan` `_unsafe_globals`)

All ten appear in `picklescan`'s `_unsafe_globals` (module `picklescan/scanner.py`)
with an explicit danger note. Their top-level package is in `pickle_model_scan`'s
`BENIGN_TOP`; none matches the `numpy.f2py` carve-out; so all ten are cleared.

| # | path (`module` : `name`) | picklescan's stated danger | `pickle_model_scan` 0.2.1 result |
|---|---|---|---|
| 1 | `torch._inductor.codecache` : `compile_file` | `compile_file('', '', ['sh','-c','$(echo pwned)'])` — direct command execution | `benign` (no finding) |
| 2 | `numpy.testing._private.utils` : `runstring` | `runstring()` is a synonym for `exec()` | `benign` (no finding) |
| 3 | `torch.jit.unsupported_tensor_ops` : `execWrapper` | wraps `exec` | `benign` (no finding) |
| 4 | `torch.fx.experimental.symbolic_shapes` : `ShapeEnv.evaluate_guards_expression` | evaluates an attacker expression | `benign` (no finding) |
| 5 | `torch._dynamo.guards` : `GuardBuilder.get` | guard-expression evaluation path | `benign` (no finding) |
| 6 | `torch.serialization` : `load` | pickle-inside-a-pickle (loads a second file) | `benign` (no finding) |
| 7 | `torch.utils._config_module` : `ConfigModule.load_config` | pickle-inside-a-pickle | `benign` (no finding) |
| 8 | `torch.utils.data.datapipes.utils.decoder` : `basichandlers` | pickle-inside-a-pickle | `benign` (no finding) |
| 9 | `torch.utils.bottleneck.__main__` : `run_cprofile`, `run_autograd_prof` | profiler entry points that run code | `benign` (no finding) |
| 10 | `torch.utils.collect_env` : `run` | runs shell commands | `benign` (no finding) |

Severity is not uniform and this audit does not inflate it: #1 and #2 are direct
code/command execution; #3–#5 evaluate attacker-controlled expressions; #6–#8
are "pickle-in-pickle" nesting gadgets (dangerous as a chaining primitive, not
standalone RCE); #9–#10 run external commands/profilers. The claim is only that
all ten are **flagged by the reference scanner and missed here** — the precise
exploitability of each is the upstream (picklescan) maintainers' assessment plus
a reading of the callables, not independently reproduced in this run.

## Scope and honest limits

- **This is a false-negative in MV2's own defensive scanner, not a huntr
  Model-File-Vulnerability.** It is a tool-quality/coverage gap, documented
  openly so it can be fixed; it is not a vulnerability report against torch or
  numpy. The underlying gadgets are already public (picklescan ships them).
- **No execution.** The "no finding" column is a source-review conclusion from
  reading `_classify` and the scan loop, to be confirmed by the PoC job below.
- **Not a claim about scipy/sklearn/pandas/joblib/transformers/keras/
  tensorflow/torchvision.** Those top-level packages are *also* fully cleared by
  `BENIGN_TOP`, which is a broader latent risk of top-level allowlisting, but
  `picklescan` currently lists no `_unsafe_globals` under them, so this audit
  asserts no concrete false-negative there — only that the same mechanism would
  shadow any future gadget found in them.
- **Allowlisting is a deliberate design choice** (it keeps false positives low;
  see `SHADOWPICKLE_COVERAGE.md`). The fix below preserves that design: it adds
  a small, precise denylist of known-dangerous *sub-paths* that is consulted
  **before** the top-level benign clear — exactly as `numpy.f2py` already is.

## Fix (specified, to land via a sandbox job — see below)

Mirror the existing `numpy.f2py` mechanism. Add the 10 dangerous sub-paths as a
denylist checked at the same point as `GADGET_MODULE_PREFIXES`, before the
`BENIGN_TOP` clear, classifying them `"rce_gadget"` (→ PKL005). Precise sub-paths
(module-prefix granularity, which is what the opcode stream exposes):

```
DANGEROUS_SUBPATHS = (
    "torch._inductor.codecache",
    "torch.jit.unsupported_tensor_ops",
    "torch.fx.experimental.symbolic_shapes",
    "torch._dynamo.guards",
    "torch.serialization",
    "torch.utils._config_module",
    "torch.utils.data.datapipes.utils.decoder",
    "torch.utils.bottleneck",
    "torch.utils.collect_env",
    "numpy.testing._private.utils",
)
```

Check: `if any(module == p or module.startswith(p + ".") for p in
DANGEROUS_SUBPATHS): return "rce_gadget"`, placed immediately after the existing
`GADGET_MODULE_PREFIXES` check. This keeps the allowlist intact for every other
`torch.*`/`numpy.*` path (e.g. `torch.FloatStorage`, `numpy.ndarray` stay
benign) and raises the ten real gadgets to the same severity picklescan assigns.

## Proof-of-concept spec (sealed `poc` compute job, no network in run steps)

Pure disassembly — the gadgets are **never unpickled or executed**, only their
opcode streams are built and scanned.

1. For each of the 10 paths, emit a minimal pickle whose opcode stream contains
   a `GLOBAL`/`STACK_GLOBAL` for `module\nname` plus a trailing REDUCE (hand-
   assembled bytes; no real unpickling). `torch`/`numpy` need not be installed —
   the scanner only disassembles.
2. Run current `pickle_model_scan.scan_pickle_bytes` on each → assert **0
   findings** (reproduces the miss).
3. Apply the `DANGEROUS_SUBPATHS` patch → assert each now yields a PKL005
   finding and that a control set (`torch.FloatStorage`, `numpy.core.multiarray._reconstruct`,
   `collections.OrderedDict`) still yields 0 findings (no new false positives).
4. Ship as `pickle_model_scan` 0.3.0 + repo test `test_benign_top_shadow.py`
   once green.

---

*Part of `munimtechnologies/keras-model-scan` (Apache-2.0). Authored by MV2 of
Munim, Inc. with AI agents; findings are source-review conclusions pending the
sandbox confirmation described above.*
