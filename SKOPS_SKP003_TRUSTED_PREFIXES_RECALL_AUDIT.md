# Recall audit: the skops scanner's SKP003 `TRUSTED_PREFIXES` blindspot

**Project:** `munimtechnologies/keras-model-scan` — `skops_scan.py` (as of release v0.47.0)
**Scope:** source review only, no execution. This is a **tool-coverage (recall) finding on our
own open-source scanner**, not a new third-party vulnerability. All third-party sinks named
below are documented, by-design behaviors or already-patched issues in their own projects.
**Author:** MV2 of Munim, Inc. Work made with AI agents in MV2's name.

---

## Summary

`skops_scan.py` classifies each node in a `.skops` archive's `schema.json` with four rules.
SKP003 is the only **catch-all backstop** — a conservative "please review this object from an
unexpected place" MEDIUM. SKP003 is **suppressed whenever a node's top-level package is in
`TRUSTED_PREFIXES`**. SKP001 (CRITICAL) and SKP002 (HIGH) have no such exemption, but they
only match a **fixed denylist** (`DANGEROUS_MODULES`) and a **fixed set of calling node types**
(`OperatorFuncNode`/`MethodNode`/`operator`), respectively.

The gap: **a dangerous callable whose own `__module__` sits under a trusted top-level package
evades all four rules.** It is not in `DANGEROUS_MODULES` (so SKP001 is silent), it is not a
risky loader (so SKP002 is silent), and its top-level package is trusted (so SKP003 is
suppressed). This is the **skops analogue of the r188 pickle `BENIGN_TOP` false-negative**
(where pristine `torch`/`numpy` gadget paths cleared benign), now found in a second scanner.

---

## The four rules, exactly as implemented (source review, v0.47.0)

`_classify(node)` extracts `module` (`__module__`), `cls` (`__class__`), `loader`
(`__loader__`), and returns the **first** match (highest severity by order):

1. **SKP001 (CRITICAL)** — fires if the node's **top-level package** (module split at first `.`)
   is in `DANGEROUS_MODULES`, **or** the **full module string** is in `DANGEROUS_MODULES`,
   **or** (`module == "builtins"` **and** `cls` in `DANGEROUS_BUILTINS`).
   - `DANGEROUS_MODULES` = {`os`, `posix`, `nt`, `subprocess`, `sys`, `socket`, `shutil`,
     `pty`, `importlib`, `runpy`, `code`, `codeop`, `pickle`, `_pickle`, `marshal`, `ctypes`,
     `multiprocessing`, `pdb`, `webbrowser`}.
   - `DANGEROUS_BUILTINS` = {`eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`,
     `delattr`, `open`, `input`, `breakpoint`, `exit`, `quit`}.

2. **SKP002 (HIGH)** — fires if `loader` in `RISKY_LOADERS` = {`OperatorFuncNode`,
   `MethodNode`}, **or** `module == "operator"`.

3. **SKP003 (MEDIUM)** — fires if `loader` is truthy **and** `loader` not in
   `STRUCTURAL_LOADERS` **and** `_top_package(module) not in TRUSTED_PREFIXES`.
   - `TRUSTED_PREFIXES` = {`numpy`, `scipy`, `sklearn`, `pandas`, `builtins`, `collections`,
     `skops`, `xgboost`, `lightgbm`}.

4. **SKP010 (HIGH)** — separate, in `scan_file`: non-ZIP path ending `.skops` (joblib/pickle
   fallback). Unrelated to node classification.

**The decisive line:** SKP003's guard is `_top_package(module) not in TRUSTED_PREFIXES`. For a
node whose `module` is e.g. `pandas.io.pickle`, `_top_package` returns `pandas`, which is in
`TRUSTED_PREFIXES`, so **SKP003 never fires** — and nothing else does either.

---

## Concrete blindspot cases

Each row is a **real callable whose own `__module__` is under a trusted prefix** (not an
`os`/`subprocess` re-export — those resolve to `__module__ == "os"` etc. and are caught by
SKP001; and dot-notation traversals like `pandas.compat.os.system` surface as `MethodNode`,
caught by SKP002). These are the cases that genuinely evade all four rules:

| Callable (own `__module__`.`__qualname__`) | Trusted top-level | Real sink / reference | SKP001? | SKP002? | SKP003? |
|---|---|---|---|---|---|
| `pandas.io.pickle` → `read_pickle` | `pandas` | wraps `pickle.load`; CVE-2020-13091; 2026 LLM-agent dispatch RCE reports | no | no | **suppressed** |
| `pandas.core.computation.eval` → `eval` (`pandas.eval`) | `pandas` | string → `eval`-class evaluation | no | no | **suppressed** |
| `numpy.lib.npyio` → `load` (`numpy.load`) | `numpy` | `allow_pickle=True` → `pickle.load` | no | no | **suppressed** |
| `numpy.distutils.exec_command` → `exec_command` (numpy < 2.0) | `numpy` | runs a shell command | no | no | **suppressed** |
| numpy.random attribute resolved-and-called from file | `numpy` | the exact class skops patched in v0.15 as a trusted-type bypass | no | no | **suppressed** |

Why each column is "no":
- **SKP001:** none of `pandas`, `pandas.io.pickle`, `pandas.core.computation.eval`, `numpy`,
  `numpy.lib.npyio`, `numpy.distutils.exec_command` is in `DANGEROUS_MODULES` (that set carries
  bare `pickle`/`os`/`ctypes`, not these dotted trusted-package modules); `module != "builtins"`.
- **SKP002:** the loader is not `OperatorFuncNode`/`MethodNode` and `module != "operator"`.
- **SKP003:** `_top_package` ∈ `{pandas, numpy}` ⊂ `TRUSTED_PREFIXES` → the guard short-circuits.

---

## Why this is new (prior art checked)

- The **pandas `read_pickle` / `eval` gadgets** are well documented (CVE-2020-13091;
  pandas-dev/pandas#67074; the "two shortest pandas→RCE paths" research; Semgrep PY511).
- **skops' own trusted-type bypasses** are documented separately: the HiddenLayer 2024 report
  and GitLab advisories cover OperatorFuncNode/MethodNode and the Card joblib-fallback, and the
  skops v0.15 changelog records the numpy.random attribute-resolution fix.
- **r188** characterized the analogous `BENIGN_TOP` submodule false-negative in our *pickle*
  scanner.

What has **not** been done before: a **rule-by-rule recall characterization of this scanner's
SKP001/SKP002/SKP003 against the specific trusted-package gadget paths**, showing that the
`TRUSTED_PREFIXES` exemption removes SKP003's backstop for sinks whose own `__module__` lives
under `pandas`/`numpy`/`scipy`/`sklearn`, with a scoped sub-path denylist fix. It is the same
structural over-trust the r188 pickle finding documented, now confirmed in a second scanner —
a cross-scanner pattern worth fixing consistently.

---

## Honest limits

- **Tool-coverage, not a new CVE.** This describes a recall blindspot in our scanner's
  conservative backstop rule. The third-party sinks are documented/by-design; skops' own
  numpy.random case is already patched upstream.
- **Per-gadget reachability inside skops' loader is unconfirmed here.** A pure function/type
  reference loaded by skops may be resolved into memory without being *called* unless paired
  with a calling node (which SKP002 already catches). SKP003 exists precisely because some skops
  node types resolve-and-call trusted-package attributes directly — the v0.15 numpy.random fix
  proves at least one such path has existed. Confirming reachability per gadget needs a sealed,
  default-settings PoC (a compute slot); none was run for this audit.
- **Verification method:** source review of the exact `_classify` conditions and the
  `TRUSTED_PREFIXES` / `DANGEROUS_MODULES` / `DANGEROUS_BUILTINS` / `RISKY_LOADERS` sets at
  v0.47.0. No file was executed or reconstructed.

---

## Scoped fix spec (ready for a compute slot)

Mirror the r188 pickle `BENIGN_TOP` sub-path denylist for skops:

1. Add `TRUSTED_PREFIX_SUBPATH_DENYLIST` = full dotted modules that are *under* a trusted
   top-level package but known-dangerous, e.g. `pandas.io.pickle`,
   `pandas.core.computation.eval`, `numpy.lib.npyio` (for `load`), `numpy.distutils`,
   `numpy.ctypeslib`, plus a prefix rule for any `<trusted>.*.os` / `.subprocess` / `.sys`
   submodule re-export.
2. In `_classify`, before the SKP003 trusted-prefix short-circuit, fire a finding (keep MEDIUM
   as SKP003, or add **SKP004 MEDIUM** "dangerous callable under a trusted package") when the
   node's **full dotted module** matches the denylist, even though its top-level package is
   trusted.
3. Add a test asserting `pandas.io.pickle.read_pickle` and `pandas.core.computation.eval.eval`
   each produce a finding, and that a genuinely benign `numpy.ndarray` node still does not.
4. Ship as a `skops_scan` patch release with notes naming the corrected recall behavior.

Because this edits a **live scanner module and its test**, it must run as a **compute job**
(sealed sandbox), not `test_first` publish. Queue it when a slot frees.

---

## AI disclosure

This audit and its findings were produced by AI agents working in MV2's name at Munim, Inc.
Verifiable by reading `skops_scan.py` at the stated release; no execution was performed.
