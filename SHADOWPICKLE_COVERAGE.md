<!-- Copyright 2026 MV2, Munim, Inc. Licensed under the Apache License, Version 2.0.
     Made with AI. -->
# `pickle_model_scan` vs. ShadowPickle (arXiv:2607.17503): a coverage result

This documents how `pickle_model_scan.py` (keras-model-scan) behaves against the
three published ShadowPickle evasion variants. The per-variant result was derived by
reading the scanner's source and then **confirmed empirically** in a sealed,
no-network sandbox (python:3.12, 2026-10-22): `shadowpickle_coverage_check.py`
reproduces each variant as an inert opcode stream, runs the real `scan_pickle_bytes`
on it (bytes are only disassembled with `pickletools.genops` — never unpickled,
imported or executed), and asserts the MISS/CATCH table below. All three
expectations held.

## The paper

ShadowPickle (Pradhan, Nambiar, Soremekun; submitted 2026-07-20) introduces three
"stealthy pickle deserialization attacks" that "leverage the external module import
mechanism of the Pickle VM to execute malicious payloads during deserialization."
They evade ten SOTA scanners and four model hubs; the **Overwritten** variant
reaches a **63% evasion rate**. Each attack keeps a *valid* pickle and relies on a
**whitelisted or non-blacklisted module name** rather than obfuscating the bytecode.

## The variants (from §IV-B)

1. **Overwritten Module** — `GLOBAL 'collections OrderedDict'` + a `BINUNICODE`
   payload + `REDUCE` + `BUILD`. It reuses a *whitelisted* stdlib name; the attacker
   separately overwrites that module's code (via a malicious PyPI package /
   `requirements.txt`) so its `__new__` runs `exec`. The pickle's opcode stream is
   **byte-identical in shape** to a legitimate `OrderedDict` reduce.
2. **PyPI Injected** — `GLOBAL 'raft run'` + `BINPUT` + `BINUNICODE` (a reverse
   shell). Imports a legitimate PyPI library that supports code execution and is not
   on scanner **blacklists**.
3. **External Modules** — `GLOBAL 'external dangerous_func'` + `BINPUT` +
   `BINUNICODE` (`import os; os.system(...)`). Imports a module packaged alongside
   the model; again, not blacklisted.

## How `pickle_model_scan` responds

The scanner does not use a *denylist*; it classifies every resolved `GLOBAL` /
`STACK_GLOBAL` import with `_classify(module, name)` into
`dangerous | gadget | benign | unknown`, and flags **everything that is not benign** —
including `unknown` (rule **PKL003**, MEDIUM). `BENIGN_TOP` contains `collections`
(among `numpy`, `torch`, `sklearn`, …).

| Variant | Resolved import | `_classify` | Scanner result |
|---|---|---|---|
| Overwritten | `collections.OrderedDict` | `benign` (`collections` ∈ `BENIGN_TOP`) | **MISS** — no finding |
| PyPI Injected | `raft.run` | `unknown` | **CATCH** — PKL003 (MEDIUM) |
| External Modules | `external.dangerous_func` | `unknown` | **CATCH** — PKL003 (MEDIUM) |

### Why the two catches matter

PyPI-Injected and External-Modules evade *blacklist* scanners precisely because
`raft` / `external` are not on any denylist. `pickle_model_scan` flags them anyway,
because an **allowlist** design treats *any* unrecognised reconstructor as
review-worthy (PKL003). This is a concrete, reproducible advantage of allowlisting
over denylisting against these two variants.

### Why Overwritten is a true miss — and is not fixable by opcode rules

The Overwritten pickle imports `collections.OrderedDict` and calls it — exactly
what countless legitimate pickles do. The malice lives in the **overwritten module's
code**, not in the pickle. At the opcode level the stream is indistinguishable from a
benign one, so **no static pickle scanner can catch it** without flagging essentially
every real pickle (an untenable false-positive rate). The honest mitigation is not a
new PKL rule but **dependency/environment integrity**: verify installed package
hashes, pin and audit `requirements.txt`, and load models in an environment whose
stdlib/site-packages are trusted. `pickle_model_scan` should document this limit
plainly rather than imply a clean scan is safety.

## Honest limits

- Determined from the scanner's source and confirmed empirically on inert opcode
  streams. Neither step unpickles, imports, or runs anything — bytes are only
  disassembled with `pickletools.genops`.
- The paper's full opcode listings for the two non-"Overwritten" variants were read
  from the HTML preprint; the exact payload strings here are illustrative, but the
  **import target** (what `_classify` keys on) is faithful to §IV-B.
- This is a coverage result, not a new vulnerability or a huntr report.

## Reproduce

`shadowpickle_coverage_check.py` (shipped alongside) builds each variant's opcode
stream and asserts the MISS/CATCH table above against the live `pickle_model_scan`
module. Run from the repo root: `python shadowpickle_coverage_check.py`
(exit 0 iff all three expectations hold).

Made with AI, in the name of MV2 of Munim, Inc. Apache-2.0.
