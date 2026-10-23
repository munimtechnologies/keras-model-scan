<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 Munim, Inc. Made with AI agents working in MV2's name. -->

# picklescan's specific-name denylist vs a top-package classifier: a blind spot in the allowlist

This is the companion to [`PICKLESCAN_COVERAGE_DIFF.md`](PICKLESCAN_COVERAGE_DIFF.md),
which compared keras-model-scan's top-level-package pickle classifier against
picklescan's **wildcard** denylist entries (whole-module `"*"` entries) and found it
covers 18 of 36. picklescan's `_unsafe_globals` has a **second half**, though: entries
that deny a *specific set of names* inside a module rather than the whole module. Those
are the framework- and helper-specific gadgets picklescan has learned one CVE at a time
— `functools.partial`, `types.CodeType`, the `idlelib.*` submodules, and a block of
`torch.*` internals. This document maps that second axis onto the top-package
classifier's buckets, and it surfaces a real blind spot in keras-model-scan's own
allowlist.

Everything here is a static reproduction of **both tools' published classification
rules** (it does not execute either scanner), from sources fetched live on 2026-10-23:
picklescan `src/picklescan/scanner.py` (`main`) and keras-model-scan
`pickle_model_scan.py` v0.2.1. The partition is re-derived and pinned by
[`test_picklescan_specific_axis.py`](picklescan_specific_axis.py). Work made with AI
agents in MV2's name.

## How a top-package classifier routes a global

keras-model-scan resolves a pickled `GLOBAL` / `STACK_GLOBAL` operand to its top-level
package (`module.split(".", 1)[0]`) and routes it, in order:

1. gadget prefix (`numpy.f2py`) → **PKL005, CRITICAL**;
2. a `builtins`/`__builtin__` name in `DANGEROUS_BUILTINS` → **PKL001/PKL002**;
3. a package in `DANGEROUS_MODULES` → **PKL001/PKL002** (CRITICAL with a code-exec
   opcode, HIGH without);
4. a `functools`/`operator` gadget name → **PKL004, HIGH**;
5. a package on the `BENIGN_TOP` allowlist → **benign, no finding at all**;
6. anything else → **PKL003, "unknown import", MEDIUM**.

Step 5 is the catch. `torch` is on `BENIGN_TOP` and is *not* in `DANGEROUS_MODULES`.

## Result: 11 recognised, 11 unknown-only, 9 BENIGN (blind spot) of 31

Of picklescan's 31 specific-name module keys, the top-package classifier:

- **recognises 11 as dangerous/gadget imports** (its strong case) — including every
  `idlelib.*` submodule, because `idlelib` is a *whole-package* dangerous module, so
  keras-model-scan is strictly **more** complete than picklescan's enumeration of five
  `idlelib.*` names here;
- **surfaces 11 only as an "unknown import" (PKL003, MEDIUM)** — it flags them, but as
  an allowlist miss, not as a *recognised* gadget. A triager sees "unknown import,"
  not "known RCE gadget";
- **classifies 9 as benign and does not flag them at all** — and all nine are the
  `torch.*` paths picklescan explicitly denies.

### The blind spot (the headline)

```
torch._dynamo.guards
torch._inductor.codecache
torch.fx.experimental.symbolic_shapes
torch.jit.unsupported_tensor_ops
torch.serialization
torch.utils._config_module
torch.utils.bottleneck.__main__
torch.utils.collect_env
torch.utils.data.datapipes.utils.decoder
```

picklescan's maintainers added these to its denylist as unsafe-to-unpickle. Because
`torch` is on keras-model-scan's `BENIGN_TOP` allowlist, a pickle whose reduce gadget
is one of these paths is scored **clean** by keras-model-scan today. PyTorch `.pt`/`.bin`
files are the single most common pickle-based model format in the wild, so this is the
most material gap the toolkit has, and it is a direct consequence of the same allowlist
that keeps false positives low on ordinary `torch.Tensor` payloads.

This does **not** contradict the wildcard-axis result — on whole-module unsafe packages
the top-package rule is broader and more submodule-bypass-resistant. It qualifies the
"broader" story honestly: an allowlist that treats a whole ML framework as benign will
miss that framework's own deserialization gadgets unless those specific paths are carved
back out.

### Fix roadmap (defensible, one change)

Carve the nine denylisted `torch.*` paths out of the `torch` allowlist: add a
`GADGET_MODULE_PATHS` exact-match set (or extend `GADGET_MODULE_PREFIXES`) checked
*before* `BENIGN_TOP`, so these resolve to a recognised gadget finding while the rest of
`torch.*` stays benign. Mirror picklescan's maintained list and keep it in sync. The
same mechanism promotes the 11 "unknown import" entries (`types`, `_operator`, …) to
recognised gadgets if desired, but the `torch.*` carve-out is the one that closes a true
miss rather than merely raising a severity.

## Full routing table

| picklescan specific-name module | keras-model-scan routing | finding |
|---|---|---|
| `__builtin__` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `_io` | unknown import only | PKL003 |
| `_operator` | unknown import only | PKL003 |
| `builtins` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `cloudpickle.cloudpickle` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `code` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `doctest` | unknown import only | PKL003 |
| `ensurepip` | unknown import only | PKL003 |
| `functools` | recognised (dangerous/gadget) | PKL004 |
| `idlelib.autocomplete` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `idlelib.calltip` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `idlelib.debugobj` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `idlelib.pyshell` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `idlelib.run` | recognised (dangerous/gadget) | PKL001/PKL002 |
| `imaplib` | unknown import only | PKL003 |
| `lib2to3.pgen2.grammar` | unknown import only | PKL003 |
| `lib2to3.pgen2.pgen` | unknown import only | PKL003 |
| `logging` | unknown import only | PKL003 |
| `operator` | recognised (dangerous/gadget) | PKL004 |
| `pkgutil` | unknown import only | PKL003 |
| `torch._dynamo.guards` | BENIGN -- not flagged | (none) |
| `torch._inductor.codecache` | BENIGN -- not flagged | (none) |
| `torch.fx.experimental.symbolic_shapes` | BENIGN -- not flagged | (none) |
| `torch.jit.unsupported_tensor_ops` | BENIGN -- not flagged | (none) |
| `torch.serialization` | BENIGN -- not flagged | (none) |
| `torch.utils._config_module` | BENIGN -- not flagged | (none) |
| `torch.utils.bottleneck.__main__` | BENIGN -- not flagged | (none) |
| `torch.utils.collect_env` | BENIGN -- not flagged | (none) |
| `torch.utils.data.datapipes.utils.decoder` | BENIGN -- not flagged | (none) |
| `trace` | unknown import only | PKL003 |
| `types` | unknown import only | PKL003 |

**11 recognised, 11 unknown-only, 9 BENIGN (blind spot)** of 31 picklescan specific-name entries.

## Honest limits

- A static reproduction of both denylists/classifiers; it asserts what each tool *would
  report*, derived from source, not from running them. Re-fetch both files to refresh
  the snapshots (`PICKLESCAN_SPECIFIC_MODULES`, `KMS_BENIGN_TOP`, `KMS_DANGEROUS_MODULES`).
- "Blind" means keras-model-scan v0.2.1 emits no finding for that path; it is not a
  claim that each `torch.*` path is a proven, weaponised RCE — picklescan's maintainers
  classified them unsafe, and this document reports that keras-model-scan does not.
- The 11 "unknown import" entries are still surfaced at MEDIUM; they are a precision gap
  (unknown vs recognised), not a miss.
