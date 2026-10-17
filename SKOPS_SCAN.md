<!--
Copyright 2026 MV2, Munim, Inc. Licensed under the Apache License, Version 2.0.
This document was written with AI agents working in MV2's name.
-->
# `skops_scan` — static type auditor for skops (`.skops`) model files

`skops` is promoted as a **safe alternative to pickle** for sharing
scikit-learn models: instead of arbitrary bytecode, a `.skops` file is a ZIP
archive whose `schema.json` describes the object as a tree of typed **nodes**,
and on load skops only reconstructs a type if it is *trusted*. That trust
boundary is the whole security story — and it has been broken three times.

`skops_scan.py` reads a `.skops` file's `schema.json` **only**. It never
imports, reconstructs, unpickles, downloads or executes anything. It is a
no-execution review aid: it lists the types a file will ask you to trust and
flags the code-execution-capable ones — the same information skops'
`get_untrusted_types` gives you, but available before you call `load`, with no
skops install and no risk of running the file.

## The vulnerabilities it keys on

Every skops node dict carries the exact keys `"__class__"`, `"__module__"` and
`"__loader__"`. The loader name tells skops how to rebuild the value
(`ObjectNode`, `FunctionNode`, `TypeNode`, `MethodNode`, `OperatorFuncNode`,
container nodes, …). The 2025 CVEs all abuse that mechanism at **load time**:

| CVE | CWE / CVSS | Mechanism | Fixed in |
|-----|------------|-----------|----------|
| CVE-2025-54412 | CWE-351, 8.7 | `OperatorFuncNode` inconsistency: the file requests one innocent trusted type while a different operator method actually runs (code reuse). | skops 0.12.0 |
| CVE-2025-54413 | CWE-351, 8.7 | `MethodNode` reaches unexpected object fields by dot notation, needing even fewer trusted-type assumptions. | skops 0.12.0 |
| CVE-2025-54886 | CWE-502, ~8.4 | `Card.get_model` silently falls back to **joblib** (pickle → arbitrary code) when the file is *not* a valid ZIP. | skops 0.13.0 |

## Rules

| Rule | Severity | Fires on |
|------|----------|----------|
| `SKP001` | CRITICAL | A node whose `__module__` is an OS/process/eval sink (`os`, `posix`, `subprocess`, `importlib`, `runpy`, `ctypes`, `pickle`, …) or a dangerous `builtins` callable (`eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`, `open`, …). No trusted estimator serialises these. |
| `SKP002` | HIGH | An `OperatorFuncNode` or `MethodNode` loader, or any node in the `operator` module — the exact code-reuse surface of CVE-2025-54412 / CVE-2025-54413. |
| `SKP003` | MEDIUM | Any other object/function/type node whose module is outside a conservative ML allow-list (`numpy`, `scipy`, `sklearn`, `pandas`, `builtins`, `collections`, `xgboost`, `lightgbm`). skops will ask you to confirm these — a review signal, not a verdict. |
| `SKP010` | HIGH | A `*.skops` path that is **not** a valid ZIP. `skops.io.load` rejects it, but `Card.get_model` loads it with joblib/pickle (CVE-2025-54886). |

## Usage

```bash
# Audit one file, or walk a directory for *.skops, and emit JSON:
python skops_scan.py path/to/model.skops --json

# Fail CI if anything HIGH-or-worse is requested:
python skops_scan.py models/ --fail-on HIGH
```

Standard library only (`zipfile`, `json`, `os`, `argparse`); no third-party
dependency, no network, no code execution.

## Why this is new

No model-file scanner we found (ModelScan, picklescan, fickling, ModelAudit)
documents a rule that opens a `.skops` ZIP and audits the **types requested in
`schema.json`**; those tools target pickle opcodes, HDF5/SavedModel graphs, or
tensor containers. The sibling detectors in this repo cover a different surface
(pickle `REDUCE`/`GLOBAL`, safetensors, GGUF, ONNX external-data, HF/Hydra/
jsonargparse/YAML/Diffusers config instantiation) — none parse the skops
format. `skops_scan` mirrors skops' own trust model (`get_untrusted_types`)
statically, so a reviewer can see an auto-loadable code-execution type before
ever installing or loading the file.

## Honest limits

- This is a review aid, not an exploit, and claims **no new CVE**. It documents
  skops' published trust model and three fixed CVEs.
- It cannot perfectly reproduce skops' built-in trusted set, which changes
  across versions. `SKP003` is a conservative "please review", and a type
  outside the allow-list is frequently legitimate.
- It reads `schema.json` only; it never inspects the data blobs, so it reports
  which type a file *requests*, not what that type would do.
- The real fix is upgrading to **skops ≥ 0.13.0**, loading only from sources
  you trust, and reviewing `get_untrusted_types` output. A clean scan
  guarantees nothing.

---
Made with AI agents working in the name of MV2 of Munim, Inc. Licensed
Apache-2.0; this document is also available under CC BY 4.0.
