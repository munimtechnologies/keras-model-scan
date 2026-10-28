# torch_module_wrapper_scan — Keras `TorchModuleWrapper` RCE detector

`torch_module_wrapper_scan.py` is a small, dependency-free detector for a specific
code-execution sink in serialized Keras 3 models: the **`TorchModuleWrapper`** layer.

## Why this exists

Keras 3's `keras.layers.TorchModuleWrapper` serializes the PyTorch module it wraps by
`torch.save`-ing it to a buffer and base64-encoding the bytes into the layer `config`
under the key `"module"` (see `keras/src/utils/torch_utils.py`). On load,
`TorchModuleWrapper.from_config` base64-decodes that string and calls
`torch.load(buffer, weights_only=False)` — it unpickles attacker-controllable bytes.
Opening a model file from an untrusted source can therefore run arbitrary code.
This is **CWE-502** (Deserialization of Untrusted Data).

Two public CVEs track this exact class:

| CVE | CVSS | Affected | Note |
| --- | --- | --- | --- |
| **CVE-2026-12484** | 7.8 (HIGH) | keras 3.15.0 | `from_config` does not enforce safe deserialization by default outside a `SafeModeScope(True)` context. |
| **CVE-2025-49655** | 9.8 (CRITICAL) | keras 3.11.0–3.11.2 | The `torch.load` call bypassed even Keras "safe mode" (HiddenLayer disclosure). |

### The detection gap this closes

The main Keras config walk (`keras_model_scan.py`) enumerates class names such as
`Lambda` (KMS002) and `TFSMLayer` (KMS004), but **not** `TorchModuleWrapper`; its
module (`keras.layers`) is on the allowlist, so KMS001 skips it. Meanwhile the pickle
scanner reads pickle *streams*, but here the payload is a **base64 string inside JSON**,
so it is never handed a stream to inspect. Two orthogonal defenses each legitimately
decline the file, and a crafted `TorchModuleWrapper` model scans clean. This detector
enumerates the sink class statically, the same way we already enumerate `Lambda`.

## What it reports

- **TMW001 (HIGH, CWE-502, CVE-2026-12484)** — a `TorchModuleWrapper` layer is present
  (matched by `class_name` or `registered_name`, bare/dotted/`pkg>Name` forms).
- **TMW002 (HIGH, CWE-502, CVE-2026-12484)** — the wrapper's `config.module` holds a
  base64 payload that decodes to a `torch.save` zip archive or a pickle stream; the
  evidence names any code-execution opcodes found (`pickletools` only parses, it never
  executes the pickle).

## Usage

```bash
python torch_module_wrapper_scan.py model.keras           # a .keras archive
python torch_module_wrapper_scan.py config.json           # a raw config
```

Exit code `1` on any HIGH finding, `0` if clean, `2` on a usage/read error. The module
also exposes `scan_bytes(data)` and `scan_file(path)` returning a list of finding dicts
(`rule`, `severity`, `cve`, `cwe`, `message`, `evidence`).

## Scope and honest limits

- Static and read-only: it parses JSON/zip structure only; it never imports `keras` or
  `torch` and never unpickles anything.
- It flags the **presence** of the sink, which is the supply-chain signal that matters
  for an untrusted model file; it does not and cannot decide whether a particular model
  was built maliciously. A legitimately-produced `TorchModuleWrapper` model will also be
  flagged — that is intended, because loading any of them invokes `torch.load`.
- This is a standalone detector. Wiring it into the unified `model_file_scan.py` entry
  and the central `model_file_cve_map.json` (as rule KMS008) is tracked separately.

This work was made with AI by MV2 of Munim, Inc. Part of
`munimtechnologies/keras-model-scan`, licensed under the Apache License, Version 2.0.
