<!-- Copyright 2026 MV2, Munim, Inc. Licensed under the Apache License, Version 2.0. -->
# `mlflow_manifest_scan` — MLflow `MLmodel` loader-dispatch detector

A static, no-execution detector for the MLflow `MLmodel` manifest. It reads the
manifest's YAML text only — it never imports a module, resolves a `loader_module`,
unpickles an artifact, or loads a model. Part of
[`keras-model-scan`](./README.md). Made with AI, in the name of MV2, Munim, Inc.

## Why this exists

Every MLflow model ships a small YAML manifest named `MLmodel` at the root of the
model directory. Its `flavors` block says how to load the model. The generic
`python_function` flavor carries a `loader_module` key — a dotted Python module
path:

```yaml
artifact_path: model
flavors:
  python_function:
    loader_module: mlflow.statsmodels
    model_path: model.pkl
    python_version: 3.10.12
  statsmodels:
    data: model.statsmodels
    statsmodels_version: 0.14.0
mlflow_version: 2.9.2
```

When any process calls `mlflow.pyfunc.load_model()` on that directory, MLflow reads
`loader_module` from the `MLmodel` file and resolves it with
`importlib.import_module(loader_module)` — **with no allowlist** — then calls that
module's `_load_pyfunc` entry point. The dotted string in the manifest therefore
selects which code runs at load time, and the manifest also names the artifact that
gets deserialized. This detector surfaces both before anything is loaded.

### Public precedent (already disclosed; this documents the class)

- **`GHSA-gqvg-gmmx-x4hm`** — mlflow (PyPI), introduced 2.1.0, **fixed 3.15.0**,
  CWE-502, CVSS **8.8**. MLflow offers `MLFLOW_ALLOW_PICKLE_DESERIALIZATION`, which
  operators set to `False` to block unsafe pickle loading. The `mlflow.statsmodels`
  flavor **omits that guard**: its loader calls a thin `pickle.load` wrapper
  unconditionally, so a crafted `MLmodel` using `loader_module: mlflow.statsmodels`
  plus a malicious pickle executes code on `load_model()` **even when the control is
  set to False**. Fixed by adding the guard to the statsmodels flavor in 3.15.0.
- **CVE-2024-37052 … CVE-2024-37060** — the broader MLflow model-loading
  deserialization family: loading an untrusted model (sklearn, pytorch, tensorflow,
  lightgbm, xgboost, pmdarima and other pickle-backed flavors) deserializes
  attacker-controlled artifacts referenced by the `MLmodel` manifest.
- **`CVE-2026-79721`** — NVD CVSS **8.6** HIGH, **CWE-829**. The `python_function`
  flavor also carries a `code` key naming a directory bundled inside the (untrusted)
  artifact. `mlflow.pyfunc.load_model` prepends that directory to `sys.path`
  **before** `importlib.import_module(loader_module)` runs, so top-level code in a
  bundled module executes at load time — before `_load_pyfunc` is ever called.

## Rules

| Rule | Severity | Fires on |
| --- | --- | --- |
| `MLF001` | HIGH / CRITICAL | A `loader_module` that leaves the `mlflow.` first-party namespace — `mlflow.pyfunc.load_model` would `importlib.import_module` it and call its `_load_pyfunc`. CRITICAL when the module's top-level name grants code execution / deserialization / import / reflection / process / network access (`os`, `subprocess`, `builtins`, `pickle`, `ctypes`, `socket`, …); HIGH otherwise. |
| `MLF002` | HIGH | `loader_module: mlflow.statsmodels` — the flavor that bypasses `MLFLOW_ALLOW_PICKLE_DESERIALIZATION` (GHSA-gqvg-gmmx-x4hm). |
| `MLF003` | MEDIUM | The manifest references a pickle artifact — a `.pkl` / `.pickle` / `.cloudpickle` path, a `pickled_model` key, or `serialization_format: pickle` / `cloudpickle`. Loading it deserializes that artifact (CVE-2024-37052 family). |
| `MLF004` | INFO | The `python_function` flavor is present; corroborates that the model is loaded through the `loader_module` dispatch path. |
| `MLF005` | HIGH / MEDIUM | The `python_function` flavor declares a `code` path. `mlflow.pyfunc.load_model` prepends that artifact-bundled directory to `sys.path` **before** importing `loader_module`, so module-level code in the bundled directory runs at load time, before `_load_pyfunc` is called (`CVE-2026-79721`, CWE-829). HIGH when `loader_module` is non-first-party (the exact CVE-2026-79721 shape); MEDIUM otherwise. |

## Usage

```bash
# scan a model directory (walks for files named exactly "MLmodel")
python mlflow_manifest_scan.py ./my_model_dir

# scan an explicit manifest, fail CI on HIGH or above
python mlflow_manifest_scan.py ./MLmodel --fail-on HIGH

# machine-readable output
python mlflow_manifest_scan.py ./my_model_dir --json
```

A directory walk matches only files named exactly `MLmodel`. An explicit file is
scanned whatever its name, but produces findings only if it looks like a manifest
(it has a `flavors` mapping). Exit code is non-zero when a finding at or above
`--fail-on` is present (default `NONE`).

## Honest limits

- This is a detector, not an exploit, and not a claim of a new CVE. It documents
  MLflow's own documented loading behaviour so a reviewer can spot an unexpected
  loader target or an ungated pickle flavor in an untrusted model.
- The underlying code-execution primitive for the pickle flavors is pickle
  deserialization, which a dedicated pickle scanner catches when it reads the
  referenced `.pkl`. The value added here is **manifest-level**: the `MLmodel` file
  names the loader and the artifact before anything is unpickled.
- A first-party `mlflow.` `loader_module` is **not** proof of safety, and a clean
  scan guarantees nothing. The real protection is only loading MLflow models from a
  source you trust, and upgrading mlflow to **≥ 3.15.0**.
- This parses one manifest's YAML with a minimal block-mapping reader (not a general
  YAML parser). It does not download the referenced artifact, unpickle anything, or
  confirm what any import does.

## License

Apache-2.0. See [LICENSE](./LICENSE).
