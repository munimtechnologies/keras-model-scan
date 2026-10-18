# hdf5_keras_lambda_scan

Static, no-execution detector for code-execution risk in **legacy Keras HDF5**
(`.h5` / `.hdf5`) model files. Made with AI by MV2 of Munim, Inc. Apache-2.0.

## The gap it closes

This toolkit's `keras_model_scan` reads the **`.keras` v3** format, which is a
ZIP archive carrying `config.json`. It does **not** cover the older `.h5`/`.hdf5`
format, which is an HDF5 *binary container* that stores the architecture as a
UTF-8 `model_config` attribute. That is a different file format with a different,
still-exploited sink — so it gets its own detector.

## The vulnerability

- **CVE-2025-9905 / CVE-2025-9906** (Keras, fixed in **3.11.3**, CWE-913):
  `Model.load_model` **silently ignores `safe_mode=True`** for legacy HDF5
  models. A `Lambda` layer whose function is stored as serialized (marshalled)
  Python code therefore executes on load **even when the caller asked for safe
  mode**. The attack needs no inference — loading the file is enough.
- Reported by Gabriele Digregorio (Io_no) as a follow-up to earlier Keras
  `safe_mode` bypasses. `safe_mode` was only ever wired to `.keras` v3, so there
  is no built-in way to restrict Lambda code in an `.h5` model.

## What it does

Reads only the file **bytes**. It never imports `h5py`, never builds or loads the
model, and never executes any payload. It confirms the HDF5 superblock signature
(at offset 0 or `512 * 2**k`), then scans the embedded UTF-8 Keras config text.

| Rule | Severity | Meaning |
|------|----------|---------|
| HKL001 | high | HDF5 Keras config contains a `Lambda` layer (with a serialized `function`) → code exec on load under Keras <3.11.3 (CVE-2025-9905/9906). |
| HKL002 | medium | Config references a non-core / custom registered object (`registered_name`, non-`keras` `module`) → attacker-controllable deserialization (CWE-502). |
| HKL003 | info | Legacy Keras HDF5 model with no code marker found — still note that `safe_mode` does not protect `.h5`; prefer `.keras` v3 and Keras ≥3.11.3. |

## Usage

```bash
python hdf5_keras_lambda_scan.py model.h5 other.hdf5
```

Exit code `1` if any **high** finding, else `0` (`2` on bad usage / I/O error),
so it drops into CI next to the other scanners in this repo.

## Honest limits

Detection is marker-based over the raw bytes, because legacy `.h5` files store
the config JSON as contiguous text in the container. A file whose Keras config
has been externally compressed or split so the JSON is not present as contiguous
text is better handled by a loader-based tool. This module ships validated
against synthetic byte fixtures (see `test_hdf5_keras_lambda_scan.py`); validate
against real Keras-saved `.h5` files before relying on it as a sole gate.
