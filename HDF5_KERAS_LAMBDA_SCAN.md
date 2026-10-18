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

- **CVE-2025-9905** (GHSA-36rr-ww3j-vrjv; Keras, affected 3.0.0–3.11.2, fixed
  in **3.11.3**, CWE-913): `Model.load_model` **silently ignores
  `safe_mode=True`** for legacy HDF5 models. A `Lambda` layer whose function is
  stored as serialized (marshalled) Python code therefore executes on load
  **even when the caller asked for safe mode**. The attack needs no inference —
  loading the file is enough. This is the sink this detector targets.
- **Not to be confused with CVE-2025-9906** (GHSA-36fq-jgmw-4r9c; Keras, fixed in
  **3.11.0**, CWE-502): a *distinct* bypass in the newer `.keras` **v3 ZIP
  archive**, where a crafted `config.json` first calls
  `enable_unsafe_deserialization()` and then runs a `Lambda` payload. That format
  is handled by this toolkit's `keras_model_scan`, not here. The two CVEs share a
  root cause (Lambda code-exec) but are different file formats with different
  fixed versions (3.11.0 vs 3.11.3) and different CWEs (CWE-502 vs CWE-913);
  verified at osv.dev.
- The Keras advisory credits GitHub user `io-no` as reporter. `safe_mode` was
  only ever wired to `.keras` v3, so there is no built-in way to restrict Lambda
  code in an `.h5` model.

## What it does

Reads only the file **bytes**. It never imports `h5py`, never builds or loads the
model, and never executes any payload. It confirms the HDF5 superblock signature
(at offset 0 or `512 * 2**k`), then scans the embedded UTF-8 Keras config text.

| Rule | Severity | Meaning |
|------|----------|---------|
| HKL001 | high | HDF5 Keras config contains a `Lambda` layer (with a serialized `function`) → code exec on load under Keras <3.11.3 (CVE-2025-9905). |
| HKL002 | medium | Config references a custom registered object (a `package>Name` key in `registered_name` or, for tf.keras legacy files, in `class_name`) or a non-`keras` `module` → attacker-controllable deserialization (CWE-502). |
| HKL003 | info | Legacy Keras HDF5 model with no code marker found — still note that `safe_mode` does not protect `.h5`; prefer `.keras` v3 and Keras ≥3.11.3. |

### How HKL002 tells custom objects from built-ins

`keras.saving.register_keras_serializable(package="Custom", name=None)` names
every registered object `package>Name`. Keras 3 writes that string under
`registered_name`; tf.keras / Keras 2 legacy saving writes it as the
`class_name` itself. Built-in classes that Keras does not export publicly (for
example a nested `Functional` model) are serialized with their **bare** class
name as `registered_name`, so they are not flagged. An unregistered custom class
is still caught by its non-`keras` `module` (for example `__main__`).

## Usage

```bash
python hdf5_keras_lambda_scan.py model.h5 other.hdf5
```

Exit code `1` if any **high** finding, else `0` (`2` on bad usage / I/O error),
so it drops into CI next to the other scanners in this repo.

## Changes

- **0.1.1**: findings and docstring now cite CVE-2025-9905 only (0.1.0 also
  named CVE-2025-9906, which is the `.keras` v3 archive bypass). HKL002 no longer
  flags built-in classes whose `registered_name` is their bare class name (a
  false positive on Keras 3 models with a nested `Functional`), and now catches
  tf.keras legacy files that store a registered `Custom>Name` in `class_name`
  (previously missed).
- **0.1.0**: first release.

## Honest limits

Detection is marker-based over the raw bytes, because legacy `.h5` files store
the config JSON as contiguous text in the container. A file whose Keras config
has been externally compressed or split so the JSON is not present as contiguous
text is better handled by a loader-based tool. This module ships validated
against synthetic byte fixtures (see `test_hdf5_keras_lambda_scan.py`); validate
against real Keras-saved `.h5` files before relying on it as a sole gate.
