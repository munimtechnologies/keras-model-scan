---
name: model-file-scan
description: Static, no-execution safety check for ML model files before they are loaded. Use it when the user (or your own code) is about to call torch.load, pickle.load, joblib.load, keras load_model, numpy.load(allow_pickle=True) or similar on a model file that came from somewhere else (Hugging Face, a shared drive, an email, a pull request, a dataset), or asks whether a .pkl, .pt, .pth, .bin, .ckpt, .joblib, .npy, .keras, .h5, .safetensors, .gguf, .onnx, .tflite, .nemo, OpenVINO, XGBoost, LightGBM or skops file is safe to open. Runs one dependency-free Python command that reads the file's bytes, never imports, unpickles or executes it, and sends nothing anywhere. Apache-2.0, by MV2 of Munim, Inc., made with AI agents.
license: Apache-2.0
---

# Model file scan

`model-file-scan` is a standard-library-only Python tool (Python 3.8+) from the open-source
repository [munimtechnologies/keras-model-scan](https://github.com/munimtechnologies/keras-model-scan).
It reads a model file's bytes and reports patterns that can run code or reach outside the
model when the file is loaded: pickle imports and calls, Keras `Lambda` layers and unsafe
config, archive members that escape their folder, external-data paths in ONNX and safetensors
indexes, malformed GGUF headers, and more. It never loads the model, so scanning a hostile
file is safe.

## When to use

- Before running `torch.load`, `pickle.load`, `joblib.load`, `keras.models.load_model`,
  `np.load(..., allow_pickle=True)` or `from_pretrained` on files you did not create.
- "Is this checkpoint / .pkl / .pt from Hugging Face safe to load?"
- Reviewing a pull request or dataset that adds model files to a repository.
- Adding a CI gate for committed model files (see "In CI" below).

Do not use it on files that are not model or data files, and do not treat it as a malware
scanner for executables.

## Steps

1. Tell the user what you will install and run, and that it only reads the files. Install
   the pinned release (pipx keeps it isolated; plain pip works too):

   ```bash
   pipx install "git+https://github.com/munimtechnologies/keras-model-scan@v0.53.1"
   ```

   ```bash
   python -m pip install "git+https://github.com/munimtechnologies/keras-model-scan@v0.53.1"
   ```

   `model-file-scan --version` should print `model-file-scan 0.12.0`.

2. Scan the file or folder **before** anything loads it, with JSON output:

   ```bash
   model-file-scan path/to/model_or_folder --json > scan.json; echo "exit=$?"
   ```

   On Windows PowerShell: `model-file-scan path\to\model --json > scan.json; echo "exit=$LASTEXITCODE"`.
   Folders are walked; each file is routed to the scanner for its format.

3. Read the exit code: `0` nothing at or above the threshold (default `--fail-on medium`),
   `1` at least one finding at or above it, `2` a path was missing or a file could not be
   scanned (treat as "not checked", never as clean).

4. Read `scan.json`: `{"tool", "version", "files": [{"path", "findings": [...]}]}`. Each
   finding has at least `rule` and `severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`),
   usually `title`, `detail` and `location`, and sometimes `cve` or `cwe`. Report findings to
   the user from this file only. Do not invent findings, rules or CVEs.

5. Explain the result with the guide below, then let the user decide. Never load the file
   "to check", and never weaken a loader's safety setting to make a file load.

## How to read the findings (v0.53.1)

| What you see | What to tell the user |
|---|---|
| `PKL001` CRITICAL | A dangerous import (such as `os`, `subprocess`, `builtins.eval`) together with a call opcode: loading this pickle can run code. Do not load it. |
| `PKL002`, `PKL004`, `PKL010`, `PKL030` HIGH | Dangerous import, deferred-call gadget, NumPy object array (its data is a pickle), or an archive member that escapes its folder. Do not load it until a person has reviewed it. |
| `PKL007` HIGH **with no** PKL001/PKL002/PKL004 | The scanner could not resolve some import names. **Known false positive in this release:** honest pickles written at protocol 4 or 5 (for example by PaddlePaddle or Python's own `pickle` module) often trigger it; in our pre-registered check, 20 of 23 published pickles got it. Say "not verified", not "malicious". A fix is pre-registered and under test. |
| `PKL003` MEDIUM | An import outside the known-safe list. List the imports from `detail`; the user's own classes and many libraries appear here. Loading runs that library's code. |
| `PKL000` LOW on `.joblib` / joblib-written `.pkl` | The scan stopped early. Files that `joblib.dump` wrote with NumPy arrays are only partly read in this release (about 12% of the bytes on our test files), so a clean or LOW result on them says little. |
| `PKL006` LOW | lz4/zstd compression the tool cannot open; nothing inside was checked. |
| Other scanners' HIGH (Keras, ONNX, GGUF, safetensors index, OpenVINO, NeMo, ...) | Read `title` and `detail` and relay them; they name the field and the reason. |
| `INFO` only | Format notes (for example "safetensors: no code-execution surface"). |

Rule tables for every format: [MODEL_FILE_SCAN.md](https://github.com/munimtechnologies/keras-model-scan/blob/main/MODEL_FILE_SCAN.md)
and [PICKLE_SCAN.md](https://github.com/munimtechnologies/keras-model-scan/blob/main/PICKLE_SCAN.md).

## Safer loading, whatever the scan says

- Prefer `.safetensors` (or GGUF / ONNX) weights over pickle-based `.bin`, `.pt`, `.pkl`.
- `torch.load(path, weights_only=True)` (the default since PyTorch 2.6). Do not pass
  `weights_only=False` for files from elsewhere.
- Keras 3: keep `safe_mode=True` (the default) in `load_model`.
- `pickle`, `joblib` and `np.load(allow_pickle=True)` have no safe mode: only load files from
  sources the user trusts.

## Limits to tell the user

- Static heuristics, not a sandbox. A flag means "worth human review", not proof of malice,
  and a clean result is not a guarantee of safety.
- Known gaps in v0.53.1: the PKL007 false positive and partial joblib coverage above;
  lz4/zstd containers are not opened; GGUF checks cover the header, metadata and tensor
  table, not the weights; sub-byte safetensors dtypes (`F4`, `F6_*`) are not size-checked.
- It checks only the files given. Code that a model repository runs itself
  (`trust_remote_code=True`, custom `*.py`) is a separate risk: read that code.

## In CI

The same repository is a GitHub Action that uploads SARIF to code scanning:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: munimtechnologies/keras-model-scan@v0.53.1
    with:
      paths: models/
      fail-on: high
```

General technical information, not professional security advice. Made with AI agents
working for MV2 of Munim, Inc.; issues and corrections are welcome at
https://github.com/munimtechnologies/keras-model-scan/issues.
