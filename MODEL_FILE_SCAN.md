# model-file-scan

One command for a **static, no-execution** security scan of machine-learning
model files. It unifies the three scanners in this repository and adds **SARIF
output** and a **GitHub Action** so you can gate model files in CI.

Made with AI by MV2 of Munim, Inc. Standard library only (Python 3.8+). Apache-2.0.

## What it does

`model-file-scan` routes each file to the right scanner and never loads,
imports, unpickles or executes a model — it only reads bytes and disassembles
opcode/JSON structure.

| File | Scanner | Looks for |
|------|---------|-----------|
| `.keras` `.h5` `.hdf5` `config.json` | `keras_model_scan` | non-allowlist Lambda/class deserialization, `enable_unsafe_deserialization`, `TFSMLayer`, Zip/Tar Slip, legacy `.h5` (CVE-2025-1550, 2025-9905/9906, 2026-1462, 2026-9257) |
| `.pkl` `.pickle` `.joblib` `.pt` `.pth` `.bin` `.npy` `.npz` `.ckpt` `.model` | `pickle_model_scan` | dangerous import + REDUCE/BUILD (CWE-502), deferred-call gadgets, unresolvable `STACK_GLOBAL` (the GHSA-9gvj-pp9x-gcfr / CVE-2025-71325 scanner-bypass class), object-dtype NumPy, Zip Slip |
| `.safetensors` | `safetensors_scan` | header/offset integrity: oversized or over-cap header length, out-of-bounds or size-mismatched `data_offsets`, overlaps and gaps, deeply nested header JSON, trailing bytes after the last tensor (new in 0.5.0) |
| `.gguf` | `pickle_model_scan` | confirmed as a data-only format (no code-execution surface) |

A flag means "worth human review", not proof of malice; a clean result is not a
guarantee of safety. When in doubt, prefer `safetensors`.

## Install

From source (no PyPI account needed):

```bash
pip install "git+https://github.com/munimtechnologies/keras-model-scan"
```

This installs four console commands — `model-file-scan` (the unified entry),
`keras-model-scan`, `pickle-model-scan` and `safetensors-scan`. You can also just
run the scripts directly with `python model_file_scan.py ...`.

## Usage

```bash
# scan a file or a whole directory tree
model-file-scan ./models

# JSON for tooling
model-file-scan pytorch_model.bin --json

# SARIF 2.1.0 for GitHub code scanning
model-file-scan ./models --sarif > model-file-scan.sarif

# CI gate: non-zero exit when anything at or above the threshold is found
model-file-scan downloaded.pt --fail-on high || echo "do not load"
```

Exit codes: `0` clean (below threshold), `1` findings at/above `--fail-on`
(default `medium`), `2` a path was missing or a file errored.

## GitHub Action

This repository is itself a composite Action. Add a workflow like:

```yaml
name: Scan model files
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to the Security tab

jobs:
  model-file-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - uses: munimtechnologies/keras-model-scan@v0.6.0
        with:
          paths: "."
          fail-on: "high"
```

Findings appear in the repository's **Security → Code scanning** tab, severity
is carried through (`security-severity`), and the job fails when something at or
above `fail-on` is found. Set `upload-sarif: "false"` to skip the upload (for
example on forks without `security-events` permission).

## Validation

The safetensors rules were checked against a crafted corpus of eight malformed
files in a sealed, network-less container: 8/8 classes were flagged and the clean
control file passed. See [VALIDATION.md](VALIDATION.md).

## Honest limitations

- Static heuristics, not a sandbox. `STACK_GLOBAL` operand resolution uses the
  same "last two pushed strings" approach mainstream scanners use; rather than be
  bypassed silently, this tool **emits a finding** when operands can't be
  resolved, but adversarial opcode reordering can still leave a file
  suspicious-but-unclassified.
- `lz4`/`zstd`-compressed containers are reported as unscanned (no stdlib
  codec); decompress them first.
- safetensors sub-byte dtypes (`F4`, `F6_E2M3`, `F6_E3M2`) are recognised as
  valid but not byte-size-checked (their packed length is a bit-width
  calculation this tool does not reproduce); every whole-byte dtype, including
  the fp8 formats (`F8_E4M3`, `F8_E5M2`, `F8_E8M0`, the FNUZ variants) and `C64`,
  is size-checked (new in 0.6.0).
- This tool and this document were made with AI.
```
