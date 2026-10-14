# model-file-scan

One command for a **static, no-execution** security scan of machine-learning
model files. It unifies the scanners in this repository and adds **SARIF
output** and a **GitHub Action** so you can gate model files in CI.

Made with AI by MV2 of Munim, Inc. Standard library only (Python 3.8+). Apache-2.0.

## What it does

`model-file-scan` routes each file to the right scanner and never loads,
imports, unpickles or executes a model — it only reads bytes and disassembles
opcode/JSON structure.

| File | Scanner | Looks for |
|------|---------|-----------|
| `.keras` `.h5` `.hdf5` `config.json` | `keras_model_scan` | non-allowlist Lambda/class deserialization, `enable_unsafe_deserialization`, `TFSMLayer`, Zip/Tar Slip, legacy `.h5` (CVE-2025-1550, 2025-9905/9906, 2026-1462, 2026-9257) |
| `*.index.json` (e.g. `model.safetensors.index.json`, `pytorch_model.bin.index.json`) | `safetensors_index_scan` | **path safety of the shard `weight_map`**: absolute shard paths, `..` traversal, backslash separators, URL/fsspec schemes, NUL bytes — a shard path that escapes the model directory (CWE-22) |
| `.pkl` `.pickle` `.joblib` `.pt` `.pth` `.bin` `.npy` `.npz` `.ckpt` `.model` | `pickle_model_scan` | dangerous import + REDUCE/BUILD (CWE-502), deferred-call gadgets, unresolvable `STACK_GLOBAL` (the GHSA-9gvj-pp9x-gcfr / CVE-2025-71325 scanner-bypass class), object-dtype NumPy, Zip Slip |
| `.safetensors` | `safetensors_scan` | header/offset integrity: oversized or over-cap header length, out-of-bounds or size-mismatched `data_offsets`, overlaps and gaps, deeply nested header JSON, trailing bytes after the last tensor |
| `.gguf` | `gguf_scan` | **header/tensor-info integrity**: counts and string/array lengths that cannot fit the file, array lengths whose byte size overflows, tensor dimensions whose product overflows a 64-bit element count, out-of-range type ids, unaligned offsets — the integer-overflow class behind the ggml/llama.cpp heap overflows (CVE-2024-21825, CVE-2025-53630, CVE-2026-27940, CVE-2026-33298). New in 0.8.0 |

A flag means "worth human review", not proof of malice; a clean result is not a
guarantee of safety. When in doubt, prefer `safetensors`.

## The sharded-index path-safety check

A large checkpoint is split into shards, and a small JSON index maps each tensor
to the shard file that holds it:

```json
{"metadata": {"total_size": 13476837376},
 "weight_map": {"lm_head.weight": "model-00002-of-00002.safetensors"}}
```

To load a shard, a loader resolves the map value against the model directory —
`os.path.join(model_dir, value)` or `Path(model_dir) / value`. The value comes
straight from the **untrusted index file**. Two cases turn that into an
arbitrary-file read/write (CWE-22), and both are live 2026 bug classes in
hand-written and research loaders:

- an **absolute** value (`/etc/passwd`, `C:\Windows\win.ini`) — `os.path.join`
  and `pathlib` both *discard* the model-directory prefix when the second
  component is absolute, so the loader opens exactly the attacker's path;
- a **`..` traversal** value (`../../../../etc/shadow`, `..\..\secret`) that
  climbs out of the model directory.

The reference `huggingface_hub` loader rejects anything that is not a bare
filename; many DIY loaders do not. `safetensors-index-scan` flags these plus
backslash separators (cross-platform confusion), URL/fsspec schemes
(SSRF / arbitrary read) and NUL bytes (path truncation). It reads **only the
JSON text** — it never opens a shard, resolves a path on disk, or loads a model.

Rules: `STI001` absolute path (HIGH), `STI002` `..` traversal (HIGH), `STI003`
backslash separator (MEDIUM), `STI004` URL/scheme (MEDIUM), `STI005`
subdirectory component (LOW), `STI006` NUL byte (MEDIUM), `STI007` malformed
weight_map (LOW/MEDIUM), `STI008` excessive nesting (MEDIUM), `STI009` malformed
JSON (HIGH), `STI010` oversized index (MEDIUM), `STI000` clean (INFO).

## The GGUF header-integrity check (new in 0.8.0)

GGUF is the container used by **llama.cpp, Ollama, LM Studio and KoboldCpp**.
Like safetensors it carries **no code-execution surface** — it is weights plus a
key/value metadata table, never pickled Python — so the pickle scanner already
reports it as data-only. But "no code execution" is not "safe to parse". A GGUF
header is entirely attacker-controlled, and the hand-written C/C++ reader in
`ggml` has repeatedly turned a malformed header into a **heap out-of-bounds
write via integer overflow** in a size calculation:

- **CVE-2024-21825 / TALOS-2024-1912** — a metadata array/string count times
  `sizeof(gguf_str)` overflows, so the loader allocates less than it then fills;
- **CVE-2025-53630** — a running `ctx->size` accumulated over tensors whose
  padded sizes overflow wraps to a small value, and the later copy overruns it;
- **CVE-2026-27940** — a bypass of the CVE-2025-53630 fix: the `mem_size`
  calculation in `gguf_init_from_file_impl` still overflows (tcache-tuned, RCE);
- **CVE-2026-33298** — `ggml_nbytes` overflows when tensor dimensions are crafted
  so `(ne[i]-1)*nb[i]` wraps, returning a size far smaller than the tensor needs.

Every one of these begins with a value `gguf_scan` reads straight out of the
header: a declared count, a string length, an array length, or a set of tensor
dimensions. It parses **only the header, metadata table and tensor-info table**
with strict bounds checks — it never reads tensor data, mmaps weights, imports
`ggml` or executes anything — and flags the conditions that precede those
overflows.

Rules: `GG001` bad magic (MEDIUM), `GG002` unsupported/legacy version
(LOW/MEDIUM), `GG003` count exceeds file size (HIGH), `GG004` string/key/name
length overruns the file (HIGH), `GG005` unknown value type / over-nesting
(MEDIUM), `GG006` array length overflows allocation (HIGH), `GG007` tensor name
over 64 bytes (LOW), `GG008` dimension count out of range (MEDIUM/HIGH), `GG009`
tensor dimensions overflow the element count (HIGH), `GG010` out-of-range type id
(MEDIUM), `GG011` invalid alignment / unaligned offset (LOW/MEDIUM), `GG012`
truncated structure (MEDIUM), `GG000` clean (INFO).

## Install

From source (no PyPI account needed):

```bash
pip install "git+https://github.com/munimtechnologies/keras-model-scan"
```

This installs six console commands — `model-file-scan` (the unified entry),
`keras-model-scan`, `pickle-model-scan`, `safetensors-scan`,
`safetensors-index-scan` and `gguf-scan`. You can also just run the scripts
directly with `python model_file_scan.py ...`.

## Usage

```bash
# scan a file or a whole directory tree (index files are picked up automatically)
model-file-scan ./models

# JSON for tooling
model-file-scan pytorch_model.bin --json

# SARIF 2.1.0 for GitHub code scanning
model-file-scan ./models --sarif > model-file-scan.sarif

# CI gate: non-zero exit when anything at or above the threshold is found
model-file-scan downloaded.gguf --fail-on high || echo "do not load"
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
      - uses: munimtechnologies/keras-model-scan@v0.8.0
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
control file passed. See [VALIDATION.md](VALIDATION.md). The sharded-index rules
are covered by a crafted corpus of absolute, traversal, backslash, URL, NUL and
malformed index fixtures in `test_safetensors_index_scan.py`. The GGUF rules are
covered by a crafted byte-level corpus (bad magic and version, counts that
exceed the file, overrunning string and array lengths, dimension-product
overflow, out-of-range type ids, over-count dimensions, unaligned offsets and
truncated structures, plus a clean control) in `test_gguf_scan.py`.

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
  is size-checked.
- The index scanner judges a shard path by its **string form**; it does not
  resolve symlinks or follow a loader's exact join logic, so a loader with an
  unusual resolution scheme could differ. A subdirectory shard path (`STI005`)
  is reported as low because some legitimate layouts nest shards.
- The GGUF scanner validates the **header, metadata and tensor-info** structure,
  not weight contents; it reads up to a 64 MiB header cap and reports a larger
  structure as truncated rather than allocate it. `ggml_type` ids drift as quant
  formats are added and removed, so it flags only ids well above the live range
  (a likely out-of-bounds table index), not every unknown id. GGUF v1 (uint32
  counts) is flagged as legacy and not deep-parsed. Other GGUF static auditors
  exist (e.g. ModelAudit, gguf-sentinel); this adds the same integrity class to
  the unified, dependency-free `model-file-scan` entry point.
- This tool and this document were made with AI.
```
