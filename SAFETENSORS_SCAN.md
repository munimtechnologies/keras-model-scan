# safetensors-scan — static integrity validator for `.safetensors` files

`safetensors_scan.py` is a standard-library-only, no-execution validator for the
[safetensors](https://github.com/huggingface/safetensors) model-file format. It
reads **only** the 8-byte length prefix and the JSON header — it never reads the
tensor data section, never allocates the declared header size, and guards its own
JSON parse against the recursion bug it detects.

> Made with AI, by MV2 of Munim, Inc. Apache-2.0.

## Why a "safe" format still needs a scanner

safetensors is correctly described as free of a *code-execution* surface: unlike
pickle, loading a safetensors file cannot call arbitrary functions. But the header
is still attacker-controlled data, and several real, hand-written loaders have
trusted it without bounds checks. Those bugs are denial-of-service and
out-of-bounds, not RCE — but they are real, and they are **not** covered by
pickle-focused scanners (modelscan, picklescan), which treat safetensors as safe
and move on. This fills that gap: a CI check that rejects a malformed/hostile
safetensors file *before* it reaches a loader that might trust it.

Documented real-world cases this scanner's rules are modelled on:

| Class | Real case | Rule |
|---|---|---|
| Declared header length read straight into an allocation | [AUTOMATIC1111/stable-diffusion-webui #17498](https://github.com/AUTOMATIC1111/stable-diffusion-webui/issues/17498) | SFT001, SFT002 |
| `data_offsets` not validated against `shape × dtype` → heap overflow | [turboderp-org/exllamav2 #820](https://github.com/turboderp-org/exllamav2/issues/820) | SFT003, SFT005 |
| Deeply nested header → uncaught `RecursionError` | [kornia #5218 / #5248](https://github.com/kornia/kornia/issues/5218) | SFT006 |
| Bytes after the last tensor (polyglot file) | rejected by the reference loader as `MetadataIncompleteBuffer` | SFT009 |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| SFT000 | INFO | Header length, JSON, dtypes and `data_offsets` are internally consistent and cover the whole data section. |
| SFT001 | HIGH | Declared header length + 8 exceeds the file size (oversized read / allocation DoS). |
| SFT002 | HIGH | Header length is above the 100 MB safetensors cap (HeaderTooLarge / allocation DoS). |
| SFT003 | HIGH/MEDIUM | `data_offsets` malformed, reversed, negative, or past the end of the data section (out-of-bounds read). |
| SFT004 | MEDIUM/LOW | Tensor byte ranges overlap, leave a gap, or the first tensor does not start at offset 0. |
| SFT005 | HIGH | `data_offsets` span ≠ `numel(shape) × dtype_size` (the size-mismatch heap-overflow trigger). |
| SFT006 | MEDIUM | JSON header nests past a safe depth; `json.loads` would risk `RecursionError`. Parsing is skipped. |
| SFT007 | HIGH/LOW | Not a safetensors file, truncated, empty, or malformed JSON header. |
| SFT008 | LOW | Unknown dtype string. |
| SFT009 | MEDIUM | Trailing bytes after the last tensor: data the header does not describe. The reference implementation rejects these files; such bytes can carry a second, hidden payload. (New in 0.2.0 / repo v0.5.0.) |

SFT004's start-at-zero check and SFT009 bring the validator in line with the
reference implementation's full-coverage rule: tensors sorted by offset must start
at 0, follow each other with no gap or overlap, and the last one must end exactly
at the end of the file.

A finding means the file would break or exhaust a naive loader and deserves
review before use — it is **not** proof of malice, and a clean result is **not** a
guarantee of safety.

## Usage

```bash
# scan one file or a directory tree of *.safetensors
python safetensors_scan.py model.safetensors
python safetensors_scan.py ./models --json

# CI gate: exit 1 if any finding is at least HIGH
python safetensors_scan.py ./models --fail-on HIGH

# or through the unified command, which routes .safetensors here
model-file-scan ./models --sarif > model-file-scan.sarif
```

Requires only Python 3.8+ (standard library). No third-party dependencies, so it
is safe to run in a hardened CI job and cannot be influenced by the file it scans.

## Design notes

- Reads at most `min(declared_header_length, file_size − 8, 100 MB + 1)` bytes, so
  a forged length never causes this tool itself to allocate a hostile size.
- Measures JSON nesting depth with a single byte pass **before** calling
  `json.loads`, so it never reproduces the recursion DoS it is meant to catch.
- `scan_file(path) -> list[Finding]` and `main(argv=None) -> int` match the other
  scanners in this repo; `Finding` is a frozen dataclass
  (`rule, severity, title, detail, location, cve`) with `as_dict()`.

## Validation

See [VALIDATION.md](VALIDATION.md): eight crafted malformed files, one per class,
were scanned in a sealed container with no network; all eight were flagged and the
clean control passed.

## Scope and honesty

This scanner is defensive. It performs static inspection of local files only. It
never loads, maps, or executes a model, never contacts a network, and makes no
claim about files it reports clean beyond header integrity. Newer sub-byte dtypes
are reported as unknown (SFT008) rather than size-checked.
