# Validation of safetensors-scan

Made with AI by MV2 of Munim, Inc. Text CC BY 4.0; code Apache-2.0.

## What was run

On 2026-10-14, safetensors-scan (module version 0.1.0, shipped in repo release
v0.4.0) ran in a sealed `python:3.12` container with **no network access**:

1. its unit tests (`python -m unittest -v test_safetensors_scan`): passed;
2. a generator that wrote eight small `.safetensors` files into the container,
   one clean control file plus one file per malformed-header class;
3. a harness that scanned each file and recorded which rules fired.

Nothing was loaded into any ML framework, and no external system was touched.

## Result: 8/8

| File | Class | Expected rule | Rules fired | Detected |
|---|---|---|---|---|
| clean.safetensors | well-formed control | SFT000 | SFT000 | yes (no false positive) |
| oversized_header.safetensors | header length > file size | SFT001 | SFT001 | yes |
| over_cap.safetensors | header length > 100 MB cap | SFT002 | SFT001, SFT002 | yes |
| oob_offsets.safetensors | data_offsets past the data section | SFT003 | SFT003, SFT005 | yes |
| overlap.safetensors | overlapping tensor ranges | SFT004 | SFT004 | yes |
| size_mismatch.safetensors | span ≠ numel × dtype size | SFT005 | SFT005 | yes |
| deep_nested.safetensors | header nested past depth cap | SFT006 | SFT006 | yes |
| not_json.safetensors | header is not JSON | SFT007 | SFT007 | yes |

All exit codes were 0. The extra rules on two files are expected: an over-cap
header also exceeds the file, and an out-of-bounds range also has the wrong size.

## What changed after validation (v0.5.0)

Version 0.2.0 of the module adds the reference implementation's full-coverage
rule: the first tensor must start at offset 0 (SFT004) and the last must end at
the end of the file (SFT009, trailing bytes). These two checks are covered by the
unit tests in `test_safetensors_scan.py` (class `Coverage`), which run before every
release. The clean control above still passes, because its single tensor covers
the whole data section.

## Limits

- The corpus is small and synthetic: one file per class. It shows each rule fires
  on its own case. It says nothing about false-positive rates on real model hubs.
- A clean result means the header is internally consistent. It does not mean a
  model is trustworthy.
