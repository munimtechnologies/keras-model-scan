# Pre-registration: gguf_scan and the newest ggml tensor types

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 2 November 2026 (UTC), before job `gguf-types-v1` ran.

## Why

`gguf_scan.py` 0.1.0 (keras-model-scan v0.50.0) reports a tensor whose ggml
type id is above 39 as **GG010 (MEDIUM)**, "type id out of range". The
default gate of `model-file-scan` fails on MEDIUM. That limit is now out of
date. llama.cpp's `ggml.h` on 2 November 2026 (tag b12034) defines:

| id | type |
|---|---|
| 39 | `GGML_TYPE_MXFP4` |
| 40 | `GGML_TYPE_NVFP4` |
| 41 | `GGML_TYPE_Q1_0` |
| 42 | `GGML_TYPE_Q2_0` |
| 43 | `GGML_TYPE_F8_E4M3` (added by llama.cpp PR #27512, merged 29 October 2026) |
| 44 | `GGML_TYPE_COUNT` |

llama.cpp's own loader (`ggml/src/gguf.cpp`) refuses a type id outside
`[0, GGML_TYPE_COUNT)`. NVFP4 GGUF files are already published on the
Hugging Face Hub, so on an honest NVFP4 model our gate would fail
with a false positive.

The fix (`gguf_scan` 0.2.0) changes two lines: `_MAX_GGML_TYPE = 43` and the
version. Ids 4, 5, 31-33 and 36-38 (types removed from ggml) are left as
they are in 0.1.0; this change is only about the upper limit.

## Setup

A sealed `python:3.12` container. Setup has network only to download the
keras-model-scan v0.50.0 source tarball, llama.cpp tag b12034 (only its
`gguf-py/` folder, llama.cpp's own Python GGUF writer and reader, MIT) and
gguf-py's PyPI dependencies. The run steps have no network.

- `research/gguf-types/patch_gguf.py` patches the v0.50.0 `gguf_scan.py`
  into 0.2.0 by anchor (each anchor exactly once, a second pass changes
  nothing, only the two lines differ).
- `research/gguf-types/realfile_check_gguf_types.py` writes one GGUF file per
  type with `gguf.GGUFWriter`, each holding one 2 x 256 tensor: F32 and F16
  from seeded random floats, and Q4_0, Q8_0, Q4_K, Q6_K, IQ4_XS, BF16, TQ2_0,
  MXFP4, NVFP4, Q1_0, Q2_0 and F8_E4M3 as seeded random bytes of the size
  `GGML_QUANT_SIZES` gives for the type. It also writes one file holding every
  type that could be written. The files are structurally what llama.cpp's
  writer produces; their numbers are not a trained model.

## Predictions

| # | case | prediction |
|---|---|---|
| R0 | gguf-py's `GGUFReader` on every honest file | reads it, and each tensor has the type it was written with |
| O1 | gguf_scan 0.1.0 on each file of type id 39 or below | no GG010, nothing at MEDIUM or above |
| O2 | gguf_scan 0.1.0 on each file of type id 40-43 | GG010 on each (the false positive reproduces on real files) |
| O3 | `model-file-scan` v0.50.0 on the NVFP4 file | exit 1 |
| N1 | gguf_scan 0.2.0 on every honest file | no GG010, nothing at MEDIUM or above |
| N2 | patched `model-file-scan` on the folder of honest files | exit 0 |
| N3 | gguf_scan 0.2.0 on a copy of the NVFP4 file with its type id set to 44 | GG010 |
| N4 | gguf_scan 0.2.0 on the file holding every type | no GG010, nothing at MEDIUM or above |
| U1 | the published `test_gguf_scan.py`, run against 0.2.0 | all pass |
| U2 | the new `test_gguf_scan_types.py` against 0.2.0 | all pass |

## Grading

- If gguf-py at b12034 has no member for a type, or cannot write it, the
  cases for that type are **not run**, never held or failed. The type ids
  gguf-py reports are recorded.
- If the edited copy's tensor-info bytes cannot be found exactly once, N3 is
  not run.
- If the patch step fails, nothing is graded; the patch is fixed and the job
  re-run under a new version.
- Everything else is reported in full, whatever it is. 0.2.0 is published
  only if O2, N1, N3, U1 and U2 hold.

## Limits

One file per type, tiny tensors, random contents. This checks the type-id
limit and the structure llama.cpp's writer produces, not a false-positive
rate on published models. It says nothing about whether llama.cpp's loader
handles any of these types safely.
