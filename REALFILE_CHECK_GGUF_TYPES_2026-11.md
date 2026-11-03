# Real-file check: gguf_scan and the newest ggml tensor types (November 2026)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Pre-registration: [research/PREREG_GGUF_TYPES.md](research/PREREG_GGUF_TYPES.md)
(written before the first run, amended before the second). Job
`gguf-types-v2`, run 2 November 2026, 15:02-15:05 UTC, in a sealed
`python:3.12` container with no network during the run steps.

**Result: all 10 pre-registered predictions held** (8 graded by the check
script, plus both unit-test suites). Nothing was left unrun.

## What was wrong

`gguf_scan` 0.1.0 (keras-model-scan v0.50.0) reported any tensor whose ggml
type id was above 39 as **GG010 (MEDIUM), type id out of range**, and
`model-file-scan`'s default gate fails on MEDIUM. llama.cpp has since added
four types:

| id | type |
|---|---|
| 40 | `GGML_TYPE_NVFP4` |
| 41 | `GGML_TYPE_Q1_0` |
| 42 | `GGML_TYPE_Q2_0` |
| 43 | `GGML_TYPE_F8_E4M3` (llama.cpp PR #27512, merged 29 October 2026) |
| 44 | `GGML_TYPE_COUNT` |

So an honest GGUF using any of them failed our gate. This was a false
positive in our scanner, not a problem in llama.cpp or in the files.

`gguf_scan` 0.2.0 changes two lines: the limit becomes 43 and the version
0.2.0. The patch was applied by anchor in the job; a second pass changed
nothing, and the file kept its 518 lines. Ids of types ggml removed (4, 5,
31-33, 36-38) are treated as before.

## Files

Written with llama.cpp's own Python writer (`gguf-py` at tag b12034, which
reports itself as gguf 0.19.0): one file per type, each with one 2 x 256
tensor (F32 and F16 from seeded random floats, the others seeded random bytes
of the size gguf-py's `GGML_QUANT_SIZES` gives), one file holding all 14
types, and one copy of the NVFP4 file with its type id edited to 44. Every
type was written; no write failed.

Type ids and block sizes as gguf-py b12034 reports them (block elements,
bytes per block): Q4_0 (32, 18), Q8_0 (32, 34), Q4_K (256, 144),
Q6_K (256, 210), IQ4_XS (256, 136), TQ2_0 (256, 66), MXFP4 (32, 17),
**NVFP4 (64, 36), Q1_0 (128, 18), Q2_0 (64, 18), F8_E4M3 (1, 1)**.

## Results

| # | case | prediction | result |
|---|---|---|---|
| R0 | gguf-py's `GGUFReader` on every honest file | reads it; each tensor has the type it was written with | held (ids 0, 1, 2, 8, 12, 14, 23, 30, 35, 39, 40, 41, 42, 43) |
| O1 | gguf_scan 0.1.0 on the 10 files of type id 39 or below | no GG010, nothing at MEDIUM or above | held (GG000 only) |
| O2 | gguf_scan 0.1.0 on the 4 files of type id 40-43 | GG010 on each | held: the false positive reproduces on real files |
| O3 | `model-file-scan` v0.50.0 on the NVFP4 file | exit 1 | held (exit 1, `GG010 ... type id 40, above the known range (0-39)`) |
| N1 | gguf_scan 0.2.0 on all 14 honest files | no GG010, nothing at MEDIUM or above | held (GG000 only) |
| N2 | patched `model-file-scan` on the folder of honest files | exit 0 | held |
| N3 | gguf_scan 0.2.0 on the NVFP4 copy with type id 44 | GG010 | held (`type id 44, above the known range (0-43)`) |
| N4 | gguf_scan 0.2.0 on the file holding every type | no GG010, nothing at MEDIUM or above | held |
| U1 | the published `test_gguf_scan.py` against 0.2.0 | all pass | held (19 of 19) |
| U2 | the new `test_gguf_scan_types.py` against 0.2.0 | all pass | held (4 of 4) |

Old 0.1.0 on the file holding every type reported GG010 for ids 40, 41 and
42; the check script keeps only the first three GG010 messages per file, so
the fourth (43) is not shown in its output.

## The first run

`gguf-types-v1` applied the same patch but crashed in our check script's
module loader before any case ran (the module was not registered in
`sys.modules`, which Python's `dataclasses` needs). Nothing from v1 was
graded. The amendment and the fixed script were published before v2 ran.

## Limits

- One small file per type with random contents. This checks the type-id
  limit on files with the structure llama.cpp's writer produces. It is not a
  false-positive rate on published models.
- It says nothing about whether llama.cpp's loader handles these types
  safely. llama.cpp's own loader refuses ids outside `[0, GGML_TYPE_COUNT)`.
- The limit will go stale again when ggml adds a type. The test
  `test_gguf_scan_types.py` pins today's range so the next change is a
  deliberate one.

## Other scanners

A pre-registered check of how promptfoo's ModelAudit treats the same files
is in [research/PREREG_GGUF_XTOOL.md](research/PREREG_GGUF_XTOOL.md).
