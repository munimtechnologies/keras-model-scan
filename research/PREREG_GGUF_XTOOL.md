# Pre-registration: ModelAudit on GGUF files of the newest ggml tensor types

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 3 November 2026 (UTC), before job `gguf-xtool-v1` ran.

## Why

Our own `gguf_scan` 0.1.0 wrongly failed honest GGUF files whose tensors use
ggml types 40-43 ([report](../REALFILE_CHECK_GGUF_TYPES_2026-11.md)). The
fix, `gguf_scan` 0.2.0, accepts every id below `GGML_TYPE_COUNT` (44 in
llama.cpp tag b12034). We then asked whether the widest open model-file
scanner, promptfoo's ModelAudit (MIT), handles the same types. From reading
its source on 3 November 2026:

- The newest PyPI release, **0.2.54** (13 October 2026), predates ModelAudit
  PR #1909 ("recognize the remaining ggml tensor types", merged 14 October).
  That PR says that before it, a tensor type missing from the scanner's table
  made the scan **inconclusive, exit code 2**. Its release PR (#1910, v0.2.55)
  was still open on 3 November.
- On `main` (commit `415819f`, 21 October 2026), `_GGML_TYPE_INFO` in
  `modelaudit/scanners/gguf_scanner.py` lists ids up to **42** (Q2_0). It has
  no entry for **43, `GGML_TYPE_F8_E4M3`**, which llama.cpp added on
  29 October 2026 (PR #27512). An unknown id gets an INFO check "Tensor Type
  Validation" (S902, "uses unknown GGML type N") and marks the scan
  inconclusive.

This job checks those readings on real files. It is a compatibility check of
a scanner, not a vulnerability report: an inconclusive result fails closed.

## Setup

A sealed `python:3.12` container. Setup has network to download llama.cpp
tag b12034 (only `gguf-py/`), ModelAudit 0.2.54 and its dependencies from
PyPI, and ModelAudit `main` at `415819f`. The run step has no network, and
ModelAudit's telemetry is switched off with the variables its README names.

- `ma_rel`: `pip install modelaudit==0.2.54`.
- `ma_main`: the same, then `main` at `415819f` installed over it with
  `--no-deps` (main asks for `modelaudit-picklescan` 0.1.13, which is not on
  PyPI yet; the GGUF scanner does not use it).
- Fallback, `overlay`: 0.2.54 with only main's `gguf_scanner.py` copied in.
  It is graded **only if** `ma_main` did not install or its scanner cannot be
  imported; the report says which one was graded.

`research/gguf-xtool/xtool_check.py` writes the same files as job
`gguf-types-v2` with llama.cpp's own `gguf.GGUFWriter`: one file per type
(F32, F16, Q4_0, Q8_0, Q4_K, Q6_K, IQ4_XS, BF16, TQ2_0, MXFP4, NVFP4, Q1_0,
Q2_0, F8_E4M3; one 2 x 256 tensor each, seeded random contents), one file
holding every type, and a copy of the NVFP4 file with its type id set to 44.
Each file is scanned with `modelaudit FILE --format json --output ...`. An
"unknown type" report is any match of `unknown GGML type N` in the output.

## Predictions

| # | tool | case | prediction |
|---|---|---|---|
| R0 | gguf-py | read every honest file back | each tensor has the type it was written with |
| A1 | 0.2.54 | F32, F16, Q4_0, Q8_0, Q4_K, Q6_K, IQ4_XS, BF16 | no unknown-type report |
| A2 | 0.2.54 | TQ2_0, MXFP4, NVFP4, Q1_0, Q2_0, F8_E4M3 | each reports its own id as unknown, exit 2 |
| V0 | main | the scanner's type table | has 40, 41 and 42, not 43 |
| M1 | main | every honest file except F8_E4M3 | no unknown-type report |
| M2 | main | the F8_E4M3 file | reports 43 as unknown, exit 2 |
| M3 | main | the file holding every type | reports only 43 as unknown |
| M4 | main | the NVFP4 copy with type id 44 | reports 44 as unknown (control: the scanner ran) |

## Grading

- A case whose tool did not install, or whose file was not written, is
  **not run**, never held or failed.
- Exit codes of the cases not named above, and any WARNING or CRITICAL
  finding on these random-content files, are reported in full but not
  graded.
- If M2 holds, MV2 will open one short, factual issue on promptfoo/modelaudit
  pointing to llama.cpp's enum and this report, disclosing that the work was
  made with AI. If it does not hold, nothing is filed and the report says why.

## Limits

One small file per type with random contents, written by llama.cpp's Python
writer, not by its quantizer. This tests how a scanner treats the type ids,
not its false-positive rate on published models. ModelAudit's `main` may
change before its next release; the report names the commit tested.
