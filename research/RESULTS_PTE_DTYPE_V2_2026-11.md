# Results: executorch_pte_scan 0.1.1 dtype table, corrected grader (job pte-dtype-v2)

Pre-registered in [PREREG_PTE_DTYPE_FIX_V2.md](PREREG_PTE_DTYPE_FIX_V2.md)
before the job ran (the job recorded the pre-registration's SHA-256
f218103422c219520e8b9709019523ca647df7db38e93531d6e9d4669500a5bd at 2026-11-15T00:34:45Z).
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0 (code),
CC BY 4.0 (this text).

The job finished at 2026-11-15T00:38:58Z in a sealed container; its run steps had no
network. ExecuTorch commit 3e85cae1e744454713413db4deb31090a505adf4; candidate scanner
0.1.1. All 8 steps (3 setup, 5 run) exited 0.

## Outcome

- **All 7 rows held. executorch_pte_scan 0.1.1 is released as v0.61.0.**
  With the parser fixed, the patched table equals ExecuTorch's runtime dtype
  list (N = 30). Together with the real-file rows that held
  in [job pte-dtype-v1](../REALFILE_CHECK_PTE_DTYPE_2026-11.md), the fix meets both
  pre-registrations.

## Rows

| Row | Prediction (short) | Result | Measured |
|---|---|---|---|
| P1 | patch edits match once; old table = released; imports | held | patch ok=True; edits [1, 1, 1, 1, 1]; import ok |
| T1 | patched tests pass, at least 41 | held | patched: ran 41, failures [], errors []; base: ran 35 ok True |
| U1 | grader unit tests pass | held | ran 14, failures [], errors [] |
| F1 | same 4 files, same commit, same SHA-256 as v1 | held | commit 3e85cae1; scalar_type.h, scalar_type_util.h, tensor_parser_portable.cpp, scalar_type.fbs all identical to v1 |
| V1 | table keys/sizes = ET_FORALL_SCALAR_TYPES | held | 30 runtime dtypes, table equal |
| V2 | parser still gates on isValid (>=0, NumOptions, Undefined) | held | parser_calls_isValid, isValid_found, nonnegative, NumOptions, Undefined: all true |
| V3 | entry starts = parsed = comments; comments 0..N-1 | held | 30 entry starts, 30 parsed, 30 comments, 0..29 |

Counts: 30 entry starts, 30 parsed, 30 comments. Runtime dtypes the 0.1.0 table lacked:
ComplexHalf (8), ComplexFloat (9), ComplexDouble (10), Bits1x8 (18), Bits2x4 (19),
Bits4x2 (20), Bits8 (21).

## What this does and doesn't show

- It checks the scanner's table against ExecuTorch's source at one commit.
  Published files were covered by v1's rows G1, E1 and D1-D4, which held
  on the same patched code (448 files from 173 models; the 15 files 0.1.0 flagged
  only for a dtype, all `ComplexFloat`, get no integrity finding under 0.1.1).
  Those rows were not re-run.
- Sizes come from C type names through a fixed mapping, not a compiler.
- The v1 failure (row V1) was a bug in our grader, which skipped wrapped entries;
  v2 added row V3 to catch exactly that, and it held.
- The default gate is still dominated by the backend-delegate notice PTE003
  (433 of 448 honest files); this release does not change that.
- A clean scan means the structure is consistent; it does not mean a program
  is safe.

Raw outputs: [pte-dtype-v2/](pte-dtype-v2/) (dtype_v2_summary.json,
vendor_check.json, patch_report.json).
