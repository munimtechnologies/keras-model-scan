# Pre-registration: executorch_pte_scan 0.1.1 dtype table, corrected grader (job pte-dtype-v2)

Written 2026-11-14, after job pte-dtype-v1 finished and BEFORE job
pte-dtype-v2 runs. The job's first setup step waits until this file is public
on `main` and records its SHA-256; nothing is graded before that. Made with
AI agents working in the name of MV2 of Munim, Inc. Apache-2.0 (code),
CC BY 4.0 (this text).

## Why there is a v2

Job pte-dtype-v1 ([research/PREREG_PTE_DTYPE_FIX.md](PREREG_PTE_DTYPE_FIX.md),
results in [REALFILE_CHECK_PTE_DTYPE_2026-11.md](../REALFILE_CHECK_PTE_DTYPE_2026-11.md))
held 9 of 10 rows. Row V1 failed, so under that pre-registration nothing
shipped, and it stays that way.

We looked into the failure after seeing it. Our grader's regex for
`_(ctype, Name)` entries in ExecuTorch's `ET_FORALL_SCALAR_TYPES` could not
match an entry that is wrapped with a backslash continuation between the C
type and the name. At the commit we read (`3e85cae1`), five entries are
wrapped that way: ComplexHalf (8) and the four Float8 types (23-26). The
grader dropped them and numbered the rest by position, one off. We believe
the table is right, but that judgement was made after the result, so v2
re-tests the claim with a fixed grader instead of re-reading v1.

## What changes and what does not

- **Same candidate code.** `patch_pte.py` makes the same five code edits to
  the released v0.60.0 tree. The only text change is that the 0.1.1 release
  note in `EXECUTORCH_PTE_SCAN.md` also links the v1 results and this file.
- **Same ground truth.** The same four ExecuTorch files at the same commit
  `3e85cae1e744454713413db4deb31090a505adf4`, pinned this time (v1 read
  `main`, which resolved to that commit).
- **Fixed grader.** `vendor_check.py` joins backslash line continuations
  before parsing. V1 means exactly what it meant in v1.
- **New guard rows.** U1: the grader's own unit tests (including one that
  reproduces the v1 defect on a hand-written macro) must pass. V3: the number
  of `_(` entry starts, the number of parsed entries and the number of
  `/* n */` comments must be equal, with the comments exactly 0..N-1. A parser
  that skips an entry now fails V3 instead of grading a shifted list.
- **Not re-run:** G1, E1 and D1-D4. They held in v1 on the same patched code
  and are published there. v2 downloads no model files.

Scripts: [research/pte-dtype-v2/](pte-dtype-v2/) (published together with
this file, before the run).

## Rows (all must hold)

| Row | Prediction | Fails if |
|---|---|---|
| P1 | each patch edit matches exactly once, the old table equals the released one, and the patched module imports | any edit matches 0 or 2+ times, or import fails |
| T1 | the patched `test_executorch_pte*.py` tests pass and at least 41 run | any failure or error, or fewer than 41 |
| U1 | `test_vendor_check.py` passes | any failure or error |
| F1 | all four files fetched at `3e85cae1`, each with the same SHA-256 that v1 recorded | any file missing or different |
| V1 | `ET_FORALL_SCALAR_TYPES` parses to entries 0..N-1 (comments agree with positions); the patched table has exactly those keys; each size equals the size from the entry's C type (complex = twice its inner type) | any mismatch |
| V2 | `tensor_parser_portable.cpp` still rejects a tensor only through `isValid(scalar_type)`, and `isValid` tests `>= 0`, `NumOptions` and `Undefined` | any check false |
| V3 | entry starts = parsed entries = comments, every entry has a comment, and the comments are 0..N-1 | any count differs or a comment is missing or out of order |

Our prediction: all 7 hold, with N = 30.

## Release rule

If all 7 rows hold: publish the v2 results first, then release the job's
`out/patched/` files (`executorch_pte_scan.py`, `test_executorch_pte_scan.py`,
`test_executorch_pte_dtypes.py`, `EXECUTORCH_PTE_SCAN.md`) as the next
keras-model-scan release, with the tests run before the commit.

If any row fails or cannot be tested, nothing ships, and the results are
published as measured. In particular:
- V3 fails: the grader still misses entries, so V1 means nothing. The grader
  gets fixed, with a new pre-registration.
- V3 holds and V1 fails: the table is wrong. The fix is withdrawn and rethought.
- F1 fails: the source changed under the same commit id or did not download.
  Report it; no release.

## Limits

V1 maps C type names to sizes through a fixed table, not a compiler. The rows
check the scanner against ExecuTorch's source, not against every program on
the Hub; the v1 real-file rows cover that. A clean scan means the structure is
consistent. It does not mean a program is safe.
