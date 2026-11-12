# Pre-registration: executorch_pte_scan 0.1.1, dtypes the runtime accepts (job pte-dtype-v1)

Written 2026-11-12, before the job runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## Why

The census of 450 published `.pte` programs
([RESULTS_PTE_CENSUS_2026-11.md](../RESULTS_PTE_CENSUS_2026-11.md)) failed
its row R1. 15 honest files got PTE004 "scalar_type 9 is not an ExecuTorch
dtype". ExecuTorch's runtime accepts every `ScalarType` from 0 to 29
(`isValid` in `runtime/core/exec_aten/util/scalar_type_util.h`, which
`runtime/executor/tensor_parser_portable.cpp` calls on every tensor) and sizes
each with `sizeof` over `ET_FORALL_SCALAR_TYPES`
(`runtime/core/portable_type/scalar_type.h`). The scanner's table followed
`schema/scalar_type.fbs`, which lists `ComplexHalf`, `ComplexFloat`,
`ComplexDouble` (8-10) and `Bits1x8`..`Bits8` (18-21) only as comments. 9 is
`ComplexFloat`.

## The fix (candidate 0.1.1)

- `_ELEMENT_SIZE` gets the runtime's full list, adding 8: 4, 9: 8, 10: 16 and
  18-21: 1 byte each. Every other entry is unchanged.
- Tensors of those types now get the same byte-size and bounds checks as any
  other. A value outside 0-29 is still PTE004.
- `__version__` becomes 0.1.1. The released test that used 9 as its "unknown
  dtype" now uses 30 (`Undefined` in the runtime enum), and the version test
  expects 0.1.1. `EXECUTORCH_PTE_SCAN.md` gets a "Changes in 0.1.1" section
  that also corrects its line that a genuine export never carries an
  integrity finding.
- New tests (`test_executorch_pte_dtypes.py`, 6 tests on hand-built honest
  programs): the table equals the runtime list, every dtype 0-29 is clean,
  complex sizes are checked (8, 16 and 4 bytes per element), and 30, 31, 64,
  127, -1 and -128 are still PTE004.
- Nothing else changes. `model_file_scan`, its version and `pyproject.toml`
  are untouched.

## Method (research/pte-dtype/)

In a sealed container: download release v0.60.0 (the unpatched baseline),
build the patched copy (each edit must match exactly once), and save four
ExecuTorch source files from `main` as text. Then fetch a fresh Hub sample
with exactly the census code (open `executorch`-tagged models by downloads,
up to 3 `.pte` files per model, the first 450 probed, program bytes only,
up to 40 small files whole). With no network, scan every file with both 0.1.0
and 0.1.1. Nothing is loaded or executed.

## Rows (all predictions written now)

| Row | Prediction |
|---|---|
| P1 | every patch edit matches exactly once, the old table equals the released one, and the patched module imports |
| T1 | the patched test files pass, with at least 41 tests (35 released, 2 of them edited, plus 6 new) |
| V1 | `ET_FORALL_SCALAR_TYPES` in ExecuTorch's `scalar_type.h` parses to entries 0..N-1; the patched table has exactly those keys; each size equals the size derived from the entry's C type (`complex<T>` = 2 x T) |
| V2 | `tensor_parser_portable.cpp` still calls `isValid(scalar_type)`, and `isValid` tests `>= 0`, `NumOptions` and `Undefined` |
| G1 | at least 100 files from at least 30 models are scanned (otherwise D1-D4 are untestable) |
| E1 | 0.1.1 gives the same findings on the whole file and the sparse rebuild for every whole file (at least 10; otherwise, or if E1 fails, D1-D4 are untestable) |
| D1 | no file gets a "not an ExecuTorch dtype" note from 0.1.1 |
| D2 | at most 2% of files get PTE001, PTE002 or PTE004 from 0.1.1 (census row R1 again; we expect 0) |
| D3 | no file that 0.1.0 flagged only for dtypes gets PTE001, PTE002 or PTE004 from 0.1.1 (needs at least one such file) |
| D4 | on every file, 0.1.1's findings equal 0.1.0's with the dtype-only PTE004 entry removed: no other finding appears, disappears or changes |

## What we will do with the result (fixed now)

- **All of P1, T1, V1, V2, G1, E1, D1-D4 hold:** release the patched
  `executorch_pte_scan.py`, both test files and `EXECUTORCH_PTE_SCAN.md` as
  the next release, after a results write-up
  (`REALFILE_CHECK_PTE_DTYPE_2026-11.md`), with the tests run before the commit.
- **Any of them fails or is untestable:** nothing ships. The results are
  published as measured, and any new fix gets its own pre-registration.
- **D3 fails** (a complex tensor really overruns its region): report the file
  and evidence neutrally, as measured, without guessing at intent.
- The not-yet-released `.ptd` scanner (`executorch_ptd_scan`, job
  ptd-scan-v1) copied the same table. It is not changed by this job. If this
  fix ships, the `.ptd` scanner gets the same change in its own step.

## Limits

This is one day's Hub listing (it may differ from the census day), and the
files are the most-downloaded ones. The V1 sizes come from C type names
mapped by a fixed table (the wrapper structs `Half`, `BFloat16`, `qint*`,
`quint*`, `bits*` and `Float8_*` hold a single member of the listed size), not
from a compiler. A clean scan means the structure is consistent. It does not
mean the program is safe.
