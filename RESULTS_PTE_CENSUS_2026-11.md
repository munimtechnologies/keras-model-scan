# Results: ExecuTorch programs on the Hugging Face Hub (job pte-census-v1)

Graded 2026-11-12. Pre-registration:
[research/PREREG_PTE_CENSUS.md](research/PREREG_PTE_CENSUS.md) (written
2026-11-11, before the job ran). Made with AI agents working in the name of
MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

**Summary.** `executorch_pte_scan` 0.1.0 (the version in releases v0.59.0 and
v0.60.0) was run, unchanged, on 450 published `.pte` programs from 171 open
Hugging Face models. 7 of 8 pre-registered rows held. **R1 failed:** 15 files
(3.3%, limit 2%) got an integrity finding. In every one of them the only
finding is PTE004 "scalar_type 9 is not an ExecuTorch dtype". Reading
ExecuTorch's runtime source shows that the scanner is wrong here, not the
files: type 9 is `ComplexFloat`, and the runtime's tensor parser accepts it.
The scanner's dtype table was copied from `schema/scalar_type.fbs`, which
lists complex types only as comments. A fix has its own pre-registration
([research/PREREG_PTE_DTYPE_FIX.md](research/PREREG_PTE_DTYPE_FIX.md)).

## What ran

- Job `pte-census-v1`, sealed container, no network during the scan;
  2026-11-12 14:41-15:02 UTC; peak memory 0.07 GB.
- The job's own helper tests (17) and the scanner's released tests (35) passed
  before the scan.
- Hub listing (public API, tag `executorch`, by downloads): 914 models, 861
  open; 850 ship a `.pte`, 18 a `.ptd`, 17 both; 3,259 `.pte` files in all.
  Up to 3 files per model gave 1,537 candidates, and the first 450 were
  probed. 466 MB of program bytes were fetched; no file was skipped.
- File sizes: median 90 MB, largest 21 GB. Program (FlatBuffer) sizes: median
  39 KB, largest 2.6 MB. 442 of 450 files have an `eh00` extended header.

## Rows

| Row | Prediction | Result | Measured |
|---|---|---|---|
| G1 | at least 100 files from at least 30 models | held | 450 files, 171 models |
| E1 | whole-file scans equal sparse-rebuild scans (at least 10 files) | held | 40 of 40 the same |
| R1 | at most 2% of files get PTE001, PTE002 or PTE004 | **failed** | 15 of 450 (3.3%) |
| R2 | at most 5% get PTE005 | held | 8 of 450 (1.8%) |
| R3 | at least 70% get PTE003 (backend delegate) | held | 433 of 450 (96.2%) |
| R4 | `XnnpackBackend` is the delegate named in the most files | held | 188 files, then CoreML 75 |
| R5 | at least 70% fail the default `--fail-on medium` gate | held | 438 of 450 (97.3%) |
| R6 | at least 95% of probed files are `ET12` | held | 450 of 450 |

Delegates by files: XnnpackBackend 188, CoreMLBackend 75, VulkanBackend 58,
MLXBackend 45, NeuropilotBackend 36, QnnBackend 24, CudaBackend 10,
EthosUBackend 3, MetalBackend 1. 12 files had no finding at all.

One file per model (the first in the fixed order, 171 files): PTE003 165,
integrity finding 4, PTE005 3, default gate fails 167.

## R1: 15 files, one cause

Every R1 file carries a single PTE004 note whose evidence is a tensor with
`scalar_type 9`, from 1 to 3 tensors per file:

| Model | Files |
|---|---|
| software-mansion/gemma-4-E2B-it-ExecuTorch | 3 |
| larryliu0820/parakeet-tdt-0.6b-v3-executorch | 3 |
| Arm/whisper-small-int8-xnnpack-executorch | 2 |
| Arm/whisper-tiny-int8-xnnpack-executorch | 2 |
| wasi-master/parakeet-ultra-executorch | 2 |
| software-mansion/fsmn-vad-ExecuTorch | 1 |
| mistral-experimental/Voxtral-Mini-4B-Realtime-2602-ExecuTorch | 1 |
| larryliu0820/whisper-large-v3-turbo-INT8-INT4-ExecuTorch-XNNPACK | 1 |

Most of these are speech models, and five of the files are named
`preprocessor.pte` or `whisper_preprocessor.pte`.

As the pre-registration required, the finding was read against ExecuTorch's
own source (main branch, read 2026-11-12; reading only, nothing was run):

- `schema/scalar_type.fbs` lists 23 values. `COMPLEXHALF = 8`,
  `COMPLEXFLOAT = 9`, `COMPLEXDOUBLE = 10` and `BITS1x8`..`BITS8` (18-21)
  are present only as comments under "Types currently not implemented".
- The runtime enum (`runtime/core/portable_type/scalar_type.h`,
  `ET_FORALL_SCALAR_TYPES`) defines every value from 0 to 29, including
  `complex<float>, ComplexFloat /* 9 */`.
- `runtime/executor/tensor_parser_portable.cpp` casts the stored value to
  that enum and rejects the tensor only if `!isValid(scalar_type)`.
- `isValid` (`runtime/core/exec_aten/util/scalar_type_util.h`) accepts any
  value from 0 up to `NumOptions` other than `Undefined`, and `elementSize`
  is `sizeof` over the same list (8 bytes for `ComplexFloat`).

So the runtime's loader accepts type 9, and the scanner's table, which follows
the `.fbs` file, does not. These are false positives in our scanner. They are
not malformed files. The scanner also skipped the size checks for those
tensors, because it stops at an unknown dtype. A fix that uses the runtime's
list (adding 8, 9, 10 and 18-21 with their `sizeof` sizes) is pre-registered
and queued as job `pte-dtype-v1`. It ships only if every row holds.

The module docs say of integrity findings that "a genuine export never
contains them". For dtypes 8-10 and 18-21 that was wrong, and the release
that carries the fix will say so.

## R2: 8 files with PTE005 (held, recorded)

All 8 lack an `eh00` extended header but list one data segment:
Arm/depth-anything-v3-small-mix-precision (2), Arm/zipdepth-fp16-executorch
(2), abhijitbetigeri/dcops-e8 (3, Ethos-U85 programs) and
anira-project/simple-gain (1). ExecuTorch's `Program::load` treats a file
without the header as "the program consumes the whole file, and there are
no segments". A segment load then fails only when something actually asks
for a segment, and a constant segment with a single offset counts as empty.
Whether these 8 programs ever ask for one was not checked. R2 held, and
nothing changes now. Whether PTE005 should fire only when a segment is
actually referenced is left for a later pre-registered check.

## R3 and R5 held: what that means for the default gate

97.3% of honest published `.pte` files fail `model-file-scan`'s default
`--fail-on medium` gate, almost all because of PTE003 alone (a MEDIUM note
that the file carries a backend blob the scanner cannot read inside). As
fixed in advance, whether PTE003 should stay MEDIUM is a separate
pre-registered decision, with this census as its evidence. Nothing changed
in this job.

## Limits

This is one day's Hub listing. The most-downloaded models dominate, with at
most 3 files per model, and files from the same model are not independent.
Only the program bytes were scanned, and E1 showed this matches whole-file
scans on 40 files. A clean scan means the structure is consistent. It does
not mean the program is safe. No file was loaded or executed.

Graded output:
[research/pte-census/pte_census_summary.json](research/pte-census/pte_census_summary.json)
(rows, counts, every flagged file and every whole-file comparison).
