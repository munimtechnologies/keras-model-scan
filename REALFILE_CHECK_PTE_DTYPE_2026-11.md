# Real-file check: executorch_pte_scan 0.1.1 dtypes (job pte-dtype-v1)

Pre-registered in [research/PREREG_PTE_DTYPE_FIX.md](research/PREREG_PTE_DTYPE_FIX.md)
before the job ran. Made with AI agents working in the name of MV2 of
Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

The job finished at 2026-11-14 12:16 UTC (sealed container, 1 CPU, peak memory 0.07 GB,
no network in the run steps). ExecuTorch source was read at commit
`3e85cae1e744454713413db4deb31090a505adf4`. Scanners: released 0.1.0, candidate 0.1.1.

## Outcome

**9 of 10 rows held; V1 failed. Nothing ships.** executorch_pte_scan 0.1.0 is
still the released scanner (keras-model-scan v0.60.0). As the pre-registration
requires, any further attempt at this fix gets its own pre-registration. It is
[research/PREREG_PTE_DTYPE_FIX_V2.md](research/PREREG_PTE_DTYPE_FIX_V2.md),
published together with this write-up.

Why V1 failed (diagnosis written after the result, so read it as such): the
fault is in **the grader**, not the scanner. Row V1 parses the
`ET_FORALL_SCALAR_TYPES` X-macro in ExecuTorch's `scalar_type.h`. Five of its
30 entries are wrapped over two lines with a backslash continuation between the C
type and the name: `ComplexHalf` (8) and `Float8_e5m2`, `Float8_e4m3fn`,
`Float8_e5m2fnuz`, `Float8_e4m3fnuz` (23-26). The grader's regex did not allow
for a continuation there, so it skipped those five and numbered the other 25 by
position. From `ComplexFloat` on, every entry is shifted by one. The grader's
own output shows this: for every entry after the first skipped one, the
header's own `/* n */` comment ("ComplexFloat: comment 9 at position 8", and so
on) equals the key the patched table uses. Keyed by those comments, all 25
parsed sizes equal the patched table, and the five comment numbers missing
from the parsed list (8 and 23-26) are exactly the five wrapped entries.
Reading the header by hand gives the same
result: all 30 patched entries (0-29) match it. This is a diagnosis, not a pass. The
rule says nothing ships, so nothing ships. The v2 job re-runs V1 with the
parser fixed and adds a completeness row (V3), so a grader that skips an
entry fails loudly instead of grading a shifted list.

## Rows

| Row | Prediction (short) | Result | Measured |
|---|---|---|---|
| P1 | each patch edit matches once; old table = released; module imports | held | patch ok; edits [1, 1, 1, 1, 1]; import ok |
| T1 | patched tests pass, at least 41 | held | patched: ran 41, 0 failures, 0 errors; base: ran 35, ok |
| V1 | table keys/sizes = ET_FORALL_SCALAR_TYPES in scalar_type.h | **failed** | 17 "comment n at position n-1" mismatches (ComplexFloat .. UInt64); keys in table only: 25-29; 9 size mismatches (dtypes 8, 9, 10, 13, 14, 15, 21, 23, 24), all from the one-position shift described above |
| V2 | tensor parser still calls isValid; isValid checks >=0, NumOptions, Undefined | held | all five checks true |
| G1 | at least 100 files from 30 models | held | 448 files from 173 models |
| E1 | whole file = sparse rebuild under 0.1.1 (at least 10) | held | 40 of 40 whole files scan the same |
| D1 | no "not an ExecuTorch dtype" note under 0.1.1 | held | 0 of 448 |
| D2 | at most 2% of files get PTE001/2/4 under 0.1.1 | held | 0 of 448 |
| D3 | files 0.1.0 flagged only for dtypes get no PTE001/2/4 | held | 0 of 15 |
| D4 | 0.1.1 findings = 0.1.0 findings minus dtype-only PTE004 | held | 0 of 448 differ |

## Numbers

- Hub list (one page of the most-downloaded `executorch`-tagged models): 917
  models, 864 open, 853 with a `.pte`, 3,263 `.pte` files. 1,540 candidates (at
  most 3 per model); 450 probed; 448 scanned from 173 models; 473,650,910 bytes
  fetched (headers and program bytes only, plus 40 whole files).
- 0.1.0: 15 files with PTE001/2/4, all 15 only for a dtype note (0 mixed).
- 0.1.1: 0 files with PTE001/2/4; 8 with PTE005; 433 with PTE003; 438 fail the
  default gate; 10 have no finding at all.
- The 15 files that had a dtype note under 0.1.0 all show `scalar_type 9`
  (ComplexFloat), and under 0.1.1 they have no integrity finding: 
  software-mansion/fsmn-vad-ExecuTorch (1 file),
  software-mansion/gemma-4-E2B-it-ExecuTorch (3), larryliu0820/parakeet-tdt-0.6b-v3-executorch (3),
  Arm/whisper-small-int8-xnnpack-executorch (2), Arm/whisper-tiny-int8-xnnpack-executorch (2),
  mistral-experimental/Voxtral-Mini-4B-Realtime-2602-ExecuTorch (1),
  wasi-master/parakeet-ultra-executorch (2),
  larryliu0820/whisper-large-v3-turbo-INT8-INT4-ExecuTorch-XNNPACK (1).
  Per-file detail: [research/pte-dtype/dtype_summary.json](research/pte-dtype/dtype_summary.json).
- No new integrity findings, D4 differences or equivalence failures.

## What this does and doesn't show

- The default gate is still dominated by PTE003: 433 of 448 honest files here.
  This job does not change PTE003; a separate pre-registered decision follows.
- The unreleased `.ptd` scanner copied the same dtype table. It gets fixed in
  its own pre-registered step, and only after this fix ships.
- This is one day's Hub listing of the most-downloaded `executorch`-tagged
  models, drawn with the same code as the November census, so it overlaps that
  sample heavily. V1 derives sizes from C type names through a fixed mapping,
  not from a compiler. Nothing was loaded or executed. A clean scan means the
  structure is consistent; it does not mean a program is safe.

Raw outputs: [research/pte-dtype/](research/pte-dtype/) (dtype_summary.json,
patch_report.json, vendor_check.json).
