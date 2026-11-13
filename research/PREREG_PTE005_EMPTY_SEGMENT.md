# Pre-registration: PTE005 and the empty constant segment (ExecuTorch `.pte`)

Status: **pre-registered 2026-11-13, before any job has run.** Nothing here is
released. Made with AI agents working in the name of MV2 of Munim, Inc.
Text CC BY 4.0, code Apache-2.0.

## Question

In job pte-census-v1 ([RESULTS_PTE_CENSUS_2026-11.md](../RESULTS_PTE_CENSUS_2026-11.md),
per-file data in [pte-census/](pte-census/)), `executorch_pte_scan` 0.1.0
raised **PTE005** (medium, CWE-693, "the program lists data segments but no
extended header gives a segment base offset") on 8 of 450 honest published
`.pte` files. All 8 are `ET12` files with no `eh00` extended header that list
exactly 1 segment:

| census n | Hugging Face repo | file | bytes |
|---|---|---|---|
| 219 | Arm/depth-anything-v3-small-mix-precision | da3_prepare_image.pte | 1,104 |
| 220 | Arm/depth-anything-v3-small-mix-precision | da3_restore_depth.pte | 1,408 |
| 255 | Arm/zipdepth-fp16-executorch | zipdepth_prepare_image.pte | 1,992 |
| 256 | Arm/zipdepth-fp16-executorch | zipdepth_restore_depth.pte | 2,024 |
| 301 | anira-project/simple-gain | executorch/simple_gain_network_16ch.pte | 1,720 |
| 304 | abhijitbetigeri/dcops-e8 | deployed/kws_dscnn_m_agc/kws_ethos-u85-256.pte | 95,424 |
| 305 | abhijitbetigeri/dcops-e8 | deployed/vision_v3_board_ft/student_ethos-u85-256.pte | 2,356,624 |
| 306 | abhijitbetigeri/dcops-e8 | deployed/vision_v4_demo_ft/student_ethos-u85-256.pte | 2,356,448 |

Is this our scanner's false positive on the writer's normal output, or a
real layout quirk?

## What the vendor source says (ground truth, read 2026-11-13, pytorch/executorch main)

- **Writer**, `exir/_serialize/_program.py`, `serialize_pte_binary`: the
  constant segment is appended under `if len(constant_segment_offsets) > 0:`,
  and its own comment says that with no constants the data length is 0 but
  `constant_segment_offsets` still has one entry. Each listed segment gets
  `size=len(segment.data)`, and the header is skipped by
  `# If there are no segments present, do not insert the extended header.`
  / `if len(segments_data) == 0:` (a byte-length test on the segment data,
  not a count of `program.segments`). So a program without constants is
  written with **one listed segment of size 0, constant offsets `[0]`, and
  no extended header**.
- **Runtime**, `runtime/executor/program.cpp`: with no extended header the
  loader takes the whole file as the program ("there are no" segments) and
  leaves the segment base offset at 0; `LoadSegment` refuses any segment
  load when the base offset is 0; a constant segment with exactly one offset
  is loaded as "no constant data". Nothing is read through a size-0 segment.

So the hypothesis is that all 8 are the writer's no-constants layout, and
PTE005 should fire only when a headerless program lists a segment that holds
bytes.

## Change under test (staged, not released)

`executorch_pte_scan` next patch version, applied by
[pte005-empty-segment/patch_pte005.py](pte005-empty-segment/patch_pte005.py)
on top of whichever version is the latest release when the job runs (0.1.1
or 0.1.2 are already staged and touch different lines):

- headerless PTE005 test: `any segment listed` -> `any listed segment has a
  non-zero size`. A headerless program listing a segment with bytes still
  gets PTE005, unchanged (existing test kept).
- docstring row and `EXECUTORCH_PTE_SCAN.md` "Changes in" section.
- new [test_executorch_pte_segments.py](pte005-empty-segment/test_executorch_pte_segments.py)
  (7 tests, hand-built honest structures only).

No severity, rule id or other rule changes.

## Job (to be filed as `pte005-cal-v1`, kind poc, 1 CPU, 1-2 GB)

Fetch the repository tree at the latest release tag; run all tests on it;
apply the patch; run all tests on the patched tree; download the 8 files
above whole from Hugging Face (about 4.8 MB, revision recorded); download a
regression set of other census files (seeded sample, seed 20261113, of
the census files under 10 MB, up to 60, whole); scan everything with the released and the patched
module; record each file's segment table (offset, size), whether it has an
extended header, and the constant segment's offset count.

## Rows (fixed now)

- **P1** patch_report ok: every anchored edit matched exactly once; patched
  module imports with the new version.
- **T1** every test passes on the released tree and on the patched tree;
  the patched tree runs at least 7 more tests.
- **D1** (prediction) all 8 files: no extended header, every listed segment
  has size 0.
- **D2** (prediction) all 8 files: the constant segment, where present, has
  at most 1 offset (no constant tensor is read from a segment).
- **R1** patched module: 0 PTE005 findings on the 8 files; every other
  finding on them identical to the released module's (rule, severity,
  message, evidence).
- **R2** at least 40 other census files (the census has 77 others under
  10 MB; the model count is reported, not gated): findings identical
  between released and patched module.
- **R3** (reported, not a gate) default `--fail-on medium` gate result of
  the 8 files before and after (files with a PTE003 delegate finding may
  still fail on PTE003).
- **Release rule:** P1, T1, D1, R1 and R2 hold. Otherwise the results are
  published as measured and nothing is released. If D1 fails (a file lists
  a segment that holds bytes with no header), that file is a real layout
  quirk and keeps PTE005.

## Honest limits

- 8 files from 4 repositories; the writer and runtime were read at
  `main` on 2026-11-13, which may differ from the ExecuTorch versions that
  wrote these files.
- Static review only: no file is loaded by the ExecuTorch runtime.
- A PTE005 finding was never a claim that a model is unsafe; neither is its
  absence.
