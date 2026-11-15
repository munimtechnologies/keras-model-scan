# Gate arithmetic on the ExecuTorch .pte census (2026-11-14, updated 2026-11-15)

Made with AI agents working in the name of MV2 of Munim, Inc. Text: CC BY 4.0;
code: Apache-2.0.

**What this is:** counting on the published per-file findings of job
pte-census-v1 (`pte_census_files.json` in this folder: executorch_pte_scan
0.1.0 on 450 honest, published `.pte` files from 171 Hugging Face models). No
file was downloaded or scanned again. Every number below is recomputed by
`gate_arithmetic.py` and pinned by `test_pte_census_arithmetic.py` at the repo
root.

**What this is not:** a measurement of a patched scanner, or a statement about
which ExecuTorch backends load native code. A finding is not a claim that a
model is unsafe.

## Update 2026-11-15: the shipped dtype fix changes no gate outcome here
Fix 1 below (the data-type table) has shipped: executorch_pte_scan 0.1.1 in
release v0.61.0, after its pre-registered re-check (job pte-dtype-v2) held 7 of
7 rows. Its real-file check measured the 15 PTE004 false alarms disappearing.
Counting the census by fix (new `per_fix` output of `gate_arithmetic.py`):

| Fix alone | Findings | Files | Files that also carry PTE003 | Still fail the default gate |
|---|---|---|---|---|
| none (0.1.0 findings) | - | - | - | 438 (97.3%) |
| dtype table (shipped, 0.1.1) | 15 | 15 | 15 | **438 (97.3%)** |
| single-segment PTE005 (queued, pte005-cal-v1) | 8 | 8 | 3 | 433 (96.2%) |
| both | 23 | 23 | 18 | 433 (96.2%) |

Every file with a dtype false alarm also names a backend delegate (PTE003,
medium), so removing those 15 findings fixed what the report says but moved no
file across the default gate. The whole five-file gain depends on the PTE005
fix: 5 of its 8 files have no other finding. The other 3 are the census's three
Ethos-U files (one model), which also carry PTE003. This is arithmetic on
recorded 0.1.0 findings. The PTE005 fix is still waiting for its own
pre-registered check, and nothing here predicts how that check will come out.

## Why count this
model-file-scan's default gate (`--fail-on medium`) fails **438 of 450 (97.3%)**
of these honest files (RESULTS_PTE_CENSUS_2026-11.md, row R5). A gate that fails
almost everything teaches people to switch it off. Three changes were staged,
each with its own pre-registered check on real files before anything is released:

1. a data-type table fix (jobs pte-dtype-v1 and pte-dtype-v2; **shipped in
   v0.61.0**): every one of the 15 PTE004 findings here has only "scalar_type 9"
   evidence;
2. a PTE005 fix for ExecuTorch's own no-constants layout (job pte005-cal-v1,
   PREREG_PTE005_EMPTY_SEGMENT.md): all 8 PTE005 findings are on single-segment
   programs;
3. a planned PTE003 change: rate the "backend delegate present" notice low only
   for backends whose ExecuTorch runtime source shows no dynamic-library loader
   call. Its pre-registration is not public yet.

## Results
| Quantity | Files |
|---|---|
| files / models | 450 / 171 |
| files with any PTE003 (backend delegate) | 433 |
| files naming 0 / 1 / 2 backends | 17 / 426 / 7 |
| findings that fixes 1 and 2 target (15 PTE004 + 8 PTE005) | 23 |
| other non-PTE003 findings | 0 |
| fail the default gate today | 438 (97.3%) |
| fail if the 23 targeted findings were gone | 433 (96.2%) |

So fixes 1 and 2, even if both clear every finding they target, move the gate
from 97.3% to 96.2%. On these files the gate is decided by PTE003 alone.

Files naming each backend (a file can name two): XNNPACK 188, Core ML 75,
Vulkan 58, MLX 45, NeuroPilot 36, QNN 24, CUDA 10, Ethos-U 3, Metal 1. All 7
two-backend files pair XNNPACK with one other: Vulkan (4), QNN (2), MLX (1).

**What-if ladder.** Without the 23 targeted findings, how many files still fail
if the PTE003 notice were "low" for the backends listed so far? Backends are
added in descending file count. That order is neutral, not a ranking of safety,
and nothing here says any backend will qualify.

| PTE003 "low" for | Still fail |
|---|---|
| none | 433 (96.2%) |
| + XNNPACK | 252 (56.0%) |
| + Core ML | 177 (39.3%) |
| + Vulkan | 119 (26.4%) |
| + MLX | 74 (16.4%) |
| + NeuroPilot | 38 (8.4%) |
| + QNN | 14 (3.1%) |
| + CUDA | 4 (0.9%) |
| + Ethos-U | 1 (0.2%) |
| + Metal | 0 (0.0%) |

## What this tells the planned PTE003 check
- On this sample, the XNNPACK decision alone moves the gate by about 41
  percentage points (97.3% to 56.0%). Every two-backend file includes XNNPACK,
  so the other backend sets the outcome for those 7 files.
- A planned prediction that the gate-fail rate drops by at least 30 points
  would, on this sample's backend mix, hold only if XNNPACK qualifies. The real
  check uses a fresh draw of files not in this census, whose backend mix may
  differ (it comes from less-downloaded models).
- If only some backends qualify, a sizeable share of honest files will still
  fail the default gate. That will be documented rather than hidden. Note that
  `--fail-on high` is not a substitute: it also stops gating on the medium
  integrity rules (PTE004, PTE005), not only on PTE003.
- Lesson recorded on 2026-11-15: a fix that removes real false alarms can
  still change no gate outcome when another rule fires on the same files.
  Future pre-registrations count gate outcomes per fix, not only findings.

## Limits
- The PTE005 what-if treats "1 segments" as the no-constants layout. The census
  did not record segment sizes; pte005-cal-v1 measures this on pinned files.
- The dtype rows count the census's 0.1.0 findings with the 15 "scalar_type 9"
  notes removed. pte-dtype-v1 measured on 448 published .pte files that the 15
  findings disappear under 0.1.1 (REALFILE_CHECK_PTE_DTYPE_2026-11.md). The
  census was not re-scanned with 0.1.1.
- One snapshot (pte-census-v1, November 2026) of the most-downloaded public
  `.pte` files; 3 files per model at most.

Reproduce: `python research/pte-census/gate_arithmetic.py` (stdlib only), or
pass a different order of backends as arguments.
