# Ledger of pre-registered checks (as of 2026-11-15)

MV2 of Munim, Inc. checks changes to model-file-scan (this repository) the same way
each time. The predictions are written down and committed first (`research/PREREG_*.md`).
A sealed job then runs them on files that the real libraries wrote, and the results are
published as measured (`REALFILE_CHECK_*.md` / `RESULTS_*.md`). A fix ships only if
every row its pre-registration names as gating holds.

This page counts every graded check so far in one place, **including the misses**.
It was compiled from each write-up's own headline counts. If this page and a linked
write-up disagree, the write-up is authoritative. Made with AI agents working in MV2's
name. Text: CC BY 4.0; code in this repository: Apache-2.0.

## Totals (36 graded checks, 30 Oct - 14 Nov 2026)

| | count |
|---|---|
| Graded checks (jobs) | 36 |
| Checks where every graded row held | 26 |
| Checks with at least one miss | 10 |
| Graded prediction rows | 409 |
| Rows that held | 396 (96.8%) |
| Rows that failed | 13 |
| Releases gated by a check that held | 11 (v0.52.0 to v0.60.0) |
| Releases blocked by a failed row | 4 (three later shipped after a re-run; one re-run is queued) |

How rows are counted: rows that were "not run" or "untestable" are left out (3 in
pt2-census-v1, 1 in nemo-legacy-v1), as each write-up says. When a job was re-run
under the same pre-registration (paddle v2 -> v3, ovi-realfile v2 -> v3), only the
final graded run is counted. Runs that crashed before writing results were never
graded and are not counted (coreml v1, gguf-types v1, ovi-realfile v1, oed-functions v1).

A high hold rate is **not** evidence that the scanner catches attacks. Most rows
predict how the scanner behaves on honest files written by the real libraries
(false alarms and silent skips). The predictions were written by the same agents who
wrote the code, so the rate measures how well they knew their own code, not an
independent audit.

## The 13 failed rows

| Check | Row(s) | What the write-up says | Effect |
|---|---|---|---|
| sti-realfile-v1 | W2 | a wrong guess about what transformers writes, not a scanner problem | measurement only |
| ovi-u3u6-v1 | S1 | test suite failure: a stale `test_version` pin | release blocked; re-run ovi-u3u6-v2 shipped v0.52.1 |
| walk-names-v1 | F3, H3 | false alarms on honest `.pdparams` files (H3: 6 of 7 published files flagged) | release blocked; walk-names-v2 shipped v0.55.0 |
| pkl-memo-v1 | H3 | 2 honest joblib-written Hub files still flagged | release blocked; traced by pkl-diag-v1, fixed in pkl-joblib-v1 (v0.54.0) |
| nemo-legacy-v1 | H1 (not gating) | 55 files walked vs 60 predicted | all 12 release rows held; shipped v0.56.0 |
| zip-storage-v1 | S1, H1 | S1: freshly initialised weights start with byte 0x80 far more often (98 of 3,200) than the 1-in-256 we assumed; H1: only 6 published files fitted the size cap (80 predicted) | measurement only |
| zip-data-v1 | H1, H4 (not gating) | H1: 21 Hub files read vs 30 predicted (download budget); H4: 25 of 3,658 (0.68%) | all 11 release rows held; shipped v0.57.0 |
| pt2-nest-v1 | D1 (diagnostic) | a path mistake in our own grader; the recorded findings confirm the gap D1 predicted | all 11 release rows held; shipped v0.59.0 |
| pte-census-v1 | R1 | scanner false alarm: ComplexFloat (type 9) flagged in 15 of 450 files | measurement; fix pre-registered as pte-dtype |
| pte-dtype-v1 | V1 | our grader's regex skipped five line-wrapped entries in ExecuTorch's header | release blocked; pte-dtype-v2 pre-registered and queued |

By cause, as each write-up states it:
- **Scanner false alarm on honest files: 4 rows** (walk-names F3/H3, pkl-memo H3,
  pte-census R1). Three are fixed in released versions (v0.54.0, v0.55.0); the
  ExecuTorch one (R1) has a fix waiting on its re-check (pte-dtype-v2).
- **Our own grader or test suite: 3 rows** (ovi-u3u6 S1, pt2-nest D1, pte-dtype V1).
  Lesson applied: graders that parse vendor C/C++ source now join `\` line continuations
  and check that every entry was parsed.
- **Our prediction about the outside world: 6 rows** (sti W2, nemo-legacy H1,
  zip-data H1/H4, zip-storage S1/H1). Three of these six are Hub sample sizes that came
  out smaller than predicted (nemo-legacy H1, zip-data H1, zip-storage H1: a download
  budget, a size cap, an empty list, gzip tars left unwalked). None of the six
  blocked a release.

## Every graded check

| # | Job | Graded | Held / graded | Real files | Outcome | Write-up |
|---|---|---|---|---|---|---|
| 1 | mpk-arc-realfile-v1 | 2026-10-30 | 13/13 | msgpack, zip-based and archive files written by the libraries | measurement | [REALFILE_CHECK_2026-10](../REALFILE_CHECK_2026-10.md) |
| 2 | coreml-realfile-v2 | 2026-10-31 | 7/7 | coremltools 9.0 outputs | measurement | [COREML](../REALFILE_CHECK_COREML_2026-10.md) |
| 3 | paddle-realfile-v3 | 2026-10-31 | 7/7 | paddlepaddle 3.3.1 programs | measurement | [PADDLE](../REALFILE_CHECK_PADDLE_2026-10.md) |
| 4 | rds-realfile-v1 | 2026-10-31 | 15/15 | 15 files written by R | measurement | [RDS](../REALFILE_CHECK_RDS_2026-10.md) |
| 5 | tfl-realfile-v1 + pte-realfile-v1 | 2026-10 | 8/8 | TFLite and ExecuTorch converter outputs | measurement | [TFL_PTE](../REALFILE_CHECK_TFL_PTE_2026-10.md) |
| 6 | lgb-realfile-v1 | 2026-11-01 | 10/10 | 8 LightGBM 4.7.0 models | measurement | [LGB](../REALFILE_CHECK_LGB_2026-10.md) |
| 7 | xgb-realfile-v1 | 2026-11-01 | 8/8 | 12 XGBoost .json/.ubj | measurement | [XGB](../REALFILE_CHECK_XGB_2026-10.md) |
| 8 | mfs-tree-route-v1 | 2026-11-01 | 7/7 | 7 honest XGBoost/LightGBM files | measurement (v0.49.0) | [MFS_ROUTING](../REALFILE_CHECK_MFS_ROUTING_2026-11.md) |
| 9 | skops-realfile-v1 | 2026-11-01 | 10/10 | 11 skops.io.dump models | routing change (model-file-scan 0.11.0) | [SKOPS](../REALFILE_CHECK_SKOPS_2026-11.md) |
| 10 | gguf-types-v2 | 2026-11-02 | 10/10 | 16 GGUF from llama.cpp gguf-py | gguf_scan 0.2.0 | [GGUF_TYPES](../REALFILE_CHECK_GGUF_TYPES_2026-11.md) |
| 11 | ovi-realfile-v3 | 2026-11-02 | 14/14 | OpenVINO IR from save_model | measurement | [OVI](../REALFILE_CHECK_OVI_2026-11.md) |
| 12 | gguf-xtool-v1 | 2026-11-03 | 8/8 | 16 GGUF (cross-tool) | measurement | [GGUF_XTOOL](../REALFILE_CHECK_GGUF_XTOOL_2026-11.md) |
| 13 | sti-realfile-v1 | 2026-11-06 | 21/22 | 394 Hub shard indexes | measurement | [STI](../REALFILE_CHECK_STI_2026-11.md) |
| 14 | ovi-u3u6-v1 | 2026-11-06 | 9/10 | 32 honest OpenVINO IR | blocked | [OVI_U3U6](../REALFILE_CHECK_OVI_U3U6_2026-11.md) |
| 15 | sti-variant-fix-v1 | 2026-11-06 | 16/16 | 394 Hub indexes + 38 writer files | **v0.52.0** | [STI_VARIANT_FIX](../REALFILE_CHECK_STI_VARIANT_FIX_2026-11.md) |
| 16 | ovi-u3u6-v2 | 2026-11-06 | 13/13 | 32 honest OpenVINO IR | **v0.52.1** | [OVI_U3U6_V2](../REALFILE_CHECK_OVI_U3U6_V2_2026-11.md) |
| 17 | walk-names-v1 | 2026-11-06 | 13/15 | 7 Hub .pdparams + writer files | blocked | [WALK_NAMES](../REALFILE_CHECK_WALK_NAMES_2026-11.md) |
| 18 | oed-functions-v2 | 2026-11-07 | 13/13 | honest ONNX files | candidate (shipped via #20) | [OED_FUNCTIONS](../REALFILE_CHECK_OED_FUNCTIONS_2026-11.md) |
| 19 | nemo-big-v1 | 2026-11-07 | 12/12 | 2 published .nemo | **v0.53.0** | [NEMO_BIG](../REALFILE_CHECK_NEMO_BIG_2026-11.md) |
| 20 | gate-oed-v1 | 2026-11-07 | 3/3 | (test re-run on combined tree) | **v0.53.1** | [RELEASE_GATE_OED](../REALFILE_CHECK_RELEASE_GATE_OED_2026-11.md) |
| 21 | pkl-memo-v1 | 2026-11-07 | 12/13 | 23 Hub pickles + 8 writer files | blocked | [PKL_MEMO](../REALFILE_CHECK_PKL_MEMO_2026-11.md) |
| 22 | pkl-diag-v1 | 2026-11-07 | 9/9 | 3 Hub joblib files + 4 written | diagnostic | [PKL_DIAG](../REALFILE_CHECK_PKL_DIAG_2026-11.md) |
| 23 | pkl-joblib-v1 | 2026-11-08 | 16/16 | 30 Hub joblib/pkl + 18 written | **v0.54.0** | [PKL_JOBLIB](../REALFILE_CHECK_PKL_JOBLIB_2026-11.md) |
| 24 | walk-names-v2 | 2026-11-09 | 15/15 | 25 Hub .pdparams/.pdopt + 12 written | **v0.55.0** | [WALK_NAMES_V2](../REALFILE_CHECK_WALK_NAMES_V2_2026-11.md) |
| 25 | legacy-torch-v1 | 2026-11-09 | 19/19 | 500 Hub headers, 4 Hub files, 9 written | **v0.56.0** | [LEGACY_TORCH](../REALFILE_CHECK_LEGACY_TORCH_2026-11.md) |
| 26 | nemo-legacy-v1 | 2026-11-09 | 13/14 | 55 Hub .nemo walked (headers only) | **v0.56.0** | [NEMO_LEGACY](../REALFILE_CHECK_NEMO_LEGACY_2026-11.md) |
| 27 | zip-storage-v1 | 2026-11-09 | 9/11 | 6 Hub files + 204 written | measurement | [ZIP_STORAGE](zip-storage/RESULTS_ZIP_STORAGE_2026-11.md) |
| 28 | zip-data-v1 | 2026-11-10 | 15/17 | 21 Hub + 208 written | **v0.57.0** | [ZIP_DATA](../REALFILE_CHECK_ZIP_DATA_2026-11.md) |
| 29 | torchscript-v1 | 2026-11-10 | 10/10 | 5 torch-written files | measurement | [TORCHSCRIPT](../REALFILE_CHECK_TORCHSCRIPT_2026-11.md) |
| 30 | ts-fix-v1 | 2026-11-10 | 9/9 | same 5 files | **v0.58.0** | [TS_FIX](../REALFILE_CHECK_TS_FIX_2026-11.md) |
| 31 | pt2-nest-v1 | 2026-11-11 | 11/12 | 6 torch-written files | **v0.59.0** | [PT2_NEST](../REALFILE_CHECK_PT2_NEST_2026-11.md) |
| 32 | pt2-weights-v1 | 2026-11-11 | 14/14 | 6 torch-written files | **v0.60.0** | [PT2_WEIGHTS](../REALFILE_CHECK_PT2_WEIGHTS_2026-11.md) |
| 33 | pt2-census-v1 | 2026-11-11 | 2/2 (3 untestable) | Hub listings; 7 .ptl | measurement | [PT2_CENSUS](../RESULTS_PT2_CENSUS_2026-11.md) |
| 34 | pte-census-v1 | 2026-11-12 | 7/8 | 450 Hub .pte | measurement | [PTE_CENSUS](../RESULTS_PTE_CENSUS_2026-11.md) |
| 35 | hfcfg-census-v1 | 2026-11-13 | 9/9 | 1,781 Hub config.json | measurement | [HFCFG](RESULTS_HFCFG_CENSUS_2026-11.md) |
| 36 | pte-dtype-v1 | 2026-11-14 | 9/10 | 448 Hub .pte | blocked | [PTE_DTYPE](../REALFILE_CHECK_PTE_DTYPE_2026-11.md) |

"Hub" = public files on Hugging Face, read as bytes and never loaded. A finding on a
published file is not a claim that the model is unsafe.

## Pre-registered, not yet graded

These pre-registrations are public and their jobs are waiting for compute (or, for
PTE005, waiting for the dtype fix to ship first). Each will be added here when graded,
whatever the outcome.

| Pre-registration | Job |
|---|---|
| [PREREG_PTE_DTYPE_FIX_V2](PREREG_PTE_DTYPE_FIX_V2.md) | pte-dtype-v2 |
| [PREREG_PTD_SCAN](PREREG_PTD_SCAN.md) | ptd-scan-v1 |
| [PREREG_TFSM_ROUTE](PREREG_TFSM_ROUTE.md) | tfsm-route-v1 |
| [PREREG_GCT_ROUTE](PREREG_GCT_ROUTE.md) | gct-route-v1 |
| [PREREG_CTR_CALIBRATION](PREREG_CTR_CALIBRATION.md) | ctr-cal-v1 |
| [PREREG_PTE005_EMPTY_SEGMENT](PREREG_PTE005_EMPTY_SEGMENT.md) | pte005-cal-v1 (not filed yet) |

MV2, Munim, Inc., mv2@munimtech.com
