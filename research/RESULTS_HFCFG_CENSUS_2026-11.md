# Results: job hfcfg-census-v1 (Hugging Face config.json scanners)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0 (code),
CC BY 4.0 (text). Pre-registration: [`PREREG_HFCFG_CENSUS.md`](PREREG_HFCFG_CENSUS.md)
(commit 14039f73, 2026-11-12, before the job ran). Raw outputs:
[`hfcfg-census/hfcfg_summary.json`](hfcfg-census/hfcfg_summary.json) and
[`hfcfg-census/hfcfg_flagged.json`](hfcfg-census/hfcfg_flagged.json).

**Outcome: all 9 pre-registered rows held.** No code changed because of this
job. The decision rule now sends two follow-ups (below): one routing patch and
one calibration patch, each pre-registered and tested separately.

## What ran

The job ran in a sealed container on 2026-11-13 from 04:59 to 05:15 UTC, with 1 CPU
and a peak of 0.05 GB of memory. The run steps had no network access. The code under test
was tag v0.60.0: `config_trust_remote_code_scan` 0.1.0 (CTR),
`hf_config_injection_scan` 0.1.0 (HCI), `model_file_scan` 0.14.0 and
`keras_model_scan`. Both modules' own unit tests passed inside the job first.

| | |
|---|---|
| models listed: A = top 1,000 `custom_code`, B = top 1,000 `transformers` (by downloads) | 2,000 (1,924 distinct; 76 in both lists) |
| top-level `config.json` downloaded and parsed | **1,781** (A 949, B 905) |
| not fetched: HTTP 401 (gated) / HTTP 404 (no top-level config.json) / over 4 MB | 62 / 75 / 6 |
| configs with `auto_map`, `custom_pipeline` or `auto_pipeline` | A 939 of 949 (98.9%), B 71 of 905 (7.8%) |

Nothing was loaded, imported or executed from any repository. Gated files were
not retried with credentials.

## Rows

| row | prediction | measured | held |
|---|---|---|---|
| G1 | ≥ 1,200 distinct parsed configs, ≥ 500 in A and in B | 1,781 (A 949, B 905) | yes |
| E1 | CTR001 + CTR002 count = `trust_remote_code` keys at any depth; no CTR000 | 0 mismatches | yes |
| E2 | HCI001 + HCI002 = injection keys; HCI003 = `auto_map`/`custom_pipeline`/`auto_pipeline` keys; no HCI000 | 0 mismatches | yes |
| R1 | `model_file_scan` 0.14.0 routes every `config.json` to `keras` only and never imports CTR or HCI (gap confirmed) | 1,781 of 1,781 routed to `["keras"]`; neither module imported | yes |
| K1 | `keras_model_scan` HIGH/CRITICAL on ≤ 1% of configs | 0 files, 0 findings of any severity | yes |
| P1 | `trust_remote_code` key in ≤ 1% of A | 2 of 949 (0.21%) | yes |
| P2 | `trust_remote_code` key in ≤ 0.5% of B | 0 of 905 | yes |
| P3 | ≥ 90% of CTR001 configs have no `lightglue` `model_type` | 2 of 2 | yes |
| P4 | HCI001/HCI002 on 0 B configs and ≤ 0.5% of A | 0 B, 0 A | yes |

## What it shows

1. **The routing gap is real, and it is the only gap.** model-file-scan sends
   every Hugging Face `config.json` to the Keras config scanner alone. The two
   config scanners that cover CVE-2026-4372 (HCI) and CVE-2026-5241 (CTR) exist
   in the repository but never run from the main CLI. On these 1,781 popular
   configs the Keras scanner produced no findings at all, so routing them
   adds coverage without new Keras noise.
2. **HCI is quiet on honest files.** Neither `_attn_implementation_internal` nor
   `_experts_implementation_internal` appears in any of the 1,781 configs.
   That fits the module's claim that `transformers` never writes these keys.
   HCI003 (INFO) marks every `auto_map`; that is context, not an alarm.
3. **CTR would raise CRITICAL alarms on honest files.** Two popular configs carry a
   serialized `"trust_remote_code": true`, and neither is a LightGlue model:

   | repository | sample | downloads at listing | keys | model_type |
   |---|---|---|---|---|
   | `chandar-lab/NeoBERT` | A #290 | 30,353 | 2 (both `true`) | `neobert` |
   | `optimum-intel-internal-testing/tiny-random-codegen2` | A #675 | 7,173 | 1 (`true`) | `codegen` |

   CTR 0.1.0 rates each key CRITICAL and tags it CVE-2026-5241. That advisory
   concerns LightGlue's config, and these are almost certainly honest
   files written when a config object was built with `trust_remote_code=True`.
   "Key present" is all this census says about them. Neither repository is
   accused of anything, and neither was contacted.
4. **Prevalence.** Among the 949 most-downloaded `custom_code` models with a
   readable top-level config, 0.21% store `trust_remote_code`. Among the 905 most-downloaded
   `transformers` models, none do. We found no earlier public count of either
   key class. arXiv 2601.14163 counts custom-code repositories on the Hub, not
   these keys.

## Correction found while preparing this write-up

The pre-registration said OSV and GHSA give CVE-2026-5241 a CVSS of "7.7
(AV:N/AC:H/PR:L/UI:R/S:C)". That was a misreading. On 2026-11-13 the GHSA page
and OSV's record (`GHSA-fgcw-684q-jj6r`, last modified 2026-09-10) both give
**8.0, `CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N`**, fixed in transformers
**5.5.0**. The module header's score (8.0) is right, but its vector ("AV:L/UI:R")
is wrong, and so is its fix version ("just after 5.2.0"). Both are corrected in the
calibration patch below.

## Decision (applying the pre-registered rule as written)

- **G1, E2, R1 and P4 held**, so `hf_config_injection_scan` is to be routed
  from model-file-scan for `config.json` as it is now, in a separately
  pre-registered patch with its own tests. Three earlier model-file-scan
  patches (.ptd, SavedModel, GGUF chat templates) are still queued for compute.
  To avoid a fourth concurrent change to the same file, this routing patch is
  pre-registered after at least one of them ships.
- **E1 held, and P3 held with two CTR001 hits outside LightGlue**, so CTR is
  **not** routed as it is now. A calibration comes first and is pre-registered
  in [`PREREG_CTR_CALIBRATION.md`](PREREG_CTR_CALIBRATION.md). It keeps a finding
  for every serialized `trust_remote_code`. The CVE-2026-5241 attribution and
  HIGH/CRITICAL severity stay only when the file names LightGlue. Everywhere else
  the finding is LOW ("caller-only loader argument stored in a config file").
  The patch also fixes the CVSS text.
- **K1 held**, so no Keras false-positive work is needed on these configs.
- **E1 and E2 held**, so neither module's key walk needs fixing.

## Limits

These are the most-downloaded models only, so the long tail may differ. Only the top-level
`config.json` was read; nested configs in subfolders were not. 137 listed models
could not be read (gated or no top-level config). The download counts are
from the Hub listing on 2026-11-13 and change daily.
