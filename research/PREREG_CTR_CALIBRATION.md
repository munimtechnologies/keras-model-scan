# Pre-registration: job ctr-cal-v1 (config_trust_remote_code_scan 0.2.0)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0 (code),
CC BY 4.0 (text). Committed before the job runs. Results go in
`research/RESULTS_CTR_CALIBRATION_2026-11.md` whatever they show.

## Why

Job hfcfg-census-v1 ([results](RESULTS_HFCFG_CENSUS_2026-11.md)) found 2 of
1,781 popular Hugging Face configs carrying a serialized
`"trust_remote_code": true`, and neither is a LightGlue model.
`config_trust_remote_code_scan` 0.1.0 rates every such key CRITICAL or HIGH and
attributes CVE-2026-5241, an advisory about LightGlue's config path. Under the
census's pre-registered decision rule, CTR is not routed from model-file-scan
until this calibration passes.

## The change (0.1.0 -> 0.2.0, standalone module; model-file-scan untouched)

| rule | when | severity | CVE |
|---|---|---|---|
| CTR001 | truthy value, and a string `model_type` containing `lightglue` (any case) appears anywhere in the file | CRITICAL | CVE-2026-5241 |
| CTR002 | any other value, `lightglue` named as above | HIGH | CVE-2026-5241 |
| CTR003 (new) | key present, `lightglue` not named | LOW | none |
| CTR000 | unreadable or not JSON | ERROR | none |

Every serialized key still gets exactly one finding. The tree walk becomes
iterative instead of recursive. The header's advisory text is corrected to match
the GHSA/OSV record checked on 2026-11-13: CVSS 8.0,
`CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N`, fixed in transformers 5.5.0.
The old header said "AV:L/UI:R" and "fixed just after 5.2.0". The census
pre-registration's "7.7, PR:L" was also a misreading.

## Data

The job draws a fresh sample the same way as hfcfg-census-v1. **A** is the top
1,000 `custom_code` models and **B** is the top 1,000 `transformers` models, both
by downloads from the public Hub API with no authentication. Only each model's
top-level `config.json` is downloaded (4 MB cap). Nothing is loaded, imported or
executed. Gated or missing files are counted, not fetched. The expected rules
come from `expect_lib.py`, which is written from the table above and unit-tested
separately from the module.

## Rows (fixed before any data is seen)

- **T** (precondition): the 0.2.0 unit tests and the library tests pass inside
  the job.
- **G1** (gate): at least 1,200 distinct parsed configs, with at least 500 in A
  and at least 500 in B. If it fails, every other row is "untestable".
- **C1**: on every parsed file, 0.2.0's rules, severities and CVE fields equal
  the spec exactly. No CTR000 and no exception.
- **C2**: on every parsed file, 0.2.0 emits as many CTR findings as 0.1.0 did,
  and that number equals the `trust_remote_code` key count at any depth (no
  finding is lost).
- **P1** (prediction): 0.2.0 gives HIGH/CRITICAL on 0 configs that do not name
  `lightglue`.
- **P2** (replication): the key appears in at most 1% of A and at most 0.5%
  of B.
- **P3** (prediction): `chandar-lab/NeoBERT` and
  `optimum-intel-internal-testing/tiny-random-codegen2`, if they are sampled
  again and still carry the key, get only CTR003 LOW. If neither is, P3 is
  "untestable".

## Decision rule

- If **T, G1, C1 and C2** hold, release `config_trust_remote_code_scan` 0.2.0
  (module, tests, and the docs rows for CTR) as the next free tag. It stays
  standalone. Routing it from model-file-scan is a later, separately
  pre-registered patch.
- If C1 or C2 fails, nothing is released. The mismatches are published and
  the module is fixed first.
- P1 to P3 are reported as measured and do not gate the release.

Flagged repositories are named only as "key present". A flag is not an
accusation, and no repository is contacted because of this job.
