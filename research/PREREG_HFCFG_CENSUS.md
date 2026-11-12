# Pre-registration: job hfcfg-census-v1 (Hugging Face config.json scanners)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0 (code),
CC BY 4.0 (text). Committed before the job runs; results go in
`research/RESULTS_HFCFG_CENSUS_2026-11.md` whatever they show.

## Why

The repository has two standalone scanners for Hugging Face `config.json` files.
`model-file-scan` 0.14.0 (release v0.60.0) never calls either of them: it sends
`config.json` only to `keras_model_scan`.

| module | rules | advisory (checked on osv.dev, 2026-11-12) |
|---|---|---|
| `config_trust_remote_code_scan` 0.1.0 | CTR001 CRITICAL (truthy serialized `trust_remote_code`), CTR002 HIGH (any other value) | CVE-2026-5241 / GHSA-fgcw-684q-jj6r, transformers 5.2.0, LightGlue nested config, CWE-829, CVSS 7.7 |
| `hf_config_injection_scan` 0.1.0 | HCI001/HCI002 HIGH (`_attn_implementation_internal` / `_experts_implementation_internal` present), HCI003 INFO (`auto_map`, `custom_pipeline`, `auto_pipeline`) | CVE-2026-4372 / GHSA-29pf-2h5f-8g72, transformers < 5.3.0, CWE-1066, CVSS 7.8 |

Before routing either module from `model-file-scan`, this job measures how each
behaves on popular, honest configs. Two observations from the source, recorded
before the job runs:

1. `transformers` pops `trust_remote_code` on the `from_pretrained` path, but a
   config built as `SomeConfig(trust_remote_code=True)` keeps it as an attribute,
   and `to_dict` does not strip it. Honest repos can therefore carry the key.
   One public example is `brianling16/relaxed-recursive-transformer`, whose
   config.json has `"auto_map"` and `"trust_remote_code": true`. The advisory
   names only the LightGlue path, yet CTR001 rates every such file CRITICAL with
   that CVE.
2. `config_trust_remote_code_scan`'s header gives CVSS "8.0, AV:L/UI:R". OSV and
   the GHSA give 7.7 (AV:N/AC:H/PR:L/UI:R/S:C). This is a documentation error to
   fix whatever the job shows.

Prior art: arXiv 2601.14163 (Jan 2026) measures how many Hub repos carry custom
code (36,697 of 2,107,935, 1.74%), but it does not count serialized
`trust_remote_code` or kernel-injection keys inside config.json. We found no
public count of either.

## Data

Public Hub API lists, unauthenticated, most-downloaded first. **A** = the top
1,000 models tagged `custom_code`; **B** = the top 1,000 tagged `transformers`.
For each model (deduplicated), only the top-level `config.json` is downloaded
(4 MB cap). Gated, private and missing files are counted, never fetched with
credentials. Nothing is loaded, imported or executed. Ground truth is an
independent stack-based JSON key walk (`census_lib.py`, unit-tested).

## Rows (all fixed before any data is seen)

- **G1** (gate): at least 1,200 distinct parsed configs, with at least 500 in
  A and at least 500 in B. If this fails, every other row is "untestable".
- **E1**: CTR001 + CTR002 count equals the number of `trust_remote_code` keys at
  any depth, on every parseable file, and no parseable file gets CTR000.
- **E2**: HCI001 + HCI002 equals the number of injection keys, HCI003 equals
  the number of `auto_map` / `custom_pipeline` / `auto_pipeline` keys, and no
  parseable file gets HCI000.
- **R1**: `model_file_scan` 0.14.0 routes every file (copied as `config.json`)
  to `["keras"]`, and an `importlib.import_module` spy shows neither module is
  ever imported. Prediction: holds (gap confirmed).
- **K1**: `keras_model_scan`, which sees these files today, reports HIGH or
  CRITICAL on at most 1% of configs.
- **P1**: a `trust_remote_code` key appears in at most 1% of A configs.
- **P2**: a `trust_remote_code` key appears in at most 0.5% of B configs.
- **P3**: of the configs given CTR001, at least 90% have no `lightglue`
  `model_type` anywhere. With no CTR001 hits, P3 is "untestable".
- **P4**: HCI001/HCI002 fire on 0 B configs and on at most 0.5% of A configs.
  This tests the module's claim that transformers never writes these keys.

Flagged files are listed by repository id with neutral wording ("key present").
Popular configs are assumed to be honest. A flag is not an accusation, and no
repository is contacted on the strength of this census.

## Decision rule

- If **G1, E2, R1 and P4** hold, route `hf_config_injection_scan` from
  `model-file-scan` for `config.json` as it is now, in a separately
  pre-registered patch with its own tests.
- If **E1** holds but **P3** holds with at least one CTR001 hit outside
  LightGlue, do not route CTR as it is now. Pre-register a calibration first:
  keep the finding for any serialized `trust_remote_code`, but attach the
  CVE-2026-5241 attribution and HIGH/CRITICAL severity only when the file names
  the advisory's LightGlue path. Everywhere else, report LOW ("caller-only
  loader argument stored in a config file"). Fix the CVSS text in the same
  patch.
- If **K1** fails, the next pre-registered work is `keras_model_scan`'s false
  positives on Hugging Face configs, ahead of either routing change.
- If **E1** or **E2** fails, fix that module before anything else.
