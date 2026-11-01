# Pre-registration: model-file-scan 0.10.0 routing on XGBoost and LightGBM files

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 1 November 2026 (UTC), before the job ran.

model-file-scan 0.10.0 sends XGBoost and LightGBM models to
`xgboost_model_scan` and `lightgbm_model_scan`. A `.ubj` goes by its
extension. Other files go by content: a `.json` whose top-level object has a
`learner` object; a `.model`/`.bst` starting with `{`; a
`.txt`/`.lgb`/`.lightgbm`/`.model`/`.bst` whose first line is `tree`. Its unit
tests use hand-made bytes. This check uses files the libraries write
themselves.

## Setup

Job `mfs-tree-route-v1` runs in a sealed `python:3.12` container. It has
network only for `pip install xgboost-cpu lightgbm numpy` and to download the
scanner modules from this repository's `main` branch.
`research/mfs_route_check.py` trains one XGBoost model (6 rounds, depth 3) and
one LightGBM model (6 rounds, 7 leaves) on 400 rows of seeded random data. It
saves them as `xgb.json`, `xgb.ubj` and `lgb.txt`, and copies the same bytes to
`xgb-ubj.model`, `xgb-json.bst`, `lgb.lgb` and `lgb-text.model`. In a second
folder it writes a pickle of the XGBoost booster (`xgb-pickled.model`) and a
copy of `xgb.json` with tree 0's root left child set to 99999
(`edited.json`). Nothing is loaded back into XGBoost or LightGBM, and the
pickle is never unpickled.

## Predictions

| # | case | prediction |
|---|---|---|
| R1 | `route_kinds` on the 7 honest files | xgboost for the 4 XGBoost files, lightgbm for the 3 LightGBM files, nothing else |
| R2 | `scan_path` on the 7 honest files | no findings on any file |
| R3 | `route_kinds` on the pickled booster saved as `.model` | pickle (it stays on the pickle scanner); its findings are reported, not predicted |
| R4 | a directory walk of the honest folder | the 6 files other than `xgb-json.bst` (a walk does not pick up `.bst` by design) |
| R5 | `model-file-scan <honest folder> --fail-on medium` | exit 0 |
| R6 | `edited.json` | routed to xgboost only, exactly {XGB001}, exit 1 with `--fail-on high` |
| R7 | `test_model_file_scan.py` with the real scanner modules importable | all pass, none skipped |

## Grading

- A prediction holds only if the result matches exactly.
- If XGBoost or LightGBM fails to train or save, the whole check is **not
  run**, never held or failed.
- The result is reported in full, whatever it is.

## Limits

One small model per library and one release of each, chosen by `pip` on the
day. This tests the routing, not the scanners' false-positive rate on
published models.
