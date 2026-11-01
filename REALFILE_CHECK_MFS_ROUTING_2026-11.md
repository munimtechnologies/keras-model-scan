# Real-file check: model-file-scan 0.10.0 routing on XGBoost and LightGBM files

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 1 November 2026 (UTC).

**Result: all 7 pre-registered predictions held.**

Pre-registration: [`research/PREREG_MFS_TREE_ROUTING.md`](research/PREREG_MFS_TREE_ROUTING.md)
(committed before the job ran). Script: [`research/mfs_route_check.py`](research/mfs_route_check.py).

## What was checked

model-file-scan 0.10.0 (release v0.49.0) sends XGBoost and LightGBM models to
`xgboost_model_scan` and `lightgbm_model_scan`. Some of that routing depends on
the file's content, not just its extension. Its unit tests use hand-made bytes.
This check used files written by the libraries themselves.

Job `mfs-tree-route-v1` ran on 1 November 2026 in a sealed `python:3.12`
container. It had network access only during setup, to install packages and to
download the scanner modules from this repository's `main` branch. pip chose
**xgboost-cpu 3.4.1, lightgbm 4.7.0 and numpy 2.5.4**. The script trained one
small model with each library on 400 rows of seeded random data. It saved
`xgb.json`, `xgb.ubj` and `lgb.txt`, then copied the same bytes to
`xgb-ubj.model`, `xgb-json.bst`, `lgb.lgb` and `lgb-text.model`. A second
folder held a pickle of the XGBoost booster (`xgb-pickled.model`) and a copy of
`xgb.json` with tree 0's root left child set to 99999 (`edited.json`). Nothing
was loaded back into XGBoost or LightGBM, and the pickle was never unpickled.

## Results

| # | case | predicted | observed | held |
|---|---|---|---|---|
| R1 | `route_kinds` on the 7 honest files | xgboost for the 4 XGBoost files, lightgbm for the 3 LightGBM files, nothing else | exactly that | yes |
| R2 | `scan_path` on the 7 honest files | no findings | no findings on any of the 7 | yes |
| R3 | `route_kinds` on the pickled booster saved as `.model` | pickle | `["pickle"]` | yes |
| R4 | directory walk of the honest folder | the 6 files other than `xgb-json.bst` | those 6 files, none missing | yes |
| R5 | `model-file-scan <honest folder> --fail-on medium` | exit 0 | exit 0, nothing on stderr | yes |
| R6 | `edited.json` | xgboost only, exactly {XGB001}, exit 1 with `--fail-on high` | `["xgboost"]`, {XGB001}, exit 1 | yes |
| R7 | `test_model_file_scan.py` with the real scanner modules importable | all pass, none skipped | 48 run, 0 failures, 0 errors, 0 skipped | yes |

### R3 in more detail (reported, not predicted)

The pre-registration said the pickle scanner's findings on the pickled booster
would be reported, not predicted. The pickle scanner raised **no findings** on
it. That fits a pickle that refers only to XGBoost's own classes. It does not
make pickled boosters safe to accept from strangers. Unpickling any file runs
pickle's import machinery, and a scanner can only judge the opcodes it sees.
For files that cross a trust boundary, prefer XGBoost's own `save_model`
formats (`.json` / `.ubj`): model-file-scan checks their structure without
running any code.

## What this shows, and its limits

- Files written by the real libraries reach the right scanner under every
  extension that was tried, including the ambiguous `.model` and `.bst`.
- Honest files raise nothing, so a CI gate using `--fail-on medium` passes them.
- An edited child index is caught at the routing layer as well as by the
  scanner alone (XGB001).
- Limits: one small model per library and one release of each. This checks
  routing. It does not measure the scanners' false-positive rate on published
  models. `.lightgbm`, LightGBM's binary format and XGBoost's old binary
  format were not tested.

## Reproduce

The script expects the job's layout. It runs from a folder holding
`ship/unified/` (`model_file_scan.py` and `test_model_file_scan.py`) and
`lib/` (the other scanner modules from this repository):

```bash
pip install xgboost-cpu lightgbm numpy
python research/mfs_route_check.py --out out
```

Earlier real-file checks of the two scanners on their own:
[XGBoost, 8 of 8](REALFILE_CHECK_XGB_2026-10.md) and
[LightGBM, 10 of 10](REALFILE_CHECK_LGB_2026-10.md).
