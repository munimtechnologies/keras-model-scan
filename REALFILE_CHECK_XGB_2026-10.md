# Real-file check: XGBoost model scanner, October 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`xgboost_model_scan.py` was written and unit-tested against models built by
hand. This check asks whether it reads models that XGBoost itself writes the
same way. The predictions and the grading rule were written down before the
job ran, in [research/PREREG_XGB_REALFILE.md](research/PREREG_XGB_REALFILE.md).
A case whose precondition was missing, or that XGBoost's own API could not
build, would have been reported as **not run**. None was.

## Result: all 8 pre-registered predictions held

The job `xgb-realfile-v1` ran in a sealed `python:3.12` container on
1 November 2026 (05:20-05:24 UTC). It had network only for
`pip install xgboost-cpu numpy`, and none while models were trained, saved,
edited and scanned. Edited files were only scanned. None was loaded in XGBoost.

Versions: `xgboost 3.4.1` (the `xgboost-cpu` wheel), `numpy 2.5.4`,
`xgboost_model_scan 0.1.0`.

| # | Case | Prediction | Result | Evidence |
|---|------|-----------|--------|----------|
| P1 | 12 honest files: 6 configs (binary-hist, multiclass, dart, categorical, pruned, exact), each saved as `.json` and `.ubj` | no findings on any file | **PASS** | `[]` on all 12 (9,561 to 21,192 bytes) |
| P2 | binary-hist JSON, tree 0, root `left_children` = 99999 | exactly {XGB001} | **PASS** | `tree 0 node 0: left child 99999, tree has 23 nodes` |
| P3 | binary-hist JSON, tree 0, root `split_indices` = `num_feature` + 3 | exactly {XGB002} | **PASS** | `tree 0 node 0: feature 9, model has 6 features` |
| P4 | binary-hist JSON, tree 0, root `right_children` = left child + 2 | exactly {XGB006} | **PASS** | `node 0: left child 1, right child 3`; `child 3 has parent 1` |
| P5 | binary-hist JSON, tree 0, the root's left child k: `left_children[k]` = 0, `right_children[k]` = 1 | exactly {XGB003, XGB006} | **PASS** | `node 1 leads back to node 0`; `node 1: child 0 has parent 2147483647; 2 in total` |
| P6 | binary-hist UBJ, the first key's 8-byte length = 2^40 | exactly {XGB005} | **PASS** | `key at offset 1 declares 1099511627776 bytes; 12323 remain` |
| P7 | binary-hist UBJ and JSON, a second `version` key in front of the real one | exactly {XGB004} on each | **PASS** (both) | `key version` |
| P8 | the published unit tests, in the same container | all pass | **PASS** | 36 of 36 |

## What XGBoost actually wrote

Rule XGB006 flags a stored right child other than left child + 1, because
XGBoost's predictor goes to left child + 1 whatever the file says
(`src/predictor/predict_fn.h`; dmlc/xgboost#7903). Before calling that a
"writer never does this" rule, the job counted it on the honest files: **in all
387 split nodes across the 12 files, the stored right child was exactly left
child + 1** (0 layouts not read). No recalibration is needed for these six
configurations, including `exact`, a pruned depth-6 model and categorical
splits.

P5's second XGB006 finding is expected: once node 1 points back at the root,
the root's parent entry (XGBoost writes 2147483647, "no parent") no longer
agrees with the child that names it.

## Honest limits

- One small file per configuration (400 rows, 8 rounds), trained by this job,
  not a corpus of published models. This is not a false-positive rate on
  real-world XGBoost models.
- One XGBoost release (3.4.1, CPU wheel), chosen by `pip` on the day. Older
  releases and GPU-trained models were not checked.
- P2-P7 are edited copies of a real file, so they test the scanner's walk over
  XGBoost's real layout, not files XGBoost would write on its own.
- Multi-target trees, `gblinear` boosters and legacy binary models are outside
  the scanner's checks (it says so with XGB007 or not at all for `gblinear`).
- A finding says the file is not something XGBoost's writer produces and
  deserves review before loading. It does not show that loading it is
  exploitable. The node-index class in XGBoost's loader is already public
  (dmlc/xgboost#7903 and XGBoost's own advice to load only JSON models that
  XGBoost produced); this check makes no new vulnerability claim.
- Static review only: no crafted model was loaded or run.

The check script is
[research/realfile_check_xgb.py](research/realfile_check_xgb.py).
