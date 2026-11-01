# Real-file check: LightGBM model scanner, October 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`lightgbm_model_scan.py` was written and unit-tested against model text built
by hand from the format. This check asks whether it reads models that
LightGBM itself writes the same way. The predictions and the grading rule were
written down before the job ran, in
[research/PREREG_LGB_REALFILE.md](research/PREREG_LGB_REALFILE.md). A case whose
precondition was missing, or that LightGBM's own API could not build, would
have been reported as **not run**. None was.

## Result: all 10 pre-registered predictions held

The job `lgb-realfile-v1` ran in a sealed `python:3.12` container on
1 November 2026 (07:29-07:45 UTC). It had network only for
`pip install lightgbm numpy`, and none while models were trained, saved,
edited and scanned. Edited files were only scanned. None was loaded in
LightGBM. After an edit inside a tree, the script rewrote `tree_sizes` the way
LightGBM's writer does, so only the intended change differed.

Versions: `lightgbm 4.7.0`, `numpy 2.5.4`, `lightgbm_model_scan 0.1.0`.

| # | Case | Prediction | Result | Evidence |
|---|------|-----------|--------|----------|
| P1 | 8 honest files: binary, multiclass, categorical, linear, dart, rf, missing, from-iteration-2 | no findings on any file | **PASS** | `[]` on all 8 (11,576 to 38,013 bytes) |
| P2 | binary, tree 0, `left_child[0]` = 9999 | exactly {LGB001} | **PASS** | `tree 0 node 0: left child 9999, tree has 14 split nodes` |
| P3 | binary, tree 0, `split_feature[0]` = `max_feature_idx` + 3 | exactly {LGB002} | **PASS** | `tree 0 node 0: feature 8, max_feature_idx is 5` |
| P4 | binary, tree 0, the first child value naming a split node set to 0 (the root) | exactly {LGB003} | **PASS** | `tree 0: node 0 leads back to node 0` |
| P5 | binary, tree 0, the first `right_child` naming a leaf set to leaf `num_leaves` | exactly {LGB001} | **PASS** | `tree 0 node 6: right child -16 is leaf 15, tree has 15 leaves` |
| P6 | categorical, the first categorical split's `threshold` = `num_cat` + 5 | exactly {LGB001} | **PASS** | `tree 0 node 1: set 7, num_cat is 2` |
| P7 | binary, the first `tree_sizes` value = 10^9 | exactly {LGB004} | **PASS** | `tree 1 at byte 1000000497 of 16691; 7 in total` |
| P8 | binary, a line `max_feature_idx=1` in front of the real one | exactly {LGB005} | **PASS** | `key max_feature_idx` |
| P9 | binary, tree 0, the last `left_child` value removed | exactly {LGB003, LGB006} | **PASS** | `left_child has 13 values, LightGBM reads 14`; `node 13 leads back to node 0` |
| P10 | the published unit tests, in the same container | all pass | **PASS** | 35 of 35 |

P7's "7 in total": once the first size is 10^9, every later tree's computed
offset is past the end of the file too, so the eight-tree model gives one
finding for trees 1-7. P9 shows the padding the scanner emulates: LightGBM's
fast array reader fills a missing value with 0, so the shortened `left_child`
makes node 13 point back at the root.

## What LightGBM actually wrote

The scanner's medium rule LGB006 assumes LightGBM writes its arrays, decision
types and `tree_sizes` consistently. The job counted, over the 8 honest files:

| Count | Value |
|---|---|
| trees | 78 (consistent with 8 per file, 24 for the 3-class model and 6 for the one saved from iteration 2) |
| single-leaf trees | 0 |
| linear trees | 8 (all in the `linear` model) |
| categorical splits | 16 |
| files where every `tree_sizes` value equals the byte length of its tree block | 8 of 8 |
| `decision_type` values seen | 2 (916 splits), 10 (28), 8 (14), 1 (16) |

Read with LightGBM's bit layout (bit 0 categorical, bit 1 default-left, bits
2-3 the missing-value type): 2 is a numerical split defaulting left with no
missing type; 8 and 10 are numerical splits with NaN as the missing type (10
also defaults left); 1 is a categorical split. No other bits occurred, which
supports LGB006's "bits the writer does not set" check. The job did not record
which file each value came from. The model saved with `start_iteration=2` had
no findings and its `tree_sizes` matched its blocks, so a partial save does
not trip the scanner.

## Honest limits

- One small file per configuration (600 rows, 8 rounds, `num_leaves=15`),
  trained by this job, not a corpus of published models. This is not a
  false-positive rate on real-world LightGBM models.
- One LightGBM release (4.7.0), chosen by `pip` on the day. Older releases and
  models saved by the R or CLI packages were not checked.
- No single-leaf trees occurred, so that branch of the scanner was covered by
  the unit tests only.
- P2-P9 are edited copies of real files, so they test the scanner's walk over
  LightGBM's real layout, not files LightGBM would write on its own.
- A finding says the file is not something LightGBM's writer produces and
  deserves review before loading. It does not show that loading it is
  exploitable. The child-index and out-of-range classes in LightGBM's text
  loader are already reported in public by others (lightgbm-org/LightGBM
  issues #7357 and #7438, with a structure-validation fix proposed in PR
  #7366); this check makes no new vulnerability claim.
- Static review only: no crafted model was loaded or run.

The check script is
[research/realfile_check_lgb.py](research/realfile_check_lgb.py).
