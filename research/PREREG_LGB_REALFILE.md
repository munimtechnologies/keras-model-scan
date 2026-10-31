# Pre-registration: lightgbm_model_scan on files written by LightGBM

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 31 October 2026 (UTC), before the job ran.

`lightgbm_model_scan.py` 0.1.0 was unit-tested on model text built by hand
from the format. This check asks whether it reads models that LightGBM
itself writes the same way.

## Setup

A sealed `python:3.12` container. Network for `pip install lightgbm numpy`
only. The script `research/realfile_check_lgb.py` trains eight small models
on 600 rows of seeded random data (8 boosting rounds, `num_leaves=15`), saves
each with `Booster.save_model` and scans it. It then edits copies of the
`binary` and `categorical` models and scans those. After an edit inside a
tree it rewrites `tree_sizes` the way LightGBM's writer does, so only the
intended change differs. **Edited files are only scanned. None is loaded in
LightGBM.**

| config | parameters |
|---|---|
| binary | `objective=binary` |
| multiclass | `objective=multiclass`, 3 classes |
| categorical | `objective=binary`, feature 0 categorical (10 values), `max_cat_to_onehot=2` |
| linear | `objective=regression`, `linear_tree=True` |
| dart | `objective=binary`, `boosting=dart`, `drop_rate=0.2` |
| rf | `objective=binary`, `boosting=rf`, bagging 0.7 every round, `feature_fraction=0.8` |
| missing | `objective=binary`, 20% NaN in feature 1 |
| from-iteration-2 | as `binary`, saved with `start_iteration=2` |

## Predictions

| # | case | prediction |
|---|---|---|
| P1 | all 8 honest files | no findings on any file |
| P2 | binary, tree 0, `left_child[0]` set to 9999 | exactly {LGB001} |
| P3 | binary, tree 0, `split_feature[0]` set to `max_feature_idx` + 3 | exactly {LGB002} |
| P4 | binary, tree 0, the first child value that names a split node (left_child, then right_child) set to 0, the root | exactly {LGB003} |
| P5 | binary, tree 0, the first `right_child` value that names a leaf set to leaf `num_leaves` (written `-(num_leaves + 1)`) | exactly {LGB001} |
| P6 | categorical, the first categorical split (odd `decision_type`): its `threshold` set to `num_cat` + 5 | exactly {LGB001} |
| P7 | binary, the first `tree_sizes` value set to 10^9 | exactly {LGB004} |
| P8 | binary, a line `max_feature_idx=1` added in front of the real one | exactly {LGB005} |
| P9 | binary, tree 0, the last `left_child` value removed (LightGBM's loader reads a 0, the root, in its place) | exactly {LGB003, LGB006} |
| P10 | the published unit tests, run in the same container | all pass |

The job also reports, over the honest files, how many trees, single-leaf
trees, linear trees and categorical splits there are, which `decision_type`
values occur, and in how many files `tree_sizes` equals the byte length of
each tree block. The scanner's LGB006 rules assume LightGBM always writes
these consistently. The counts are reported, not predicted.

## Grading

- A prediction holds only if the rule set is exactly the one listed.
- If LightGBM's own API fails to train or save a model, the cases that need
  that model are **not run**, never held or failed.
- If a crafted case's precondition is missing (P2, P3, P9: tree 0 has no
  split; P4: tree 0 has one split node; P5: no right child is a leaf; P6: no
  categorical split; P7: fewer than 2 trees), that case is **not run**.
- The result is reported in full, whatever it is.

## Limits

One small file per case and one LightGBM release, chosen by `pip` on the
day. This is not a false-positive rate on published models.
