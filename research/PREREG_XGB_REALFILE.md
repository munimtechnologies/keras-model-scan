# Pre-registration: xgboost_model_scan on files written by XGBoost

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 31 October 2026 (UTC), before the job ran.

`xgboost_model_scan.py` 0.1.0 was unit-tested on models built by hand. This
check asks whether it reads models that XGBoost itself writes the same way.

## Setup

A sealed `python:3.12` container. Network for `pip install xgboost-cpu numpy`
only. The script `research/realfile_check_xgb.py` trains six small models on
400 rows of seeded random data (8 boosting rounds each), saves each as
`.json` and `.ubj`, and scans them. It then edits copies of the first model's
files and scans those. **Edited files are only scanned. None is loaded in
XGBoost.**

| config | parameters |
|---|---|
| binary-hist | `binary:logistic`, `hist`, depth 4 |
| multiclass | `multi:softprob`, 3 classes, `hist`, depth 3 |
| dart | `binary:logistic`, `booster=dart`, `rate_drop=0.1`, depth 3 |
| categorical | `binary:logistic`, `hist`, one categorical feature, `max_cat_to_onehot=1`, depth 3 |
| pruned | `binary:logistic`, `hist`, depth 6, `gamma=2` |
| exact | `binary:logistic`, `tree_method=exact`, depth 4 |

## Predictions

| # | case | prediction |
|---|---|---|
| P1 | all 12 honest files (6 configs x `.json`/`.ubj`) | no findings on any file |
| P2 | binary-hist JSON, tree 0, root `left_children` set to 99999 | exactly {XGB001} |
| P3 | binary-hist JSON, tree 0, root `split_indices` set to `num_feature` + 3 | exactly {XGB002} |
| P4 | binary-hist JSON, tree 0, root `right_children` set to left child + 2 | exactly {XGB006} |
| P5 | binary-hist JSON, tree 0, node k = the root's left child: `left_children[k]` = 0 and `right_children[k]` = 1 | exactly {XGB003, XGB006} |
| P6 | binary-hist UBJ, the first key's 8-byte length set to 2^40 | exactly {XGB005} |
| P7 | binary-hist UBJ and JSON, a second `version` key added in front of the real one | exactly {XGB004} on each |
| P8 | the published unit tests, run in the same container | all pass |

The job also counts, over every split node in the 12 honest files, how often
the stored right child equals left child + 1. Rule XGB006 assumes that XGBoost
always writes it that way. The count is reported, not predicted.

## Grading

- A prediction holds only if the rule set is exactly the one listed.
- If XGBoost's own API fails to train or save a model, the cases that need
  that model are **not run**, never held or failed.
- If a crafted case's precondition is missing (P4: left child + 2 is not a
  node; P5: node k is a leaf; P7: the JSON does not start with
  `{"learner"`), that case is **not run**.
- The result is reported in full, whatever it is.

## Limits

One small file per case and one XGBoost release, chosen by `pip` on the day.
This is not a false-positive rate on published models.
