# xgboost_model_scan

Static validity checks for **XGBoost** model files: `.json`, `.ubj`, and
`.bst`/`.model` files saved as UBJSON (the default since XGBoost 2.0). Part of
the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan)
toolkit. Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.

```bash
python xgboost_model_scan.py model.json model.ubj
```

It exits `1` on any high finding (so it can gate CI), `2` on a usage error or
an unreadable file, and `0` when clean or only medium findings remain. It uses
**only the Python standard library**, including its own decoder for the
UBJSON subset XGBoost writes. It does not need xgboost and never loads a model.

## Why

An XGBoost tree is stored as parallel arrays: `left_children`,
`right_children`, `parents`, `split_indices`, `split_conditions` and others,
plus `categories_*` arrays for categorical splits. Reading XGBoost's loader
(`src/tree/tree_model.cc`, 31 October 2026):

- `LoadModelImpl` checks that each array has `num_nodes` entries, then copies
  every value into the node as written. It does not check that a child, a
  parent or a split's feature index is in range.
- `LoadModel` then reads each node's parent (`self[parent]`) to set up the
  tree. The only check is against the invalid-node marker, so a parent past
  the end is read as given.
- The predictor (`src/predictor/predict_fn.h`) does not follow
  `right_children`. It goes to `LeftChild(nid) + 1` for the right branch.
  [dmlc/xgboost#7903](https://github.com/dmlc/xgboost/issues/7903) reported in
  2022 that a file whose right child is not left + 1 predicts something other
  than what it says, and can read past the tree. That issue was closed by a
  documentation change ([#7918](https://github.com/dmlc/xgboost/pull/7918)),
  and the model tutorial now says: "Only load models from JSON files that were
  produced by XGBoost."
- The UBJSON reader (`src/common/json.cc`) copies a string by the length the
  file declares.

That advice is right, and a CI gate can enforce part of it: refuse a model
whose trees XGBoost's own writer could not have produced. This scanner checks
the structure the loader takes on trust.

## Rules

| rule | severity | CWE | what it means |
|------|----------|-----|---------------|
| XGB001 | high | CWE-125 | An index points outside its tree or array: a left or right child, the right branch at left child + 1, a parent, or a categorical split's range in `categories` (or more `categories_nodes` than `categories_segments`/`categories_sizes` entries). |
| XGB002 | high | CWE-125 | A split reads a feature index the model does not have: negative, or not below `learner_model_param.num_feature`. |
| XGB003 | high | CWE-835 | A tree loops: walking it from the root reaches one of a node's own ancestors. |
| XGB004 | high | CWE-20 | An object repeats a key. XGBoost's writer never does, so the file was edited after it was saved. For UBJSON the scanner checks the first value, which is the one XGBoost's UBJSON reader keeps; for JSON it checks the last. |
| XGB005 | high | CWE-125 | A UBJSON key or string length, or an array count, runs past the end of the file. |
| XGB006 | medium | CWE-20 | Tree data XGBoost's writer does not produce: a stored right child other than left child + 1, a leaf with a right child, a child whose parent entry names another node, a `tree_info` output group the model does not have, `categories_nodes` out of order or range, or a negative category. |
| XGB007 | medium | CWE-693 | Not checked: not an XGBoost JSON/UBJSON model, a legacy binary (`binf`) or pickle file, arrays whose lengths XGBoost itself refuses, multi-target trees (`size_leaf_vector` > 1), nesting deeper than 64 levels, or more than 1000 findings. |

Repeats of one kind of problem are reported once with "N in total", and the
evidence names the first tree and node.

## Prior art and what is new here

promptfoo's ModelAudit has an XGBoost scanner (`xgboost_scanner.py`, read
31 October 2026). For JSON and UBJSON models it checks that `left_children`
and `right_children` are lists of the same length, that each child is
between -1 and the array length, and how deep the trees are. It looks for
code-like strings, and it can optionally load the model in a subprocess. As
we read it, it does not compare `split_indices` with `num_feature`, check the
other arrays' lengths, `parents`, the left + 1 rule or the categorical
ranges, and its depth walk skips a revisited node rather than reporting it.
This module adds exactly those checks, without a UBJSON package and without
loading anything. It does not repeat ModelAudit's code-string search, and it
leaves pickled XGBoost models to a pickle scanner.

## Honest limits

- A clean result means the trees are well-formed by these rules, not that the
  model is safe or does what its card says. Load models only from sources you
  trust, as XGBoost's documentation says.
- Multi-target trees, `gblinear` weights and legacy binary models are not
  checked.
- The rules come from reading XGBoost's source; no crafted file was loaded in
  XGBoost to see what it does. A finding means the file breaks an invariant
  XGBoost's loader assumes, not that a given XGBoost version misbehaves on it.
- The unit tests use models built by hand from the format. A check against
  files written by XGBoost itself is pre-registered in
  [research/PREREG_XGB_REALFILE.md](research/PREREG_XGB_REALFILE.md).

If you spot a mistake, the repo is the place to raise it.
