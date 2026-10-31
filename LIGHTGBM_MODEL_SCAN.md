# lightgbm_model_scan

Static validity checks for **LightGBM** text models (`Booster.save_model`,
usually `model.txt`). Part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan)
toolkit. Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.

```bash
python lightgbm_model_scan.py model.txt
```

It exits `1` on any high finding (so it can gate CI), `2` on a usage error or
an unreadable file, and `0` when clean or only medium findings remain. It uses
**only the Python standard library**. It does not need lightgbm and never
loads a model.

## Why

A LightGBM text model is a header (`max_feature_idx`, `feature_names`,
`tree_sizes` ...) and one `Tree=` block per tree: `num_leaves`, `num_cat`,
`split_feature`, `threshold`, `decision_type`, `left_child`, `right_child`,
`leaf_value` and, for categorical splits, `cat_boundaries` and
`cat_threshold`. A child `>= 0` is a split node; a child `< 0` is leaf
`~child`.

Reading LightGBM's loader (`src/io/tree.cpp`,
`src/boosting/gbdt_model_text.cpp`, `include/LightGBM/tree.h`; 31 October
2026, latest release 4.7.0):

- `Tree::Tree(const char*, size_t*)` checks that required keys exist. It
  reads `left_child`, `right_child`, `split_feature`, `decision_type` and
  `cat_boundaries` with `StringToArrayFast`, which reads exactly
  `num_leaves - 1` (or `num_cat + 1`) values: a missing value becomes 0 and
  extra values are ignored. It does not range-check the values.
- Prediction (`GetLeaf`) follows `left_child`/`right_child` until it reaches
  a negative value, and reads `feature_values[split_feature[node]]`. A
  categorical split reads its category set number from `threshold` and looks
  it up through `cat_boundaries` without a range check.
- With `tree_sizes`, the loader starts each tree at the summed offset without
  comparing it with the length of the text.

These gaps are already public: issues
[#7357](https://github.com/lightgbm-org/LightGBM/issues/7357) and
[#7438](https://github.com/lightgbm-org/LightGBM/issues/7438) report them,
and pull request [#7366](https://github.com/lightgbm-org/LightGBM/pull/7366),
which adds child-index and split-feature validation at load time, was still
open on 31 October 2026. Until a release includes it, and for the checks
outside its scope, a CI gate can refuse a model that LightGBM's own writer
could not have produced. This scanner does that.

## Rules

| rule | severity | CWE | what it means |
|------|----------|-----|---------------|
| LGB001 | high | CWE-125 | An index points outside its tree or array: a child split node `>= num_leaves - 1`, a child leaf `>= num_leaves`, a categorical split's category set outside `0..num_cat-1`, or a `cat_boundaries` entry that is negative or past the end of `cat_threshold`. |
| LGB002 | high | CWE-125 | A split, or a linear leaf (`leaf_features`), reads a feature index the model does not have: negative, or above `max_feature_idx`. |
| LGB003 | high | CWE-835 | A tree loops: walking it from the root reaches one of a node's own ancestors (a child naming the root included), so prediction never reaches a leaf. |
| LGB004 | high | CWE-125 | The loader would read past the end of the text: a `tree_sizes` offset outside the file, or a tree whose text ends without the blank line that closes it. |
| LGB005 | high | CWE-20 | The header or a tree repeats a key. LightGBM's writer never does, so the file was edited after it was saved. The scanner checks the last value. |
| LGB006 | medium | CWE-20 | Model data LightGBM's writer does not produce: an index array with the wrong number of values (checked as the loader reads it: padded with 0 or cut), a tree that is not a binary tree (a split node or leaf that is the child of no node or of two), `decision_type` bits other than categorical/default-left/missing type, a categorical split with `num_cat` 0, `num_cat` above the number of splits, `cat_boundaries` not starting at 0 or going down, `tree_sizes` that point to a tree outside the file's own sequence or list a different number of trees, a tree count that is not whole iterations, `num_leaves` outside 1..131072, more than 22 lines in a tree, or a tree line with no `=`. |
| LGB007 | medium | CWE-693 | Not checked: not a LightGBM text model (a pickle, a JSON dump from `dump_model`, other data), data LightGBM itself refuses (missing required keys, `leaf_value`/`threshold` counts, `feature_names` count), values that are not numbers, or more than 1000 findings. |

Repeats of one kind of problem are reported once with "N in total", and the
evidence names the first tree and node. When `tree_sizes` places a tree
somewhere the file's own sequence of trees does not reach, that tree is
checked too, because it is the one LightGBM would load.

## Prior art and what is new here

promptfoo's ModelAudit has a LightGBM scanner (`lightgbm_scanner.py`, read
31 October 2026). It recognises the text format and searches the text for
command, network, path and encoded-payload strings. As we read it, it does
not parse trees: it does not check child indices, split features, category
sets, `cat_boundaries`, `tree_sizes`, array counts or loops. This module
adds exactly those structural checks, without lightgbm and without loading
anything. It does not repeat ModelAudit's string search. Pickled boosters
belong to a pickle scanner.

## Honest limits

- A clean result means the trees are well-formed by these rules, not that the
  model is safe or does what its card says. Load models only from sources you
  trust.
- The rules come from reading LightGBM's source; no crafted file was loaded in
  LightGBM to see what it does. A finding means the file breaks an invariant
  LightGBM's loader assumes, not that a given LightGBM version misbehaves on
  it.
- Only the text format is checked. `leaf_count`, gains, weights and the
  `parameters:` block are not.
- The unit tests use model text built by hand from the format. A check against
  files written by LightGBM itself is pre-registered in
  [research/PREREG_LGB_REALFILE.md](research/PREREG_LGB_REALFILE.md).

If you spot a mistake, the repo is the place to raise it.
