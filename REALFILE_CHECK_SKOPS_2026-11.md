# Real-file check: skops scanner, November 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`skops_scan.py` 0.1.0 reads the `schema.json` inside a `.skops` archive and
flags the types a file asks you to trust, without loading anything. Its unit
tests use hand-built schemas. This check asked whether it stays quiet on what
skops really writes for ordinary scikit-learn models, and whether it fires on
edited copies. The predictions and grading rules were fixed in advance in
[research/PREREG_SKOPS_REALFILE.md](research/PREREG_SKOPS_REALFILE.md).

**Result: all 10 pre-registered predictions held.**

## Setup

- Job `skops-realfile-v1`, run on 1 November 2026 (UTC) in a sealed
  `python:3.12` container. Network was on only for `pip install` and for the
  keras-model-scan v0.49.0 source tarball; the run steps had none.
- Versions: skops 0.16.0, scikit-learn 1.9.1, numpy 2.5.4, joblib 1.6.0,
  skops_scan 0.1.0, pickle_model_scan 0.2.1.
- Eleven small models fitted on seeded random data, each written with
  `skops.io.dump`. Edited copies of `logreg.skops` (only `schema.json`
  rewritten) were scanned and **never loaded**.
- Script: [research/skops-realfile/realfile_check_skops.py](research/skops-realfile/realfile_check_skops.py).

## Predictions and results

| # | case | predicted | got | held |
|---|---|---|---|---|
| H1 | ten honest models: logreg, random-forest, scaler-svc, hist-gb, kmeans, tfidf-nb, columns-onehot, mlp, knn, ufunc-transformer | no findings, no errors | no findings, no errors on all ten | yes |
| H2 | `FunctionTransformer(functools.partial(np.clip, ...))` | exactly {SKP003} | {SKP003}, type `functools.partial` | yes |
| Q1 | `pickle_model_scan` on every honest archive | nothing at MEDIUM or above | nothing at all on any of the ten | yes |
| K1 | top node `os.system` | exactly {SKP001} | {SKP001} | yes |
| K2 | top node loader `MethodNode` | exactly {SKP002} | {SKP002} | yes |
| K3 | top node module `mypkg.models` | exactly {SKP003} | {SKP003} | yes |
| K4 | top node `builtins.eval` | exactly {SKP001} | {SKP001} | yes |
| K5 | a joblib pickle saved under a `.skops` name | exactly {SKP010} | {SKP010} | yes |
| K6 | `logreg.skops` with `schema.json` removed | no findings, one error | no findings; error "ZIP has no schema.json (not a skops file?)" | yes |
| U1 | published `test_skops_scan.py` in the same container | all pass | 19 of 19 passed | yes |

## What skops asks you to trust vs what the scanner flags

skops has its own check, `skops.io.get_untrusted_types`, which lists the types
a user must confirm before `skops.io.load` will build them. It was run on every
honest file next to `skops_scan` (reported, not predicted):

| model | skops's untrusted list | skops_scan |
|---|---|---|
| logreg, scaler-svc, kmeans, tfidf-nb, columns-onehot, ufunc-transformer | empty | clean |
| random-forest | `sklearn.tree._tree.Tree` | clean |
| hist-gb | `sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor` | clean |
| mlp | `sklearn.neural_network._stochastic_optimizers.AdamOptimizer` | clean |
| knn | `sklearn.metrics._dist_metrics.EuclideanDistance64`, `sklearn.neighbors._kd_tree.KDTree` | clean |
| partial-transformer | `functools.partial`, `numpy.clip` | SKP003 (`functools.partial`) |

The two answer different questions. skops lists every type outside its
built-in trusted set, so ordinary random-forest, gradient-boosting, MLP and
k-NN models already need a manual trust decision. `skops_scan` is a CI gate:
it trusts the `sklearn`, `numpy`, `scipy` and `pandas` packages as a whole and
flags types from anywhere else, plus a short list of dangerous modules and
loaders. On these eleven files the gate raised exactly one finding, on the one
model that pulls in a type from outside those packages.

Loader kinds seen in honest schemas: `DictNode`, `ListNode`, `TupleNode`,
`JsonNode`, `TypeNode`, `NdArrayNode`, `ObjectNode`, `TreeNode`, `LossNode`,
`SliceNode`, `RandomStateNode`, `RandomGeneratorNode`, `FunctionNode` and
`PartialNode`. None of them is `MethodNode` or `OperatorFuncNode`.

## Limits

- Eleven small models, one skops release, one scikit-learn release. This is
  not a false-positive rate on models published on the Hugging Face Hub.
- The allow-list works by package. A `FunctionNode` that names any callable
  in `numpy`, `scipy`, `sklearn` or `pandas` passes without a finding, as
  `numpy.log1p` and `numpy.clip` did here. A narrower rule for function
  references is possible future work and would get its own pre-registered
  check before it ships.
- A finding means the file asks to trust a type the gate does not allow. It
  is not a claim that the file is malicious, and this report makes no
  vulnerability claim about skops.

## What changes

With H1 and Q1 holding, `model-file-scan` 0.11.0 sends `.skops` files to
`skops_scan` and also to the pickle scanner (a `.skops` name must not switch
off the archive and pickle checks). A schema the scanner cannot audit is
reported as SKP099 (medium).
