# Pre-registration: skops_scan on files written by skops

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 1 November 2026 (UTC), before the job ran.

`skops_scan.py` 0.1.0 reads the `schema.json` inside a `.skops` archive and
flags the types a file asks you to trust: OS/process/eval modules and
dangerous builtins (SKP001), the `MethodNode` / `OperatorFuncNode` / `operator`
surface (SKP002), any other non-structural type outside a conservative
allow-list (SKP003), and a `.skops` that is not a ZIP (SKP010). Its unit
tests use hand-built schemas. Before `model-file-scan` sends `.skops` files
to it, this check asks two questions. Is it quiet on what skops 0.16.0 really
writes for ordinary scikit-learn models? And does it fire on edited copies?

## Setup

A sealed `python:3.12` container. Setup has network only for
`pip install skops==0.16.0 scikit-learn` and for downloading the v0.49.0
source tarball of keras-model-scan. The run steps have no network. The script
`research/skops-realfile/realfile_check_skops.py` fits small models on 120
rows of seeded random data (60 short seeded texts for the text model) and
writes each with `skops.io.dump`:

| label | model |
|---|---|
| logreg | `LogisticRegression()` |
| random-forest | `RandomForestClassifier(n_estimators=5)` |
| scaler-svc | `make_pipeline(StandardScaler(), SVC())` |
| hist-gb | `HistGradientBoostingClassifier(max_iter=10)` |
| kmeans | `KMeans(n_clusters=3, n_init=2)` |
| tfidf-nb | `make_pipeline(TfidfVectorizer(), MultinomialNB())` |
| columns-onehot | `ColumnTransformer` (StandardScaler + OneHotEncoder) then `LogisticRegression` |
| mlp | `MLPClassifier(hidden_layer_sizes=(8,), max_iter=50)` |
| knn | `KNeighborsClassifier(n_neighbors=3)` |
| ufunc-transformer | `FunctionTransformer(np.log1p)` then `LogisticRegression` |
| partial-transformer | `FunctionTransformer(functools.partial(np.clip, a_min=-1, a_max=1))` then `LogisticRegression` |

It then edits copies of `logreg.skops` (rewriting only `schema.json`) and
scans them. **Edited files are only scanned. None is ever loaded.**

## Predictions

| # | case | prediction |
|---|---|---|
| H1 | the ten honest models above (all but partial-transformer) | no findings and no errors on any file |
| H2 | partial-transformer | exactly {SKP003} (`functools` is outside the allow-list) |
| Q1 | `pickle_model_scan` on every honest archive (the scanner `model-file-scan` would also run on a `.skops`) | nothing at MEDIUM or above |
| K1 | top node `__module__` = `os`, `__class__` = `system` | exactly {SKP001} |
| K2 | top node `__loader__` = `MethodNode` | exactly {SKP002} |
| K3 | top node `__module__` = `mypkg.models` | exactly {SKP003} |
| K4 | top node `builtins.eval` | exactly {SKP001} |
| K5 | `joblib.dump` of the same kind of model saved under a `.skops` name | exactly {SKP010} |
| K6 | `logreg.skops` with `schema.json` removed | no findings, one error |
| U1 | the published `test_skops_scan.py`, run in the same container | all pass |

**Confidence.** H1 is the least certain. skops writes some library-internal
helper types, and any of them from a package outside `numpy`, `scipy`,
`sklearn`, `pandas`, `builtins`, `collections`, `skops`, `xgboost` or
`lightgbm` would be an SKP003. H2 rests on reading skops's documentation, not
its output.

**Reported, not predicted:**
- For every honest file, the list that skops itself returns from
  `skops.io.get_untrusted_types` (it reads the schema without loading). This
  list shows which types skops would make a user confirm, next to what
  `skops_scan` flags. Where skops asks for trust and `skops_scan` is silent,
  that is a difference in purpose, not automatically a miss: `skops_scan`
  allows the whole `sklearn` package by design.
- Every `loader | module.class` pair seen in the honest schemas.
- What the pickle scanner reports on each honest archive.

## Grading

- A prediction holds only if the rule set is exactly the one listed.
- If scikit-learn or skops fails to fit or write a model, the cases that need
  that model are **not run**, never held or failed.
- If the top-level schema object is not a node (no `__class__`,
  `__module__` and `__loader__`), K1-K4 are **not run**.
- The result is reported in full, whatever it is. If H1 fails, the
  `.skops` routing in `model-file-scan` waits until the scanner is fixed and
  re-checked.

## Limits

Small models, one skops release and one scikit-learn release (chosen by
`pip` on the day). This is not a false-positive rate on models published on
the Hugging Face Hub.
