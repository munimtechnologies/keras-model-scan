<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Real-file check graded: how much of a joblib file our pickle walk reads (job `pkl-diag-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Pre-registration: [research/PREREG_PKL_DIAG.md](research/PREREG_PKL_DIAG.md)
(published 7 November 2026, before the job ran). Scripts: [research/pkl-diag/](research/pkl-diag/).
Raw results: [research/pkl-diag/results/diag_summary.json](research/pkl-diag/results/diag_summary.json).

## Result: 9 of 9 pre-registered predictions held

The job ran on 7 November 2026, 21:12-21:16 UTC, in a sealed `python:3.12`
container (no network in the run steps). The writers were joblib 1.6.0,
numpy 2.5.4, pandas 3.1.1, scikit-learn 1.9.1 and Python 3.12.15. Nothing
from the Hub was loaded or unpickled. Ground truth comes only from files the
job wrote itself.

| # | prediction | result |
|---|---|---|
| F0 | setup: the three Hub files download; `main` has pickle_model_scan 0.2.1, the published 0.3.0 and joblib_pickle_scan 0.1.0 | PASS |
| T1 | on churn and mobile, the trace walker's unresolved STACK_GLOBAL positions match 0.3.0's PKL007 positions (985 and 975) | PASS |
| D1 | every unresolved STACK_GLOBAL in churn and mobile is inside a nested pickle (after a PROTO at pos > 0) | PASS (wine_model.pkl too) |
| W0 | J1 to J4 are written; the ground truth has at least 3 distinct imports each (8, 7, 8, 8) | PASS |
| W1 | J4 (plain `pickle.dump`, protocol 5): the walk reaches STOP at the last byte, and its imports equal the ground truth | PASS (coverage 1.0) |
| W2 | J1, J2, J3 (`joblib.dump`): the walk ends early and misses real imports | PASS |
| W3 | 0.3.0 on J4: no PKL007, nothing HIGH | PASS |
| W4 | J2 (numeric arrays only): the walk stops with a parse error at joblib's padding byte, and 0.3.0 reports PKL000 LOW | PASS |
| W5 | J1 and J3 (fitted on a DataFrame): the walk enters a nested pickle and ends quietly at its STOP; 0.3.0 reports PKL007, all after the nested PROTO | PASS |

## What this means

`joblib.dump` does not write one plain pickle. After each `NumpyArrayWrapper`
it writes the array data straight into the file:

- **A numeric array** is written as a padding-length byte, padding, then the
  raw bytes. A plain pickle walk can't parse that, so it stops: 0.3.0 reports
  PKL000 LOW at the first array.
- **An object-dtype array** (for example `feature_names_in_` when a model is
  fitted on a pandas DataFrame) is written as a **nested pickle with its own
  memo**. Our walk looks up the nested memo fetches in the outer stream's
  memo, so it reports a false PKL007 HIGH there. It then ends at the nested
  STOP without any parse error, so the rest of the file goes unread.

Coverage on honest files (share of the stream read before the walk stopped):

| file | coverage | imports seen / real |
|---|---|---|
| J1 joblib, DataFrame model | 12.9% | 6 / 8 |
| J2 joblib, numpy model | 11.6% | 5 / 7 |
| J3 joblib, compress=3 | 12.9% (of the inflated stream) | 6 / 8 |
| J4 plain pickle (control) | 100% | 8 / 8 |
| churn_model.pkl (Hub, 39 MB) | 0.0044% | 6 seen |
| mobile_model.pkl (Hub, 4.4 MB) | 0.026% | 6 seen |
| wine_model.pkl (Hub, 21.6 MB) | 0.0055% | 6 seen |

Every joblib file missed `sklearn.tree._tree Tree` and
`numpy._core.multiarray scalar`. On these files, a "clean" or "PKL000 LOW"
result from pickle_model_scan 0.2.1/0.3.0 covered only the start of the file.
`joblib_pickle_scan` 0.1.0 also ends quietly at the first stop, so it reported
nothing on any of these files except JLB010 on J3. That is a coverage gap in
our own tools, and this check measured it.

## What comes next (not released yet)

A joblib-aware walk that reads the stream the way `joblib.load` does: arrays
skipped by the size their wrapper states, each nested pickle walked with a
fresh memo, and the walk carried on to the final STOP. When the size can't be
worked out, it reports that instead of stopping quietly. It gets its own
pre-registered check before release. The pass mark is coverage against the
ground truth: on honest files from several joblib, protocol and compression
settings, the walk must see every import joblib really makes, and false
PKL007 must be gone. The memo fix (0.3.0) is still unreleased and will ship
together with it.

Prior art (read 7 November 2026): promptfoo's ModelAudit already skips
numeric joblib arrays by their computed size. It refuses object-dtype arrays
and calls the file inconclusive, which fails closed. picklescan carries on
after a STOP but keeps one memo across streams.

## Limits

One Hub author (three files) and one release of each library. This checks our
own scanners on honest files. It tests no loader's handling of unusual input,
and it touched no live system beyond public downloads during setup.
