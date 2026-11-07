<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Pre-registration: why two joblib files keep PKL007, and how much of a joblib file our walk reads (job `pkl-diag-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Written and published 7 November 2026 (UTC), **before** job
`pkl-diag-v1` runs. Scripts: [research/pkl-diag/](pkl-diag/).

## Why

Job `pkl-memo-v1` held 12 of 13 rows. Row H3 failed: `pickle_model_scan`
0.3.0 still reported PKL007 HIGH on two published files,
`classification/churn_model.pkl` and `classification/mobile_model.pkl`
in `OKTAYBBS/DataScientst-models`. See
[REALFILE_CHECK_PKL_MEMO_2026-11.md](../REALFILE_CHECK_PKL_MEMO_2026-11.md).
That write-up gives a hypothesis from reading joblib's source:
`joblib.dump` writes an object-dtype array as a nested pickle with its own
memo, and our walker looks the nested memo fetches up in the outer
stream's memo. The walk then ends at the nested pickle's STOP. This job
checks that hypothesis and measures the coverage it implies.

## Setup (network)

Sealed `python:3.12` container. Installs scikit-learn, pandas and joblib
(newest; versions recorded). Waits up to 120 minutes for
`research/pkl-memo/results/patched/pickle_model_scan.py` (0.3.0) to be on
`main`, then downloads `main`. Downloads three public files from
`OKTAYBBS/DataScientst-models`, pinned to the repo's commit at that time:
churn_model.pkl, mobile_model.pkl, and wine_model.pkl (same folder;
reported only). Cap 45 MB each. Nothing from the Hub is ever loaded or
unpickled.

## Run (no network)

1. `write_joblib.py` fits two small scikit-learn RandomForestClassifier
   models on synthetic data (3 trees, depth 4): one on a pandas DataFrame
   with string labels, one on a numpy array with integer labels. It writes
   J1 `joblib.dump(model_df)`, J2 `joblib.dump(model_np)`, J3
   `joblib.dump(model_df, compress=3)` and J4 `pickle.dump(model_df,
   protocol=5)` (control). Ground truth: these are our own honest files, so
   each is loaded back with `pickle._Unpickler.find_class` wrapped to record
   every import the file makes. joblib's unpickler subclasses it.
2. `diag.py` runs a **trace walker** on every file. It copies 0.3.0's
   `scan_pickle_bytes` rules exactly (same opcode sets, memo and push rules,
   and decompression). For every STACK_GLOBAL it cannot resolve, it also
   records the 14 opcodes before it, where each operand came from, and
   whether it sits after a `PROTO` at position > 0 (a nested pickle) or after
   joblib's raw array bytes. It then runs `pickle_model_scan` 0.2.1 (`main`),
   0.3.0 (the published copy) and `joblib_pickle_scan` (`main`), each in its
   own process.

Each unresolved STACK_GLOBAL gets one class, checked in this order:
`after-array` (after the BUILD that ends a NumpyArrayWrapper whose next
byte is not an opcode), `nested-pickle` (after a PROTO at pos > 0), `memo`
(an operand is a memo fetch of a missing or non-string slot), `other-push`.

## Predictions (graded)

| # | prediction |
|---|---|
| F0 | setup: churn and mobile downloaded; `main` has pickle_model_scan 0.2.1, the published 0.3.0 and joblib_pickle_scan |
| T1 | on churn and mobile, the trace walker's unresolved STACK_GLOBAL positions equal the byte positions of 0.3.0's PKL007 findings (non-empty) |
| D1 | every unresolved STACK_GLOBAL in churn and mobile is class `nested-pickle` |
| W0 | J1 to J4 are written without error, and the ground truth has at least 3 distinct imports for each |
| W1 | J4 (plain pickle): the walk reaches STOP at the last byte, nothing is unresolved, and its distinct imports equal the ground truth's |
| W2 | J1, J2, J3 (`joblib.dump`): the walk ends before the stream's last byte and misses at least one import the ground truth has |
| W3 | 0.3.0 on J4: no PKL007, nothing HIGH or CRITICAL |
| W4 | J2 (numeric arrays only): the walk stops with a parse error, and 0.3.0 reports PKL000 |
| W5 | J1 and J3 (DataFrame model): the walk enters a nested pickle and ends at its STOP before the last byte; 0.3.0 reports no PKL000 but PKL007, all after the nested PROTO |

Reported, not graded: the full traces and contexts; coverage (fraction of
the stream before the walk stopped); what each scanner reports on each
file, including wine_model.pkl; library versions.

## What the result decides

- If T1, D1 and W5 hold, the cause is the nested-pickle memo, and our
  pickle walk silently covers only a prefix of DataFrame-fitted
  `joblib.dump` files. The next fix is a joblib-aware walk: a fresh memo
  for each nested pickle, restoring the outer memo at its STOP, then
  continuing, and skipping raw array bytes by the size the wrapper states.
  It gets its own pre-registered real-file check before any release.
- If D1 fails, the trace contexts show the actual cause and are written up
  first.
- The memo fix (0.3.0) ships only after a new pre-registered check, either
  alone or with the joblib walk.

## Prior art (read 2026-11-07, main branches)

- picklescan's `_list_globals` continues after a STOP into the next
  stream, but it keeps one memo across streams. It has no joblib-specific
  handling.
- promptfoo's ModelAudit `joblib_scanner.py` already skips numeric
  `NumpyArrayWrapper` arrays by their computed size and scans the stitched
  opcode stream. It refuses object-dtype arrays ("Object arrays require
  nested pickle analysis"), and such files end up inconclusive. That fails
  closed. Our 0.2.1/0.3.0 end quietly at the nested STOP, which fails open.
  So the skip for numeric arrays would catch us up with ModelAudit. Walking
  the nested pickle with its own memo would go further than either tool
  as we read them.

## Limits

One file author on the Hub and one release of each library. The ground
truth uses Python's pure-Python unpickler only on files this job wrote
itself. This checks our own scanners. It tests no loader's handling of
unusual input, and it touches no live system beyond public downloads in
setup.
