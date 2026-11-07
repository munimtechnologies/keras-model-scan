<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Real-file check graded: STACK_GLOBAL operands from the pickle memo, 12 of 13 held, not released (job `pkl-memo-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0.
Graded 7 November 2026 (UTC). Pre-registration:
[research/PREREG_PKL_MEMO.md](research/PREREG_PKL_MEMO.md), committed before
the job ran (2026-11-07 08:27 to 08:33 UTC, sealed `python:3.12`
container, no network in the run steps). Raw results:
[research/pkl-memo/results/](research/pkl-memo/results/).

## Result

**12 of 13 graded rows held. Row H3 failed, so as pre-registered there is
no release.** `pickle_model_scan` stays 0.2.1 and `model-file-scan` stays
0.12.0 on `main`. The scanner the job patched (0.3.0) is kept for the
record at
[research/pkl-memo/results/patched/pickle_model_scan.py](research/pkl-memo/results/patched/pickle_model_scan.py).
It is not live.

The fix did what it was meant to do. On 0.2.1, **20 of the 23** published
pickle files the job downloaded got PKL007 HIGH ("unresolved STACK_GLOBAL
operands"). 0.3.0 cleared **18** of them, plus every honest file that torch,
paddlepaddle, numpy and Python's own pickler wrote. It still caught every
planted stream, and it now classifies a memoized `os`/`system` import as
PKL001 CRITICAL rather than only PKL007. But two published files kept
PKL007 under 0.3.0, and the pre-registered prediction said none would.

## Rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once, second pass no-op, nothing lost | held |
| V1 | 0.2.1 / 0.12.0 before; 0.3.0 / 0.12.1 / pyproject 0.12.1 after | held |
| S1 | whole suite on the patched tree: 0 failures, 0 errors | held: 1,349 run, 0 failures, 3 skipped |
| S2 | new test module alone: exit 0, at least 10 tests | held: 11 tests |
| G1 | 0.2.1 gives PKL007 HIGH on paddle `.pdparams`/`.pdopt` and both collections pickles | held |
| N1 | 0.3.0 on all 8 honest written files: no PKL007, nothing HIGH or CRITICAL | held (all 8 clean) |
| N2 | 0.3.0 on the collections pickles: nothing above LOW | held |
| F1 | 0.3.0 on planted streams: Fa/Fb/Fc PKL007 HIGH; Fd/Fe PKL001 CRITICAL | held |
| F2 | 0.2.1: Fd PKL007 without PKL001; Fc nothing above LOW | held |
| H1 | at least 10 published files downloaded | held: 23 |
| H2 | 0.2.1 gives PKL007 on at least 5 of them | held: 20 |
| **H3** | **0.3.0 gives PKL007 on none of them, no scan error** | **failed: 2 files, 0 scan errors** |
| H4 | 0.3.0 keeps every 0.2.1 rule except PKL007 on each published file | held |

The two H3 files are `classification/churn_model.pkl` and
`classification/mobile_model.pkl` in the Hugging Face repo
`OKTAYBBS/DataScientst-models`. Its README loads them with `joblib.load`.

Writer versions: torch 2.15.0+cpu, paddlepaddle 3.3.1, numpy 2.5.4.
Reported, not graded: the model-file-scan CLI exit on 5 honest written files
went from 1 (0.2.1) to 0 (0.3.0). 34 Hub files over the 40 MB cap were
skipped, and one gated repo was skipped.

## Why H3 failed: a hypothesis, tested next

We have not seen inside the two files yet. The job kept only scan results,
not opcode traces. Reading joblib's source (`joblib/numpy_pickle.py`, main,
read 2026-11-07) suggests a cause that is **not** the memo bug this fix
addresses:

- `joblib.dump` writes every numpy array as a `NumpyArrayWrapper` object
  followed by the array itself, *inside* the pickle stream.
- A numeric array is written as raw bytes after a padding byte. An opcode
  walker cannot parse those, so `pickletools` stops there. Our scanner
  says so with PKL000 LOW, which is what 2 other published files got.
- An object-dtype array (for example the `feature_names_in_` of a model
  fitted on a pandas DataFrame) is written as a **separate, nested pickle**
  (`pickle.dump(array, protocol=5)`). That pickle has its own memo, numbered
  from 0. Our walker keeps one memo for the whole file. So the nested
  pickle's memo fetches look up the outer stream's slots, find no string,
  and 0.3.0 reports PKL007. Then the walk ends at the nested pickle's STOP,
  **with no error and no finding about the rest of the file**.

If this is right, the bigger problem is coverage, not the false alarm: for
`joblib.dump` files our pickle scanners read only the stream up to the
first array. picklescan continues after a STOP into the next stream, but it
also keeps one memo across streams and has no joblib-specific handling
(`scanner.py`, main, read 2026-11-07).

Job `pkl-diag-v1`, pre-registered in
[research/PREREG_PKL_DIAG.md](research/PREREG_PKL_DIAG.md), traces both
files opcode by opcode. It also writes honest `joblib.dump` files with
scikit-learn and records the imports each one really makes, to measure how
much of such a file our walk covers.

## What happens next

The memo fix stays correct for plain pickles (N1, N2 and 18 of the 20 Hub
files). Whether it ships alone, or together with a joblib-aware walk (a
fresh memo per nested pickle, continuing past the nested STOP, skipping the
raw array bytes), depends on what `pkl-diag-v1` finds. Either way it gets a
new pre-registered check first, because a pre-registered row failed.

## Limits

One release of each writer. Hub files are from the most downloaded models
on one day, not a random sample, and capped at 40 MB. This checks our own
scanner. It tests no loader, and nothing was unpickled.
