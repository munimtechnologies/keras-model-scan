<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Pre-registration: pickle_model_scan 0.4.0 walks joblib.dump files to the end (job `pkl-joblib-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0.
Written 8 November 2026 (UTC), before job `pkl-joblib-v1` runs. The job's
setup waits until this file is on `main`. Scripts and the candidate module:
[pkl-joblib/](pkl-joblib/).

## Why

[REALFILE_CHECK_PKL_DIAG_2026-11.md](../REALFILE_CHECK_PKL_DIAG_2026-11.md)
(9 of 9 rows held) showed that on honest `joblib.dump` files from
scikit-learn our pickle walk read only 11.6% to 12.9% of the stream, and
0.004% to 0.03% of three published Hub files. It always missed
`sklearn.tree._tree Tree` and `numpy._core.multiarray scalar`, which come
after the first array. A numeric array stopped the walk with PKL000 LOW (raw
bytes are not opcodes). An object-dtype array is a nested pickle with its
own memo: the walk looked its memo fetches up in the outer memo (a false
PKL007 HIGH) and then ended quietly at the nested `STOP`.

## The change (0.4.0, a coverage fix)

0.4.0 = the memo fix of 0.3.0 (graded 12 of 13 in `pkl-memo-v1`, never
released) plus a walk that reads the stream the way `joblib.load` does
(`joblib/numpy_pickle.py` at joblib 1.6.0, `NumpyArrayWrapper.read_array`):

- In a stream that names `NumpyArrayWrapper`, a symbolic stack (values are
  described, never built) follows the opcodes so the wrapper's state dict is
  known when its `BUILD` comes.
- Numeric array: read the padding-length byte and skip the padding when the
  state has `numpy_array_alignment_bytes` (not None), then skip
  `prod(shape) * itemsize` bytes. The itemsize comes from the pickled dtype:
  its `elsize` when positive (flexible and structured types), else its type
  string (`f8`, `i4`, `M8`; `U<n>` is 4n).
- Object-dtype array (type string `O`, flag bit 1, or an object field):
  walk the nested pickle with a fresh memo, then continue after its `STOP`.
- Size not derivable: **PKL008 MEDIUM** ("the rest of the file was not
  analysed"), never a quiet stop. File ends inside an array: PKL000 LOW.
- joblib's `xz` and `lzma` compressors are now decompressed (stdlib).
- New `pickle_walk(data)`: imports resolved in order, unresolved count, byte
  offset of the outer `STOP`, arrays skipped, nested pickles walked.

Also in the patch: `model_file_scan` and `pyproject.toml` go to 0.12.1; the
one test whose old stream (a memoized string) now resolves uses a memo slot
holding a tuple, as in `pkl-memo-v1`; two new test modules (memo, 11 tests;
joblib, 16 tests); two sections appended to PICKLE_SCAN.md.

## Ground truth and files

Honest files only. Writers (joblib pinned to 1.6.0; scikit-learn, pandas,
scipy, numpy as installed): RandomForest on a DataFrame with string labels
and on a numpy array; a TF-IDF + LogisticRegression pipeline; a
StandardScaler + HistGradientBoosting pipeline; a mixed pandas DataFrame;
a dict of numpy arrays covering float16, complex128, big-endian int32, bool,
unicode, bytes, structured (numeric, and with an object field), object, 0-d,
empty, Fortran order, matrix, datetime64[ms], timedelta64, int8 and a
scipy.sparse CSR matrix. Dumped with `joblib.dump` at defaults; the
DataFrame forest also with compress 3 (zlib), gzip, bz2, xz and lzma, and at
pickle protocols 2 to 5; the array dict also through a file object without
`tell()` (no padding); two plain `pickle.dump` protocol-5 controls. 18 files.

Ground truth = every `(module, name)` that `pickle._Unpickler.find_class`
receives when we load **our own** files back (`joblib.load`; joblib 1.6.0
routes the nested object-array unpickler through the same `find_class`).
Hub files (filter `sklearn`, most downloaded 500, `.joblib`/`.pkl`/`.pickle`,
non-gated, up to 30 files, 40 MB each) and the three OKTAYBBS files from
`pkl-diag-v1` (same commit) are only read as bytes, never loaded.

## Rows (graded exactly as written)

| # | prediction |
|---|---|
| P1 | patch applies once, second pass no-op, nothing lost |
| V1 | before: pms 0.2.1 / mfs 0.12.0; after: pms 0.4.0 / mfs 0.12.1 / pyproject 0.12.1 |
| S1 | whole suite on the patched tree: 0 failures, 0 errors |
| S2 | joblib test module alone: exit 0, 16 tests |
| S3 | memo test module alone: exit 0, 11 tests |
| W0 | all 18 files written; each ground truth has >= 3 distinct imports; every `.joblib` file uses `NumpyArrayWrapper` |
| C1 | on every written file, the 0.4.0 walk's imports equal the ground truth as multisets |
| C2 | on every written file the walk ends at the last byte, 0 unresolved, stack tracking never lost |
| N1 | 0.4.0 through model-file-scan on every written file: no PKL000, PKL007 or PKL008; nothing HIGH or CRITICAL |
| G1 | baseline: on every written `.joblib` file with a numeric array, a plain pickletools walk ends before the last byte |
| H1 | at least 10 Hub files downloaded |
| H2 | 0.4.0: PKL007 on no Hub file; no scan errors |
| H3 | fail-closed: every Hub file whose (decompressed) stream names `NumpyArrayWrapper` is walked to its last byte or carries PKL000/PKL008 |
| H4 | 0.4.0 keeps every 0.2.1 rule except PKL000 and PKL007 on each Hub file |
| H5 | descriptive: at least 90% of those Hub joblib files are walked to their last byte |
| D1 | OKTAYBBS churn/mobile/wine: 0.4.0 gives no PKL007 and walks each to its last byte |

**Release rule:** v0.54.0 ships `pickle_model_scan` 0.4.0 only if every row
except H5 holds. H5 is a census prediction; a miss is reported, not a
blocker. Reported, not graded: the order of imports versus ground truth,
coverage before and after per Hub file, rules 0.4.0 adds on Hub files
(deeper coverage can surface real imports), Hub files with HIGH or CRITICAL,
lz4 files (still unscanned), scan time.

## Limits

One release of each writer, one day's Hub sample (most downloaded, not
random), 40 MB cap. This checks our own scanner's coverage and false
positives on honest files; it tests no loader and no other tool. No crafted
or planted streams are used in this job.
