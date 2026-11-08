<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Real-file check: pickle_model_scan 0.4.0 reads joblib.dump files to the end (job `pkl-joblib-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0.
Graded 8 November 2026 (UTC) against the pre-registration
[research/PREREG_PKL_JOBLIB.md](research/PREREG_PKL_JOBLIB.md), which was on
`main` before the job started (the job checked: `prereg_seen: true`).

**Result: 16 of 16 pre-registered rows held. Per the release rule,
`pickle_model_scan` 0.4.0 ships in v0.54.0 (`model-file-scan` 0.12.1).**

## What was checked

This is a coverage and false-positive check of our own scanner on honest
files. Ground truth = every `(module, name)` that `find_class` received when
`joblib.load` read back **our own** files. Published Hub files were only read
as bytes, never loaded. No crafted or planted streams were used.

Writers: joblib 1.6.0 (pinned), scikit-learn 1.9.1, pandas 3.1.1, numpy
2.5.4, scipy 1.18.1, Python 3.12.15. Hub sample: the 30 readable
`.joblib` / `.pkl` files from the 500 most-downloaded Hugging Face repos with
the `sklearn` tag (40 MB cap; one bigger file skipped), plus the three
OKTAYBBS files from the earlier diagnosis, pinned to the same commit.

## Rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once, second pass no-op, nothing lost | PASS |
| V1 | before pms 0.2.1 / mfs 0.12.0; after pms 0.4.0 / mfs 0.12.1 / pyproject 0.12.1 | PASS |
| S1 | whole suite on the patched tree: 0 failures, 0 errors | PASS (1,381 tests, 3 skipped) |
| S2 | joblib test module alone: exit 0, 16 tests | PASS |
| S3 | memo test module alone: exit 0, 11 tests | PASS |
| W0 | all 18 honest files written; each has >= 3 distinct imports; every `.joblib` uses `NumpyArrayWrapper` | PASS (18 of 18) |
| C1 | 0.4.0 walk imports equal the ground truth (multisets) on every written file | PASS (18 of 18, same order on all 18) |
| C2 | walk ends at the last byte, 0 unresolved, stack tracking never lost | PASS (18 of 18) |
| N1 | through model-file-scan: no PKL000/PKL007/PKL008, nothing HIGH or CRITICAL | PASS (no findings on any of the 18) |
| G1 | baseline: a plain pickletools walk ends before the last byte on every `.joblib` with a numeric array | PASS (16 of 16) |
| H1 | at least 10 Hub files downloaded | PASS (30) |
| H2 | 0.4.0: PKL007 on no Hub file; no scan errors | PASS (0; 0.2.1 had PKL007 on 24 of 30) |
| H3 | fail-closed: every Hub joblib stream walked to its last byte or carries PKL000/PKL008 | PASS (28 of 28 walked to the end) |
| H4 | 0.4.0 keeps every 0.2.1 rule except PKL000 and PKL007 on each Hub file | PASS (nothing lost) |
| H5 | descriptive: >= 90% of Hub joblib files walked to the last byte | PASS (100%, 28 of 28) |
| D1 | OKTAYBBS churn / mobile / wine: no PKL007, walked to the last byte | PASS (3 of 3) |

## Numbers worth knowing

- **How much of a joblib file a plain pickle walk reads.** On the 28
  published files whose stream uses `NumpyArrayWrapper`, a plain
  `pickletools` opcode walk (the way 0.2.1 read them) covered a median of
  **0.4%** of the bytes. 15 of 28 files were read less than 1%; 23 of 28 less
  than half. The lowest was 0.003% (a 22 MB sentiment model). 0.4.0 reads
  all 28 to their last byte.
- **False alarms.** 0.2.1 raised PKL007 HIGH on 24 of the 30 Hub files, on all
  3 OKTAYBBS files, and on 16 of our 18 honest files (the other two, xz and
  lzma, were not decompressed by 0.2.1 and got PKL000 LOW only). 0.4.0 raised it on none.
  PKL000 LOW (the "stopped early" note) also went away on every file.
- **What stayed.** PKL003 MEDIUM (an import outside the known-safe list)
  stayed on the 5 Hub files that had it (per-file rules before and after are in
  `jl_summary.json`).
  0.4.0 added no new rule on any Hub file and reported nothing HIGH or
  CRITICAL on any of them.
- **Compression.** joblib's zlib, gzip, bz2, xz and lzma outputs all walk to
  the end; xz and lzma are new in 0.4.0. lz4 stays PKL006 LOW (unscanned): no
  lz4 file was in this sample.
- **Speed.** The slowest Hub file took 0.44 s (a 2.7 MB file with 6,496
  arrays); the 39 MB churn model walked 801 arrays to the end.

## What changed in 0.4.0

See the "joblib.dump files are walked to the end" and "STACK_GLOBAL operands
from the memo" sections of [PICKLE_SCAN.md](PICKLE_SCAN.md). In short: the
walk skips each numeric array by the size its pickled shape and dtype give,
walks each object-dtype array's nested pickle with its own memo, resolves
`STACK_GLOBAL` operands fetched from the memo, and reports **PKL008 MEDIUM**
when an array cannot be sized, instead of stopping quietly.

## Limits

One release of each writer; one day's Hub sample (most downloaded, not
random); 40 MB cap. This measures our own scanner's coverage and false
positives on honest files. It is not a test of `joblib.load`, of any other
tool, or of resistance to deliberately crafted files. A clean result is not a
guarantee of safety: `joblib.load` still runs code from any file it is given,
so load only files from sources you trust.

Raw results: [research/pkl-joblib/results/](research/pkl-joblib/results/)
(`jl_summary.json` has every row, per-file walk details and the coverage
figures above).
