# Pre-registration: folder walks that skip pickle-bearing file names (job walk-names-v2)

Written 2026-11-09, before job `walk-names-v2` runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (text).

## The gap (from reading our own code)

`model-file-scan` 0.12.1 (release v0.54.0) scans a file given by name with the pickle
scanner whatever its extension. When it is given a **folder**, it keeps only files whose
last extension is in `_MODEL_EXTS` (`model_file_scan.py`, `_walk_keeps`). Three kinds of
honest, pickle-bearing files that real libraries write fall outside that list:

| Writer | Name it uses | Source |
|---|---|---|
| `torch.save` in pytorch/examples | `checkpoint.pth.tar`, copied to `model_best.pth.tar` | `imagenet/main.py`, `save_checkpoint()` |
| `paddle.save` | `.pdparams` (Layer state_dict), `.pdopt` (Optimizer state_dict) | Paddle docs |
| `joblib.dump` | `*.z`, `*.gz`, `*.bz2`, `*.xz`, `*.lzma` (and `*.lz4` with lz4 installed): the ending picks the compressor | joblib's `dump` docstring and `numpy_pickle.dump` |

A folder that holds only such files prints "no model files found" and exits 0, so a CI gate
or an agent following our skill would report it as checked when nothing was read.

An earlier version of this check (job walk-names-v1, 2026-11-06, against 0.12.0) held 13
of 15 rows; its two failures were the PKL007 false alarm on honest `paddle.save` files,
which release v0.54.0 has since removed. Its planted-file rows are dropped in v2: every
file in this job is an honest file written by the real library.

## The change (model-file-scan 0.13.0, release v0.55.0 only if the release rows hold)

`_walk_keeps` also keeps names matching
`\.(pt|pth|ckpt)\.tar$`, `\.(pdparams|pdopt)$` and `\.(pkl|pickle|joblib)\.(z|gz|bz2|xz|lzma|lz4)$`
(case-insensitive). Nothing else changes: explicit-file scans, routing and every scanner are
untouched. A bare `model.gz` (which joblib also compresses) is **not** picked up, because a
bare `.gz` is too broad; this is reported as a known limit (observation L1), not hidden.

## Rows (graded by `walk_check.py`; a writer that fails to install makes its rows NOT_RUN)

| Row | Case | Expected |
|---|---|---|
| P1 | patch applies once, second pass no-op, no line lost | ok |
| V1 | versions | base mfs 0.12.1 + pms 0.4.0; patched 0.13.0; pyproject 0.13.0 |
| S1 | full unit-test suite on the patched tree | 0 failures, 0 errors, ran >= 1,390 |
| S2 | new test module alone | exit 0, exactly 9 tests |
| W0 | torch, paddle and joblib wrote every file and re-loaded it with the same library | all ok |
| G1 | 0.12.1 folder walk of each writer folder | keeps nothing (the gap) |
| F1 | 0.13.0 folder walk of each writer folder | keeps exactly the written files |
| F2 | 0.13.0 on the honest torch and joblib files | nothing at or above MEDIUM; folder exit 0 |
| F3 | 0.13.0 on the honest paddle.save files | no HIGH/CRITICAL, no PKL007 (MEDIUM recorded) |
| C1 | plain `.tar`, `.tar.gz`, `.txt.gz`, `.tar.xz` | neither version keeps them; 0.13.0 exits 0 |
| H1 | Hugging Face lists (pytorch 1,000, paddlepaddle 500, sklearn 500 most downloaded) | >= 1,000 models listed |
| H2 | name census: a `.pdparams`/`.pdopt` name among them | >= 1 |
| H3 | 0.13.0 on up to 25 published files per name class (non-gated, <= 25 MB) | no HIGH or CRITICAL (graded if n >= 5) |
| H4 | folder walks of each published file's folder | 0.12.1 keeps none; 0.13.0 keeps each |
| E1 | explicit-file scans of every file, 0.12.1 vs 0.13.0 | identical |

Release rule: release v0.55.0 only if P1, V1, S1, S2, F1, C1 and E1 all pass
(`release_rows_all_pass`); the other rows are reported either way. Observations (not
gated): MEDIUM findings on paddle and published files, the lz4 file's PKL006 LOW, the
bare-`.gz` limit, name counts per class.

Downloads are public, non-gated files only, one request at a time; the scanner reads
bytes and never unpickles or loads them. No live system is touched.

## Also queued: skill smoke test v2 (job mfs-skill-smoke-v2)

The agent skill `skills/model-file-scan/SKILL.md` now pins v0.54.0. Job
`mfs-skill-smoke-v2` follows the skill's own commands on honest files and grades 12 rows:
the 9 rows of v1 (frontmatter, install lines, `model-file-scan 0.12.1`, clean pickle,
clean safetensors, folder walk, JSON schema, exit 2 on a missing path, step 2 run
literally) plus A10 (an honest protocol-4 pickle of two `collections` classes no longer
shows PKL007), A11 (an honest numeric-only `joblib.dump` file scans clean, no PKL007 or
PKL008) and A12 (every PKL rule the skill's table names exists in the installed scanner).
