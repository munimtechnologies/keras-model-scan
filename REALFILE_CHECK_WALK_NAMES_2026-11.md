# Real-file check: pickle-bearing names that directory walks skip (graded, not released)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 6 November 2026 (UTC). Pre-registration:
[research/PREREG_WALK_NAMES.md](research/PREREG_WALK_NAMES.md), committed
before job `walk-names-v1` ran (2026-11-06 18:59 to 19:09 UTC). Raw results:
[research/walk-names/results/walk_summary.json](research/walk-names/results/walk_summary.json).

## Result

**13 of 15 graded predictions held. None were skipped. F3 and H3 failed,
so nothing is released.**

Everything about the walk fix itself held. model-file-scan 0.12.0's folder
walk skipped `checkpoint.pth.tar`, `model_best.pth.tar`, `.pdparams` and
`.pdopt` (G1, and G2 exit 0 with "no model files found" on every planted
folder). The proposed 0.13.0 keeps exactly those files (F1), catches the
planted pickle in each folder (F2: exit 1, PKL001 CRITICAL), and still
skips a plain `data.tar` and `logs.tar.gz` (C1). The full suite passed:
1,328 tests, 0 failures, 3 skipped.

The two failures have one cause, and it is in a different scanner of ours.
`pickle_model_scan` 0.2.1 reports **PKL007 HIGH** ("unresolved STACK_GLOBAL
operands") on honest `paddle.save` output:

- F3 (honest writer files: nothing above LOW, folder exit 0) failed only on
  paddle. `model.pdparams` and `model.pdopt` from paddlepaddle 3.3.1 each got
  PKL007 HIGH, and the folder scan exited 1. Both torch checkpoints
  (`.pth.tar`, zip and legacy format) were clean.
- H3 (published files: no HIGH or CRITICAL) failed on 6 of 7 downloaded
  `.pdparams` files, all PKL007 HIGH: `PaddleCI/tiny-random-bert`,
  `PaddleCI/tiny-random-plato-mini`, `PaddleCI/tiny-random-unimo-text-1.0`,
  `sijunhe/test_unet1d`, `sijunhe/ci-test-ernie-model-test` and
  `Kellenok/PP-OCRv6_manga` (`det/manga_det_v0.3.pdparams`).

`route()` and the pickle scanner are the same in 0.12.0 and 0.13.0 (R0). So
a `.pdparams` file given by name gets the same false alarm in the released
0.12.0. The walk fix would have spread it to every folder scan of a paddle
project, which is why the release rule stopped it.

## Why PKL007 fired

`paddle.save` writes a pickle at protocol 4. At protocols 4 and 5, Python's
pickler writes each import as two memoized strings and `STACK_GLOBAL`. A
module name that comes up again (for example `numpy` for `ndarray`, then
`dtype`) is fetched from the memo (`BINGET`), not written twice. 0.2.1
treats any memo fetch as an operand it cannot resolve. That is right for
the picklescan bypass shape it was written for (GHSA-9gvj-pp9x-gcfr), but
it is wrong for a memoized string, which can be resolved exactly.

The fix is pre-registered:
[research/PREREG_PKL_MEMO.md](research/PREREG_PKL_MEMO.md) (job
`pkl-memo-v1`). It resolves operands from the memo the way the unpickler
fills it and keeps PKL007 for everything else. The walk fix is re-run on top
of it afterwards.

## Rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once, second pass no-op, nothing lost | held |
| V1 | original 0.12.0; patched module and `pyproject.toml` 0.13.0 | held |
| S1 | whole suite passes on the patched tree | held: 1,328 run, 0 failures, 0 errors, 3 skipped |
| S2 | new test module alone: exit 0, at least 9 tests | held: 9 |
| R0 | `route()` of every written and planted name is `pickle` in both versions | held |
| G1 | 0.12.0's walk of each writer folder keeps nothing | held |
| G2 | 0.12.0's CLI exits 0, "no model files found", on each planted folder | held |
| F1 | 0.13.0's walk keeps exactly the written files | held |
| F2 | 0.13.0's CLI exits 1 on each planted folder, PKL001 in the planted file | held (4 of 4, PKL001 CRITICAL) |
| F3 | 0.13.0 on honest writer files: nothing above LOW; folder exit 0 | **failed**: paddle `model.pdparams` and `model.pdopt` PKL007 HIGH, folder exit 1; torch folders clean |
| C1 | `data.tar` / `logs.tar.gz` kept by neither; 0.13.0 exits 0 | held |
| H1 | at least 100 models listed | held: 1,261 (pytorch 1,000; paddlepaddle 261) |
| H2 | the name census finds a `.pdparams` file | held: 1,427 `.pdparams`, 48 `.pdopt` |
| H3 | published files: no HIGH or CRITICAL from 0.13.0 | **failed**: 6 of 7 PKL007 HIGH |
| H4 | 0.12.0's walk keeps none of them; 0.13.0's keeps each | held (7 of 7) |

## Reported (not graded)

- Versions: torch 2.15.0+cpu, paddlepaddle 3.3.1, numpy 2.5.4.
- PyTorch Mobile `model.ptl`: PKL003 MEDIUM (an import outside the
  allowlist). `torch.export` `model.pt2`: PKL000 LOW (a stream that did not
  fully parse). Both are input for a later routing audit, not part of this
  fix.
- Downloads: 7 published files fit the 25 MB cap. 23 were larger and one
  model was gated.
- File extensions in the census that the 0.13.0 walk still skips by name
  include `.pdstate` (120), `.states` (71), `.mnn` (69), `.pdiparams` (59),
  `.ot` (51) and `.nb` (49). That list is input for the next audit, not a
  finding.

## Limits

One tiny model and one release of each writer. The Hub lists are the most
downloaded models on one day, not a random sample, and only files of 25 MB
or less were scanned. This check covers our own scanner. It tests no loader
and touched no live system beyond public downloads in setup.
