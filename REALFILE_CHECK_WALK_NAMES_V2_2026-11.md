# Real-file check v2: folder walks keep pickle-bearing names (released in v0.55.0)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 9 November 2026 (UTC). Pre-registration:
[research/PREREG_WALK_NAMES_V2.md](research/PREREG_WALK_NAMES_V2.md), committed
before job `walk-names-v2` ran (2026-11-09 10:32 to 10:39 UTC, sealed container,
no network in the run steps). Job code: [research/walk-names-v2/](research/walk-names-v2/).
Raw results: [research/walk-names-v2/results/](research/walk-names-v2/results/).
The first attempt (v1, 13 of 15, not released) is
[REALFILE_CHECK_WALK_NAMES_2026-11.md](REALFILE_CHECK_WALK_NAMES_2026-11.md).

## Result

**15 of 15 graded predictions held. None were skipped. The release rule
(P1, V1, S1, S2, F1, C1, E1) passed, so model-file-scan 0.13.0 ships as
release v0.55.0.**

model-file-scan 0.12.1 (release v0.54.0) scanned a file given by name whatever
its extension, but a **folder** walk kept only files whose last extension was in
its table. Three kinds of honest, pickle-bearing files fell outside it, so a
folder holding only them printed "no model files found" and exited 0:

| Writer | Names | Kept by 0.12.1 walk | Kept by 0.13.0 walk |
|---|---|---|---|
| `torch.save` as in pytorch/examples (zip and legacy format) | `checkpoint.pth.tar`, `model_best.pth.tar` | none (G1) | all 3 files (F1) |
| `paddle.save` (paddlepaddle 3.3.1) | `model.pdparams`, `model.pdopt` | none | both |
| `joblib.dump` (joblib 1.6.0) with a compressor chosen by the name | `.joblib.z/.gz/.bz2/.xz/.lzma/.lz4`, `model.pkl.gz` | none | all 7 |

Every file was written by the real library and re-loaded by it before the scan
(W0: `torch.load(weights_only=True)`, `paddle.load`, `joblib.load`).

The v1 attempt failed only because our pickle scanner raised a false PKL007
HIGH on honest `paddle.save` files; release v0.54.0 fixed that, and this time
the honest paddle files and **25 of 25 published `.pdparams`/`.pdopt` files**
scanned with no finding at all (F3, H3).

## Rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once, second pass no-op, no line lost | held |
| V1 | base mfs 0.12.1 + pms 0.4.0; patched and `pyproject.toml` 0.13.0 | held |
| S1 | whole suite on the patched tree: 0 failures, 0 errors, ran >= 1,390 | held: 1,390 run, 3 skipped |
| S2 | new test module alone: exit 0, exactly 9 tests | held: 9 |
| W0 | torch, paddle, joblib wrote and re-loaded every file | held |
| G1 | 0.12.1 folder walk of each writer folder keeps nothing | held (the gap) |
| F1 | 0.13.0 folder walk keeps exactly the written files | held |
| F2 | 0.13.0 on honest torch and joblib files: nothing at or above MEDIUM, folder exit 0 | held (one PKL006 LOW, see below) |
| F3 | 0.13.0 on honest `paddle.save` files: no HIGH/CRITICAL, no PKL007 | held: no findings |
| C1 | plain `.tar`, `.tar.gz`, `.txt.gz`, `.tar.xz` kept by neither version; 0.13.0 exits 0 | held |
| H1 | at least 1,000 models listed on Hugging Face | held: 1,763 (pytorch 1,000; paddlepaddle 263; sklearn 500) |
| H2 | the name census finds a `.pdparams`/`.pdopt` name | held: 1,476 |
| H3 | 0.13.0 on published files of these names: no HIGH or CRITICAL (n >= 5) | held: n = 25, no finding of any severity |
| H4 | 0.12.1's walk keeps none of the published files; 0.13.0's keeps each | held (25 of 25) |
| E1 | explicit-file scans identical in 0.12.1 and 0.13.0 | held (38 files, no difference) |

## Reported (not graded)

- **Name census.** Among the 1,763 most-downloaded models in the three lists, the
  file listings held 1,476 `.pdparams`/`.pdopt` names but **no** `*.pth.tar` and
  **no** compressed-joblib name. Those two classes are common in training
  folders and example code, not in published Hub repos; the fix is for CI and
  local folder scans, and the Hub sample cannot measure them.
- `model.joblib.lz4`: PKL006 LOW (lz4 is not in the standard library, so the
  file is reported as unscanned rather than read). Exit 0 at the default
  thresholds.
- **Known limit (L1).** joblib also compresses a file named bare `model.gz`.
  0.13.0's walk still skips it on purpose (a bare `.gz` is too broad); given
  explicitly, it is scanned (no findings, exit 0).
- Versions: torch 2.15.0+cpu, paddlepaddle 3.3.1, joblib 1.6.0, numpy 2.5.4,
  lz4 4.4.5. Nine listed models were gated and skipped.

## Limits

One release of each writer, one tiny model per writer. The Hub lists are one
day's most-downloaded models, not a random sample, and only non-gated files of
25 MB or less were scanned (25 paddle files). The scanner read bytes only; no
published file was loaded or unpickled. This check covers our own scanner's
folder walk; it does not compare other tools. No live system was touched.
A clean scan is not a guarantee of safety.
