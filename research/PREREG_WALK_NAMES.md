# Pre-registration: pickle-bearing names that directory walks skip (walk-names-v1)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 6 November 2026 (UTC), before job `walk-names-v1` ran. Scripts:
[research/walk-names/](walk-names/). The new test module is committed only
together with the fix, so it never runs against unpatched code.

## Why

This is the next step of our own-table audit, after the variant shard-index
names fixed in v0.52.0. It asks which file names do real writers give to
files that carry a pickle, where model-file-scan's directory walk does not
look?

From model-file-scan 0.12.0's source, `_walk_keeps` keeps a file when its
last extension is in `_MODEL_EXTS`, it is `config.json` or a shard index, or
it is one of the content-checked `.xml`, `.json` or `.txt` cases. Two
documented writer outputs fall outside that:

- **`checkpoint.pth.tar` / `model_best.pth.tar`.** pytorch/examples
  (`imagenet/main.py`, `save_checkpoint`) writes `torch.save` checkpoints
  under these names. The last extension is `.tar`, so the walk skips them.
- **`.pdparams` / `.pdopt`.** `paddle.save` writes a Layer or Optimizer
  `state_dict` as a plain pickle (protocol 4 by default), and Paddle's
  documentation recommends these suffixes.

A file given by name already goes to the pickle scanner, because `route()`
falls back to `pickle` and that scanner identifies files by content. The gap
is only in folder scans, which is how CI uses the tool. A planted pickle
named `model.pdparams` in a scanned folder is never read.

## The fix (patch_walk.py, applied to live `main` inside the job)

- `model_file_scan.py` gets a helper `_is_pickle_name(name)` matching
  `\.(?:pt|pth|ckpt)\.tar$|\.(?:pdparams|pdopt)$` without regard to case.
  `_walk_keeps` also keeps those names. A plain `data.tar` or `logs.tar.gz`
  is still skipped. `route()` is unchanged.
- Versions: model-file-scan 0.13.0 (module and `pyproject.toml`), and the
  floor in `test_attribution.py`.
- Docs (optional, reported): the `MODEL_FILE_SCAN.md` heading, the
  "everything else" row and the Action pin.
- New stdlib test module `test_model_file_scan_walk_names.py` (9 tests).
- Each edit must apply exactly once, a second pass must change nothing, and
  no line may be lost except the replaced ones. Otherwise nothing is
  written.
- The setup step waits, for up to 60 minutes, for v0.52.0 (model-file-scan
  0.12.0) to be on `main`, because the patch is written against it.

## Setup

A sealed `python:3.12` container. Setup has network. It downloads live `main`
and installs CPU torch, paddlepaddle and numpy (the newest releases; versions
are recorded). It also lists the most downloaded Hub models tagged `pytorch`
(1,000) and `paddlepaddle` (500), with their file names. It downloads at most
30 published files whose names match the new pattern (non-gated, at most 2
per model, 25 MB each, each in its own folder). The run steps have no
network. Nothing is ever loaded or unpickled: the scanner only disassembles
bytes.

Writers, each in a child process, use a seeded tiny MLP:
`tv_pth_tar` (`torch.save` of the pytorch/examples checkpoint dict as
`checkpoint.pth.tar`, copied to `model_best.pth.tar`), `legacy_pth_tar`
(the same with `_use_new_zipfile_serialization=False`) and `pd_params`
(`paddle.save` of a Linear layer's and an Adam optimizer's `state_dict` as
`model.pdparams` and `model.pdopt`). Reported only, not part of the fix:
PyTorch Mobile `model.ptl` and `torch.export.save` `model.pt2`.

Planted folders E1 to E4 (`evil.pdparams`, `checkpoint.pth.tar`,
`model.pdopt`, `weights.pt.tar`) each hold the opcode stream
`test_attribution.py` already uses (GLOBAL `os system`, REDUCE). The control
folder holds a real `data.tar` and `logs.tar.gz`.

## Predictions

| # | prediction |
|---|---|
| P1 | the patch applies under the rules above |
| V1 | the original reads 0.12.0; the patched module and `pyproject.toml` read 0.13.0 |
| S1 | the whole unit-test suite passes on the patched tree: 0 failures, 0 errors |
| S2 | the new test module alone exits 0 and runs at least 9 tests |
| R0 | `route()` of every written and planted name is `pickle` in both versions |
| G1 | the gap: 0.12.0's walk of each writer folder keeps nothing |
| G2 | the gap: 0.12.0's CLI exits 0 with "no model files found" on each planted folder |
| F1 | 0.13.0's walk keeps exactly the written files in each writer folder |
| F2 | 0.13.0's CLI exits 1 on each planted folder, with PKL001 in the planted file |
| F3 | 0.13.0 on the honest writer files: no finding above LOW, and its CLI exits 0 on each writer folder |
| C1 | neither version keeps `data.tar` or `logs.tar.gz`; 0.13.0 exits 0 on the control folder |
| H1 | gate: at least 100 models listed |
| H2 | the name census finds at least one `.pdparams` file |
| H3 | published files of these names (at least 5 downloaded): no HIGH or CRITICAL finding from 0.13.0 |
| H4 | the same files: 0.12.0's walk of each one's folder keeps nothing, and 0.13.0's keeps the file |

## Grading

- If P1 fails, every other row is **not run**.
- A writer that raises or writes different files than predicted makes its
  folder **not graded**. That is reported, not dropped silently. If no
  graded writer works, G1, F1 and F3 are not run.
- Gate H1: fewer than 100 listed models makes H2 to H4 not run. Fewer than 5
  downloaded files makes H3 and H4 not run.
- An API or network error means the affected rows were not run.
- Reported, not graded: magic bytes of each written file, the `.ptl` and
  `.pt2` scan results, counts of each name class in the census, the 30
  extensions that the 0.13.0 walk skips by name most often in the census
  (input for the next audit), MEDIUM findings on published files, and
  download errors.
- **Release rule:** if every graded row holds, release **v0.53.0** with the
  patched files exactly as the job wrote them. One condition comes first: if
  the OpenVINO u3/u6 fix (v0.52.1) has shipped by then, the full suite must
  first pass in a short job on a tree with both changes. If any row fails,
  there is no release, and the failure is written up first.

## Limits

One tiny model and one release of each writer. The Hub lists are the most
downloaded models on one day, not a random sample. The census uses names
only. A clean result says our rules found nothing, not that a file or its
loader is safe. This check covers our own scanner. It does not test any
loader, and it touches no live system beyond public downloads in setup.
