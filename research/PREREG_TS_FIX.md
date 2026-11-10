# Pre-registration: the TorchScript fix (job ts-fix-v1)

Written 2026-11-10, before the job runs. It tests a code change on the honest
files of job torchscript-v1 ([REALFILE_CHECK_TORCHSCRIPT_2026-11.md](../REALFILE_CHECK_TORCHSCRIPT_2026-11.md),
10 of 10 rows held). Made with AI agents working in the name of MV2 of
Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## The change (research/ts-fix/patch_ts.py)

- **model_file_scan 0.14.0**: `.ptl`, `.torchscript` and `.pt2` join
  `_MODEL_EXTS`, so folder walks scan them (they already route to the pickle
  scanner when named directly). pyproject version 0.14.0.
- **pickle_model_scan 0.7.0**: `scan_zip` recognises a TorchScript archive: a
  prefix with `data.pkl` plus a `code/` folder or a `bytecode.pkl`. For each
  one it reports **one PKL040 MEDIUM "TorchScript archive: treat as executable
  code"**, citing PyTorch's SECURITY.md, and drops only the PKL003 findings
  that name a `__torch__.` class and sit in that prefix's own `data.pkl`,
  `constants.pkl` or `bytecode.pkl`. Every other finding stays: any
  non-`__torch__` import, any other rule, any other member.
- New tests: `test_model_file_scan_torchscript_walk.py` (4) and
  `test_pickle_model_scan_torchscript.py` (9), on tiny in-memory zips whose
  pickles only name classes. They expect the new versions, so they are added
  to the repository root with the release, not before (until then they live
  in the job's work folder and in its `out/patched`).

Severity is unchanged by design (PKL003 and PKL040 are both MEDIUM), so the
default gate (`--fail-on medium`) still stops every TorchScript file.

## Rows (all predicted to hold)

The job writes the same five honest files as torchscript-v1 with torch's own
writers (F1 `model.pt` scripted, F2 `model.torchscript` traced, F3 `model.ptl`
lite, F4 `model.pt2` torch.export, F5 `weights.pth` state_dict control), then
scans them with the untouched v0.57.0 (**base**) and the patched tree.

| Row | Prediction |
|---|---|
| P1 | the patch applies once to each of model_file_scan.py, pyproject.toml, pickle_model_scan.py (a second pass changes nothing, no line lost); versions base 0.13.2/0.6.0, patched 0.14.0/0.7.0 |
| S1 | the whole unit-test suite passes on the patched tree and runs more tests than base |
| W3 | the patched folder walk keeps all five files; base keeps only `model.pt` and `weights.pth` |
| T1 | F1, F2, F3 each get exactly one PKL040 MEDIUM and no `__torch__` PKL003 when patched (base had at least one each) |
| T2 | patched: no CRITICAL/HIGH finding and no scanner error on any file |
| T3 | F4 and F5 get exactly the same findings (rule, severity, location) from base and patched |
| T4 | the highest severity of every file is the same in base and patched |
| C2 | patched CLI with its default gate exits non-zero on F1 and on the folder, and 0 on F5 (as base does) |
| L0 | torch's own loaders load F1, F2 (`torch.jit.load`) and F3 (lite interpreter) |

Recorded without prediction: base and patched test counts, F4's findings
(torchscript-v1 saw one PKL000 LOW on a non-pickle member), the member list
of each file, torch's version.

## Decision rule (fixed now)

- **All rows hold** → release keras-model-scan v0.58.0 (model-file-scan
  0.14.0, pickle_model_scan 0.7.0) from the job's `out/patched`, with docs
  updated, then pin the agent skill to it.
- **Any row fails** → reported as failed; nothing ships. A failing S1 or T
  row is fixed in a new pre-registered job (ts-fix-v2).

## Limits

One small network and one torch version. Static scanner: PKL040 says the file
is a TorchScript program to be trusted like code, not whether that program is
safe.
