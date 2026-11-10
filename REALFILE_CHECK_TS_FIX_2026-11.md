# Real-file check: the TorchScript fix (job ts-fix-v1)

Graded 2026-11-10 against the pre-registration
[research/PREREG_TS_FIX.md](research/PREREG_TS_FIX.md), which was committed
before the job ran. Made with AI agents working in the name of MV2 of
Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

**Result: 9 of 9 pre-registered rows held**, so by the pre-registered decision
rule the change ships as **keras-model-scan v0.58.0** (model_file_scan 0.14.0,
pickle_model_scan 0.7.0). Raw output:
[research/ts-fix/results/](research/ts-fix/results/).

## Setup

torch 2.15.0+cpu in a sealed container (1 CPU, 2 GB, no network for the run
steps; the job ran on 2026-11-10 from 13:36 to 13:40 UTC). The same five
honest files as job torchscript-v1
([REALFILE_CHECK_TORCHSCRIPT_2026-11.md](REALFILE_CHECK_TORCHSCRIPT_2026-11.md)),
written by torch's own writers: F1 `model.pt` (`torch.jit.script` +
`torch.jit.save`), F2 `model.torchscript` (traced), F3 `model.ptl` (lite
interpreter), F4 `model.pt2` (`torch.export.save`), F5 `weights.pth`
(`torch.save(state_dict)`, control). Each was scanned by the untouched
v0.57.0 (**base**: 0.13.2 / 0.6.0) and by the patched tree (0.14.0 / 0.7.0).

## Rows

| Row | Prediction | Result |
|---|---|---|
| P1 | the patch applies once to each file, a second pass changes nothing, no line lost; versions as planned | held |
| S1 | the whole unit-test suite passes on the patched tree and runs more tests than base | held: 1,444 tests passed (base 1,431), no failures or errors, 3 skipped in both |
| W3 | the patched folder walk keeps all five files; base keeps only `model.pt` and `weights.pth` | held |
| T1 | F1, F2, F3 each get exactly one PKL040 MEDIUM and no `__torch__` PKL003 when patched | held (base: 4 such PKL003 per file; patched: 0) |
| T2 | patched: no CRITICAL/HIGH finding and no scanner error on any file | held |
| T3 | F4 and F5 get exactly the same findings from base and patched | held |
| T4 | the highest severity of every file is the same in base and patched | held (MEDIUM for F1–F3, LOW for F4, none for F5) |
| C2 | the patched CLI with its default gate exits non-zero on F1 and on the folder, and 0 on F5 | held (1, 1, 0) |
| L0 | torch's own loaders load F1, F2 (`torch.jit.load`) and F3 (lite interpreter) | held |

## What changed for users

1. **Folder scans no longer skip three PyTorch formats.** `model-file-scan
   some/folder` now scans `.torchscript`, `.ptl` and `.pt2` files. Before,
   it reported nothing about them unless they were named directly.
2. **One accurate finding instead of several misleading ones.** An honest
   TorchScript archive used to get one PKL003 "import outside the allowlist"
   for each `__torch__` class. Those classes are built by `torch.jit.load`
   from code stored in the archive; they are not Python imports. It now gets
   one PKL040 MEDIUM "TorchScript archive: treat as executable code", which
   is what PyTorch's own SECURITY.md says about TorchScript models.
3. **Nothing became quieter.** The severity is the same, every other finding
   is kept, and the default gate still stops every TorchScript file.

Recorded without prediction: F4 (`.pt2`) still gets one PKL000 LOW "could
not be fully parsed" on its member `model/data/sample_inputs/model.pt`, in
base and patched alike. That member has a pickle-like extension but is not
a pickle stream. It is the next item in the queue of known gaps. torch 2.15
prints "`torch.jit.load` is deprecated. Please switch to `torch.export`."

## Limits

One small network and one torch version; not a census of published files.
The scanner is static: PKL040 says a file is a TorchScript program to be
trusted like code, not whether that program is safe.
