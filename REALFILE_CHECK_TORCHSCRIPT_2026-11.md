# Real-file check: TorchScript, PyTorch mobile and torch.export files (job torchscript-v1)

Graded 2026-11-10 against the pre-registration
[research/PREREG_TORCHSCRIPT.md](research/PREREG_TORCHSCRIPT.md), which was
committed before the job ran. Measurement only: model-file-scan v0.57.0
(model_file_scan 0.13.2, pickle_model_scan 0.6.0) was run unchanged.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0
(code), CC BY 4.0 (this text).

**Result: 10 of 10 pre-registered rows held.** Raw output:
[research/torchscript/results/](research/torchscript/results/).

## Setup

torch 2.15.0+cpu in a sealed container with no network for the run steps. One
small Linear/BatchNorm network, saved five ways by torch's own writers.
Nothing crafted, no downloaded models.

| File | Writer | Loader used as ground truth | Loaded? |
|---|---|---|---|
| F1 `model.pt` | `torch.jit.save(torch.jit.script(net))` | `torch.jit.load` | yes (RecursiveScriptModule) |
| F2 `model.torchscript` | `torch.jit.save(torch.jit.trace(net, x))` | `torch.jit.load` | yes |
| F3 `model.ptl` | `_save_for_lite_interpreter` | `_load_for_lite_interpreter` | yes (LiteScriptModule) |
| F4 `model.pt2` | `torch.export.save` | `torch.export.load` | yes (ExportedProgram) |
| F5 `weights.pth` | `torch.save(state_dict)` (control) | `torch.load(weights_only=True)` | yes (OrderedDict) |

## Rows

| Row | Prediction | Result |
|---|---|---|
| P1 | torch writes F1, F2, F3, F5 (F4 exploratory) | held (all five written) |
| W1 | a folder walk keeps `model.pt` and `weights.pth` | held |
| W2 | the folder walk skips `model.torchscript`, `model.ptl`, `model.pt2` | **held: the gap is real** |
| D1 | F1–F3 scanned directly: PKL003 MEDIUM, every one naming a `__torch__.` class | held (4 per file) |
| D2 | no CRITICAL/HIGH and no scanner error on any file | held |
| D3 | control F5 gets nothing at MEDIUM or above | held (no findings) |
| G1 | every global the scanner classes as unknown starts with `__torch__` | held (12 of 12) |
| L1 | `torch.jit.load` loads F1, F2; `torch.load(F1, weights_only=True)` raises; `weights_only=False` returns a ScriptModule | held |
| L2 | the lite interpreter loads F3 | held |
| C1 | the CLI's default gate (`--fail-on medium`) exits non-zero on F1 | held (exit 1) |

## What it means

1. **Folder scans were silent about three PyTorch formats.** Running
   `model-file-scan some/folder` on a folder of TorchScript (`.torchscript`,
   the name Ultralytics' export writes), PyTorch mobile (`.ptl`) or
   `torch.export` (`.pt2`) files reported nothing about them. Naming a file
   directly did scan it.
2. **The level is right; the reason was wrong.** Each TorchScript class got a
   PKL003 "Import outside the known-safe allowlist". But `torch.jit.load`
   builds `__torch__.*` classes from the TorchScript code stored in the
   archive; they are not Python imports. PyTorch's own SECURITY.md says
   TorchScript models "should be treated the same way as locally executable
   code from an unknown source", so MEDIUM stays, as one accurate finding per
   archive.
3. **torch.load refuses TorchScript under its safe default.** In torch 2.15,
   `torch.load(F1, weights_only=True)` raises "Cannot use weights_only=True
   with TorchScript archives", and `weights_only=False` hands the file to
   `torch.jit.load`. torch 2.15 also prints "`torch.jit.load` is deprecated.
   Please switch to `torch.export`."

Recorded without prediction: the direct scan of F4 (`.pt2`) gave one PKL000
LOW "could not be fully parsed" on the member
`model/data/sample_inputs/model.pt`. That is the note's own next gap: the
member has a pickle-like extension but is not a pickle stream, so the note is
inaccurate on an honest file. It is LOW and below the default gate.

## Next (decided by the pre-registration's rule)

W2 held, and D1, G1 and L1 held, so the fix was pre-registered next as
[research/PREREG_TS_FIX.md](research/PREREG_TS_FIX.md) (job ts-fix-v1):
model-file-scan 0.14.0 walks the three extensions, and pickle_model_scan 0.7.0
gives a TorchScript archive one PKL040 MEDIUM finding instead of one PKL003
per class. It ships only if those rows hold.

## Limits

One small network and one torch version; not a census of published files. The
scanner is static: these rows say what it reports, not whether a given
TorchScript program is safe.
