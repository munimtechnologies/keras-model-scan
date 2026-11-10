# Pre-registration: TorchScript, PyTorch mobile and torch.export files (job torchscript-v1)

Written 2026-11-10, before the job runs. Measurement only: model-file-scan
v0.57.0 (model_file_scan 0.13.2, pickle_model_scan 0.6.0) is run unchanged.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0
(code), CC BY 4.0 (this text).

## Why

Reading `model_file_scan.py` (0.13.2) found two things about TorchScript files:

1. **Folder walks skip three PyTorch formats.** `_walk_keeps` keeps a file
   only if its extension is in `_MODEL_EXTS` (or a few name patterns). The
   extensions `.ptl` (PyTorch mobile / lite interpreter), `.torchscript` (the
   file name Ultralytics' TorchScript export writes) and `.pt2`
   (`torch.export.save`) are not in it. So `model-file-scan some/folder` never
   looks at them and says nothing. Named directly, they are scanned (the
   router defaults to the pickle scanner).
2. **The finding on a TorchScript file names the wrong reason.** TorchScript
   pickles name their classes as `__torch__.<module path>.<Class>`. The
   pickle scanner treats `__torch__` as an unknown top-level module and
   reports one PKL003 MEDIUM "Import outside the known-safe allowlist" per
   class. But `torch.jit.load` doesn't import `__torch__` names from Python.
   It resolves them from the TorchScript code stored in the archive.

**What PyTorch says** (pytorch/pytorch SECURITY.md, read 2026-11-10):
"TorchScript models should be treated the same way as locally executable code
from an unknown source." "Only run TorchScript models if you trust the
provider." PyTorch mobile `.ptl` files "are TorchScript models".

So MEDIUM is the right *level* for a TorchScript archive; the wrong part is the
*reason* (an "import" that isn't one) and the repetition (one finding per
class). **The candidate fix floated in the previous run, downgrading PKL003 to
LOW for `__torch__` names, is rejected before measuring**, because PyTorch
itself treats these files as code. (We also checked CVE-2025-32434: its fix
commit, pytorch/pytorch 8d4b8a9, concerns the legacy `.tar` load path, not
TorchScript, so this note does not cite it.)

## Files (honest, written by torch itself in the sealed container)

F1 `model.pt` (torch.jit.script + torch.jit.save), F2 `model.torchscript`
(torch.jit.trace + torch.jit.save), F3 `model.ptl` (_save_for_lite_interpreter),
F4 `model.pt2` (torch.export.save, exploratory), F5 `weights.pth`
(torch.save of a state_dict, control). One small Linear/BatchNorm network.
Nothing is crafted. No Hub files this time.

## Rows (all predicted to hold)

| Row | Prediction |
|---|---|
| P1 | torch writes F1, F2, F3 and F5 (F4 exploratory) |
| W1 | a folder walk of the fixture folder keeps `model.pt` and `weights.pth` |
| W2 | the folder walk skips `model.torchscript`, `model.ptl` and (if written) `model.pt2` (**the gap**) |
| D1 | scanning F1, F2 and F3 directly gives at least one PKL003, all MEDIUM, and every PKL003 names a `__torch__.` class |
| D2 | no CRITICAL or HIGH finding (and no scanner error) on any fixture |
| D3 | the control F5 gets nothing at MEDIUM or above |
| G1 | disassembling every `.pkl` member of F1 to F3, every global the scanner classes as unknown starts with `__torch__` (at least one exists) |
| L1 | `torch.jit.load` loads F1 and F2; `torch.load(F1, weights_only=True)` raises; `torch.load(F1, weights_only=False)` returns a ScriptModule (torch.load hands TorchScript archives to torch.jit.load) |
| L2 | the lite interpreter loads F3 |
| C1 | the CLI with its default gate (`--fail-on medium`) exits non-zero on F1 |

Recorded without prediction: the number of PKL003 per file; what F4 gets
directly; the CLI exit on the whole folder; torch's warning texts.

## Decision rule (fixed now)

- **W2 holds** → next release: model-file-scan 0.14.0 adds `.ptl`,
  `.torchscript` and `.pt2` to the folder walk, with a test per extension.
- **D1, G1 and L1 hold** → pickle_model_scan 0.7.0 recognises a TorchScript
  archive (a zip whose prefix holds `data.pkl` plus a `code/` folder, or a
  `bytecode.pkl` for `.ptl`). It reports **one** MEDIUM finding, "TorchScript
  archive: treat as executable code", citing PyTorch's SECURITY.md, instead of
  one PKL003 per `__torch__.` class. Severity stays MEDIUM, so the default
  gate still stops these files. Any global outside `__torch__.` keeps today's
  rules unchanged. That release will get its own pre-registered check on honest
  files before it ships.
- **A row fails** → it's reported as failed, and nothing ships on the strength
  of that row.

## Limits

- One small network and one torch version (the CPU wheel current when the job
  runs). This is not a census of published files.
- The scanner is static. The rows say what it *reports*, not whether a given
  TorchScript program is safe; PyTorch's own advice is to run TorchScript only
  from providers you trust.
