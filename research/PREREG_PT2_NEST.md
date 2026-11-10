# Pre-registration: zip members that are zips (job pt2-nest-v1)

Written 2026-11-10, before the job runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## Why

Jobs torchscript-v1 and ts-fix-v1 both recorded, without predicting it, that
an honest `torch.export` file (`model.pt2`) gets one PKL000 LOW "pickle stream
could not be fully parsed" on its member `model/data/sample_inputs/model.pt`.
That member has a pickle-like extension, so `scan_zip` hands it to the pickle
walker, but its bytes look like a zip archive in their own right (a
`torch.save` file stored inside the `.pt2`). Two problems follow: the note is
wrong on an honest file, and the pickles inside that member are never read.

## The change (research/pt2-nest/patch_nest.py, on top of v0.58.0)

**pickle_model_scan 0.8.0**: in `scan_zip`, a member that starts with the zip
magic `PK\x03\x04`, is not a raw tensor storage, opens as a zip, and sits
less than two levels below the outer file is scanned with `scan_zip` itself.
Everything else takes the old path unchanged (a member that has the magic but
does not open as a zip is read exactly as before). `scan_zip(data, source)`
gains an optional `_depth=0`, so callers keep working. model_file_scan and
pyproject stay 0.14.0.

New test file `test_pickle_model_scan_nested_zip.py` (8 tests) on tiny
in-memory zips whose pickles only name a made-up class. It expects 0.8.0, so
it enters the repository with the release, not before.

## Fixtures (all written by torch's own writers; nothing crafted)

F1 `model.pt` (scripted), F2 `model.torchscript` (traced), F3 `model.ptl`
(lite), F4 `model.pt2` (`torch.export.save`), F5 `weights.pth`
(`torch.save(state_dict)`, control), and new **F6 `model_b.pt2`**: the same
network after setting the first element of every float tensor to 1.0000153
(stored as `80 00 80 3f`) and `num_batches_tracked` to 128, so its raw weight
bytes start with 0x80. Each file is scanned by the untouched v0.58.0 (**base**)
and by the patched tree.

## Rows that decide the release (all predicted to hold)

| Row | Prediction |
|---|---|
| P1 | the patch applies once (4 edits), a second pass changes nothing, no line lost; versions base 0.14.0/0.7.0, patched 0.14.0/0.8.0 |
| S1 | the whole unit-test suite passes on base and on the patched tree, and the patched tree runs more tests |
| M1 | base: F4 gets exactly one finding, PKL000 LOW, on `model/data/sample_inputs/model.pt` |
| M2 | that member starts with `PK\x03\x04`, opens as a zip, and `torch.load(..., weights_only=True)` reads it |
| N1 | patched: F4 has no PKL000 and no PKL098 |
| N2 | patched: F4 has nothing at MEDIUM or above and no scanner error |
| N3 | the pickle walker is handed the member itself in base, and a `data.pkl` inside it (not the member) when patched |
| T3 | F1, F2, F3, F5 get exactly the same findings (rule, severity, location) from base and patched |
| T4 | the highest severity of F1, F2, F3, F5 is the same in base and patched |
| C2 | the CLI with its default gate exits 1 on F1 and on the folder, 0 on F4 and F5, for base and patched |
| L0 | torch's own loaders load F1 (`torch.jit.load`), F4 and F6 (`torch.export.load`) |

## Diagnostic row (predicted, does not decide the release)

| Row | Prediction |
|---|---|
| D1 | base: F6 gets at least one PKL000 LOW on a member under `model/data/weights/` (a `.pt2` has no `data.pkl`, so its raw weights are not recognised as tensor storage and any that start with 0x80 are read as a pickle) |

If D1 holds, that is the next gap, with its own pre-registration.

Recorded without prediction: F6's findings in base and patched, the member
names and first bytes of F4 and F6, the members the walker was handed, torch's
version and the test counts.

## Decision rule (fixed now)

- **All release rows hold** → release keras-model-scan v0.59.0
  (pickle_model_scan 0.8.0) from the job's `out/patched`, with docs updated.
- **Any release row fails** → reported as failed; nothing ships; the fix is
  reworked in a new pre-registered job (pt2-nest-v2).

## Limits

One small network and one torch version. The nesting depth is capped at two
levels below the outer file; a deeper zip is handled as before. Static
scanner: it reports what is in the archive, not whether a program is safe.
