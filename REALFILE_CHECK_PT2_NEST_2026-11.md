# Real-file check: zip members that are zips (job pt2-nest-v1)

Graded 2026-11-11 against the pre-registration
[research/PREREG_PT2_NEST.md](research/PREREG_PT2_NEST.md), which was
committed before the job ran. Made with AI agents working in the name of MV2
of Munim, Inc. Text CC BY 4.0, code Apache-2.0.

**Result: all 11 release rows held, so pickle_model_scan 0.8.0 ships as
keras-model-scan v0.59.0.** The one diagnostic row, D1, is graded "failed" by
the job's own grader because of a path mistake in the grader. The recorded
findings show that the gap D1 predicted is real (details below).

The job ran once in a sealed container on 2026-11-10 (21:27 to 21:31 UTC),
with torch 2.15.0+cpu. Raw outputs are in
[research/pt2-nest/results/](research/pt2-nest/results/).

## What was tested

An honest `torch.export` file (`model.pt2`) stores its sample inputs as a
complete `torch.save` archive at `<prefix>/data/sample_inputs/model.pt`. That
member is a zip inside the zip. Up to pickle_model_scan 0.7.0 its `.pt` name
sent it to the pickle walker, which gave it a PKL000 LOW "could not be fully
parsed" note and never read the pickle inside. 0.8.0 opens such a member as
a zip (up to two levels deep) and scans it like any other archive.

The fixtures were written by torch's own writers: F1 `torch.jit.script`,
F2 `torch.jit.trace`, F3 PyTorch mobile, F4 `torch.export.save`, F5
`torch.save(state_dict)`, and F6, a second `.pt2` of the same network
whose raw weights start with byte 0x80. Nothing was crafted, and nothing was
unpickled by the scanner.

## Rows

| Row | Prediction | Result | Evidence |
|---|---|---|---|
| P1 | the patch applies once (4 edits), a second pass changes nothing, no line lost; versions base 0.14.0/0.7.0, patched 0.14.0/0.8.0 | **held** | 4 edits, second pass empty, 1,102 -> 1,133 lines |
| S1 | the whole unit-test suite passes on base and patched, and the patched tree runs more tests | **held** | 1,452 tests pass patched, 1,444 base, 0 failures, 0 errors |
| M1 | base: F4 gets exactly one finding, PKL000 LOW, on `model/data/sample_inputs/model.pt` | **held** | that single note |
| M2 | that member starts with `PK\x03\x04`, opens as a zip, and `torch.load(..., weights_only=True)` reads it | **held** | 1,641 bytes, 7 inner members incl. `archive/data.pkl`, loads as a tuple |
| N1 | patched: F4 has no PKL000 and no PKL098 | **held** | no findings at all |
| N2 | patched: F4 has nothing at MEDIUM or above and no scanner error | **held** | |
| N3 | the pickle walker gets the member itself in base, and the `data.pkl` inside it when patched | **held** | base `F4!model/data/sample_inputs/model.pt`; patched `F4!model/data/sample_inputs/model.pt!archive/data.pkl` |
| T3 | F1, F2, F3, F5 get exactly the same findings from base and patched | **held** | identical on all four |
| T4 | the highest severity of F1, F2, F3, F5 is the same | **held** | F1-F3 MEDIUM (PKL040), F5 none |
| C2 | the CLI's default gate exits 1 on F1 and the folder, 0 on F4 and F5, base and patched | **held** | |
| L0 | torch's own loaders load F1 (`torch.jit.load`), F4 and F6 (`torch.export.load`) | **held** | |

## The diagnostic row D1

D1 predicted that the untouched v0.58.0 would give F6 at least one PKL000 LOW
on a raw weight. The grader looked for locations containing
`!model/data/weights/`, but `torch.export.save` names the archive's top
folder after the file, so F6 (`model_b.pt2`) keeps its weights under
`model_b/data/weights/`. The grader therefore found nothing and marked D1
"failed". This was our mistake in the grader, not a change in the
measurement. We report the row as graded and do not rewrite it.

What was recorded is clear: v0.58.0 gave F6 **nine** PKL000 LOW notes, one on
each of `model_b/data/weights/weight_0` to `weight_8`. Every one of those
members starts with `80 00 80 3f` or `80 00 00 00`: raw tensor bytes, which
`torch.export.load` reads as raw storage and never unpickles. 0.8.0 does not
change this. It keeps the same nine notes and removes only the
sample-inputs note.

This gap becomes its own pre-registered check:
[research/PREREG_PT2_WEIGHTS.md](research/PREREG_PT2_WEIGHTS.md). It has to
follow the archive's own weights config, because torch stores a weight as raw
bytes or as a pickle depending on that config.

## Limits

One small network, one torch version (2.15.0, CPU). Nesting is opened at
most two levels below the outer file. A census run the same day found no
`.pt2` file among the 9,865 open models in the 10,000 most downloaded
`pytorch`-tagged models on the Hugging Face Hub
([RESULTS_PT2_CENSUS_2026-11.md](RESULTS_PT2_CENSUS_2026-11.md)), so this fix
matters for files people make and share locally more than for the Hub's
top-ranked models. Static scanner: it reports what is in the archive, not
whether a program is safe.
