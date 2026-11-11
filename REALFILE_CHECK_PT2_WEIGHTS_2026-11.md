# Real-file check: raw weights in torch.export files (job pt2-weights-v1)

Graded 2026-11-11 against the pre-registration
[research/PREREG_PT2_WEIGHTS.md](research/PREREG_PT2_WEIGHTS.md), which was
committed before the job ran. Made with AI agents working in the name of MV2
of Munim, Inc. Text CC BY 4.0, code Apache-2.0.

**Result: all 12 release rows held, and both diagnostic rows held, so
pickle_model_scan 0.9.0 ships as keras-model-scan v0.60.0.**

The job ran once in a sealed container on 2026-11-11 (03:13 to 03:18 UTC),
with torch 2.15.0+cpu and no network during the run steps. It fetched the
released v0.59.0 source (272 files) as the base. Raw outputs are in
[research/pt2-weights/results/](research/pt2-weights/results/).

## What was tested

A `.pt2` file written by `torch.export.save` stores each weight as a separate
member under `<prefix>/data/weights/` and each lifted tensor constant under
`<prefix>/data/constants/`. A JSON config next to them says, for every tensor,
which member holds it and whether it is pickled (`use_pickle`). With
`use_pickle` false, `torch.export.load` reads the member as raw storage bytes.
Up to pickle_model_scan 0.8.0 the scanner did not read those configs, so any
raw weight whose first byte is 0x80 (the pickle `PROTO` opcode) went to the
pickle walker and got a PKL000 LOW "could not be fully parsed" note.

0.9.0 reads the configs and treats a member as data only when the archive
says `archive_format` = `pt2`, has no AOTInductor files, and a config in the
same folder names that member with `use_pickle` exactly `false`.

The fixtures were written by torch's own writers: F1 `torch.jit.script`
(`model.pt`), F3 PyTorch mobile (`model.ptl`), F4 `torch.export.save`
(`model.pt2`), F5 `torch.save(state_dict)` (`weights.pth`), F6 `model_b.pt2`
(the same network with every float tensor's first value set to 1.0000153,
stored `80 00 80 3f`, and `num_batches_tracked` = 128), and F7 `model_c.pt2`
(a network with a plain tensor attribute that `torch.export` lifts as a
constant). Nothing was crafted, and nothing was unpickled by the scanner.

## Release rows

| Row | Prediction | Result | Evidence |
|---|---|---|---|
| P1 | the patch applies once (4 edits), a second pass changes nothing, no line lost; versions base 0.14.0/0.8.0, patched 0.14.0/0.9.0 | **held** | 4 edits, second pass empty, 1,133 -> 1,203 lines |
| S1 | the whole unit-test suite passes on base and patched, and the patched tree runs more tests | **held** | 1,468 tests pass patched, 1,452 base, 0 failures, 0 errors |
| W1 | F6's own weights config names every `data/weights/weight_N` member with `use_pickle` false | **held** | all 9 members, all `false` |
| L0 | torch's own loaders load F1 (`torch.jit.load`), F4 and F6 (`torch.export.load`) | **held** | `torch.jit.load` warns that it is deprecated |
| L1 | the F6 that `torch.export.load` returns has 1.0000153 (or 128) as the first element of every state-dict tensor | **held** | all 9 tensors: the 0x80-leading bytes are tensor data |
| B1 | base: F6 gets at least one PKL000 LOW on a weight member | **held** | 9 PKL000 LOW, one per weight |
| N1 | patched: F4 and F6 have no PKL000 and no PKL098 | **held** | no findings at all |
| N2 | patched: F4 and F6 have nothing at MEDIUM or above and no scanner error | **held** | |
| N3 | base hands at least one F6 weight to the pickle walker; patched hands none | **held** | base 9, patched 0; both still walk `model_b/data/sample_inputs/model.pt!archive/data.pkl` |
| T3 | F1, F3, F5 get exactly the same findings from base and patched | **held** | identical on all three |
| T5 | on F6, patched findings equal base findings minus the weight notes | **held** | both empty after removing the 9 notes |
| C2 | the CLI's default gate exits 1 on F1 and the folder, 0 on F4, F5 and F6, base and patched | **held** | |

## Diagnostic rows

| Row | Prediction | Result | Evidence |
|---|---|---|---|
| D2 | base gives F7 at least one PKL000 on a `data/constants/` member, patched none | **held** | base: notes on `model_c/data/weights/weight_0` and `model_c/data/constants/tensor_0`; patched: none |
| D3 | `torch.export.load` reads F7 | **held** | an `ExportedProgram`, no warnings |

## What this means for honest files

F4, written with ordinary random weights, got no false note from either
version: none of its nine weights happened to start with 0x80. F6 and F7 show
that whether an honest `.pt2` drew false notes up to v0.59.0 depended only on
the first byte of each raw tensor, which is part of the weights' values. With
v0.60.0 that no longer matters for any payload the archive's own config
declares raw.

## Limits

One small network, one torch version (2.15.0, CPU). No fixture has a tensor
subclass (`use_pickle` true) or AOTInductor files; those paths keep the old
behaviour by design and are covered only by unit tests. A census on
2026-11-11 found no `.pt2` file among the 9,865 open models in the 10,000
most downloaded `pytorch`-tagged models on the Hugging Face Hub
([RESULTS_PT2_CENSUS_2026-11.md](RESULTS_PT2_CENSUS_2026-11.md)), so this fix
matters for files people make and share themselves. Static scanner: it reports
what is in the archive, not whether a program is safe.
