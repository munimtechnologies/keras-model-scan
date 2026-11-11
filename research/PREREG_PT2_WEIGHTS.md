# Pre-registration: raw weights in torch.export files (job pt2-weights-v1)

Written 2026-11-11, before the job runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## Why

Job pt2-nest-v1 ([REALFILE_CHECK_PT2_NEST_2026-11.md](../REALFILE_CHECK_PT2_NEST_2026-11.md))
recorded that the scanner gives an honest `torch.export` file nine PKL000
LOW "could not be fully parsed" notes, one per raw weight
(`model_b/data/weights/weight_0` to `weight_8`) whose first byte is 0x80.
v0.59.0 (pickle_model_scan 0.8.0) does not change that. Its grader missed
the gap because it looked for the prefix `model/`, while torch names the
archive's top folder after the file. Every row below matches
`/data/weights/` and `/data/constants/` without a fixed prefix.

How torch stores and reads these members (PyTorch source,
`torch/export/pt2_archive/_package.py`, `torch/csrc/export/pt2_archive_constants.h`,
`torch/_export/serde/schema.py`): `torch.export.save` writes
`<prefix>/archive_format` (`pt2`) and, per model,
`data/weights/<model>_weights_config.json` and
`data/constants/<model>_constants_config.json`. Each config maps a tensor to
a `PayloadMeta` with `path_name` (a bare name such as `weight_0`) and
`use_pickle`. A payload with `use_pickle` false is written as raw storage
bytes and read back with `get_storage_from_record`, never unpickled. A
payload with `use_pickle` true (tensor subclasses) goes through
`torch.save` / `torch.load`. AOTInductor packages read their weights another
way.

## The change (research/pt2-weights/patch_weights.py, on top of v0.59.0)

**pickle_model_scan 0.9.0**: a new helper `_pt2_raw_payloads(zf, names)`
returns a member only when **all** of these hold: its prefix has an
`archive_format` member whose text is `pt2`; that prefix has no
`data/aotinductor/` member; a weights or constants config in the same
folder names it as a bare name with `use_pickle` exactly `false`; and the
member exists. In `scan_zip` those members join the raw tensor storages
(0.6.0), so a leading 0x80 no longer sends them to the pickle walker.
Everything else is read exactly as before: payloads declared `use_pickle`
true or with no `use_pickle`, payloads no config names, path names with a
folder, malformed configs, and every member of an archive with AOTInductor
files. model_file_scan and pyproject stay 0.14.0.

New test file `test_pickle_model_scan_pt2_weights.py` (16 tests) on tiny
in-memory zips holding ordinary float32 bytes. It expects 0.9.0, so it enters
the repository with the release, not before.

## Fixtures (written by torch's own writers; nothing crafted)

F1 `model.pt` (scripted), F3 `model.ptl` (mobile), F4 `model.pt2`, F5
`weights.pth` (`torch.save(state_dict)`), F6 `model_b.pt2` (first element of
every float tensor 1.0000153, stored `80 00 80 3f`; `num_batches_tracked`
128), F7 `model_c.pt2` (a plain tensor attribute that `torch.export` lifts
as a tensor constant, first element 1.0000153). Each file is scanned by the
untouched v0.59.0 (**base**) and by the patched tree.

## Rows that decide the release (all predicted to hold)

| Row | Prediction |
|---|---|
| P1 | the patch applies once (4 edits), a second pass changes nothing, no line lost; versions base 0.14.0/0.8.0, patched 0.14.0/0.9.0 |
| S1 | the whole unit-test suite passes on base and patched, and the patched tree runs more tests |
| W1 | F6's own weights config, read with `json`, names every `data/weights/weight_N` member of F6 with `use_pickle` false |
| L0 | torch's own loaders load F1 (`torch.jit.load`), F4 and F6 (`torch.export.load`) |
| L1 | the F6 that `torch.export.load` returns has 1.0000153 (or 128) as the first element of every state-dict tensor: the 0x80-leading bytes are tensor data |
| B1 | base: F6 gets at least one PKL000 LOW on a `data/weights/weight_N` member |
| N1 | patched: F4 and F6 have no PKL000 and no PKL098 |
| N2 | patched: F4 and F6 have nothing at MEDIUM or above and no scanner error |
| N3 | base hands at least one F6 weight member to the pickle walker; patched hands none |
| T3 | F1, F3, F5 get exactly the same findings (rule, severity, location) from base and patched |
| T5 | on F6, patched findings equal base findings minus the PKL000 notes on weight members |
| C2 | the CLI with its default gate exits 1 on F1 and on the folder, 0 on F4, F5 and F6, for base and patched |

## Diagnostic rows (predicted, do not decide the release)

| Row | Prediction |
|---|---|
| D2 | base gives F7 at least one PKL000 on a `data/constants/` member, patched gives none |
| D3 | `torch.export.load` reads F7 |

Recorded without prediction: the weights and constants configs of F4, F6 and
F7 (path names and `use_pickle`), every member's first bytes, the members the
walker was handed, torch's version and the test counts.

## Decision rule (fixed now)

- **All release rows hold** → release keras-model-scan v0.60.0
  (pickle_model_scan 0.9.0) from the job's `out/patched`, with docs updated.
- **Any release row fails** → reported as failed; nothing ships; the fix is
  reworked in a new pre-registered job (pt2-weights-v2).

## Limits

One small network and one torch version. No fixture has a tensor subclass
(`use_pickle` true) or AOTInductor files; those paths are covered only by
unit tests, and they keep the old behaviour by design. A census on
2026-11-11 found no `.pt2` among the 9,865 open models in the 10,000 most
downloaded `pytorch`-tagged Hub models
([RESULTS_PT2_CENSUS_2026-11.md](../RESULTS_PT2_CENSUS_2026-11.md)), so this
fix is about files people make and share themselves. Static scanner: it
reports what is in the archive, not whether a program is safe.
