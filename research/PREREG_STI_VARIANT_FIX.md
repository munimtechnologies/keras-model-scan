# Pre-registration: routing variant-named shard indexes (fix + second real-file check)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 6 November 2026 (UTC), before job `sti-variant-fix-v1` ran.
Scripts: [research/sti-variant-fix/](sti-variant-fix/). The new test module
is committed together with the fix, so it never runs against unpatched code.

## Why

The first real-file check ([REALFILE_CHECK_STI_2026-11.md](../REALFILE_CHECK_STI_2026-11.md))
confirmed a gap in model-file-scan 0.11.1: an index written with a weights
variant (`save_pretrained(..., variant="fp16")` writes
`model.safetensors.index.fp16.json`) is routed to the Keras config scanner
and skipped by both directory walks, so a `..` shard path inside it passes a
folder scan. Its pre-registered rule says that the fix ships only after a
second real-file check holds.

## The fix (patch_sti.py, applied to live `main` inside the job)

- `model_file_scan.py` and `safetensors_index_scan.py` get one helper,
  `_is_shard_index(name)`, which matches `\.index(\.[A-Za-z0-9_-]+)?\.json$`
  without regard to case. This is the candidate pattern that matched exactly
  the index files in the first check (row C1) and every one of the 394 Hub
  files. Every `<expr>.endswith(".index.json")` in those two files becomes
  `_is_shard_index(<expr>)`. No quoted `".index.json"` may remain.
- Versions: model-file-scan 0.12.0 (module and `pyproject.toml`),
  safetensors_index_scan 0.2.0, and the matching floors in
  `test_attribution.py`.
- Docs: the two routing rows and the "Formats routed" heading in
  `MODEL_FILE_SCAN.md` (optional: reported, never required).
- New stdlib test module `test_safetensors_index_variant.py` (9 tests).
- Each edit must apply exactly once. A second pass must change nothing, and
  no line may be lost except the replaced ones. Otherwise nothing is written.

## Setup

A sealed `python:3.12` container. Setup has network: it downloads live
`main`, installs CPU torch, transformers, huggingface_hub and safetensors
(newest releases, versions recorded), and re-runs the first check's Hub
download with the same rules: most downloaded models in the `safetensors`
(1,000) and `diffusers` (200) lists, non-gated, at most 4 matching files per
model, 400 in all, 30 MB each, each in its own folder. The sample is drawn
again, so it can differ a little from the first one. The run steps have no
network.

Writers (child process, seeded tiny GPT-2 with `max_shard_size="100KB"`):
`tf_st` (transformers `save_pretrained`), `tf_st_fp16` (`variant="fp16"`),
`tf_st_ema` (`variant="ema"`), and `hub_st` (huggingface_hub
`save_torch_state_dict`). The `.bin` cases are dropped because transformers 5
no longer writes `.bin` (first check, row W2).

## Predictions

| # | prediction |
|---|---|
| P1 | the patch applies under the rules above (both modules, `pyproject.toml`, `test_attribution.py`) |
| S1 | the whole unit-test suite passes on the patched tree: 0 failures, 0 errors |
| S2 | the new test module alone exits 0 and runs at least 9 tests |
| V1 | versions read model-file-scan 0.12.0, safetensors_index_scan 0.2.0, `pyproject.toml` 0.12.0 |
| W1 | `tf_st`: `model.safetensors.index.json`; only STI000 INFO; both CLIs exit 0; route `sti` |
| W3 | `hub_st`: the same |
| R1 | both variant indexes (`model.safetensors.index.fp16.json`, `model.safetensors.index.ema.json`): route `sti`; kept by `expand_paths` of their folder; `safetensors_index_scan.scan_path(folder)` reports STI000; only STI000; model-file-scan exits 0 on a folder holding just that index |
| R3 | `..` edited into the fp16 index (kept on its own in a folder): the model-file-scan walk reports STI002, `safetensors_index_scan.scan_path` reports STI002, and the model-file-scan CLI exits 1 on the folder (it exited 0 before the fix) |
| R4 | the eight edited standard-name copies give exactly the same single rule as in the first check (E1 to E8), and model-file-scan exits 1 on E1 and 0 on E6 |
| R5 | among all writer files, route is `sti` exactly for names matching the pattern, and those are exactly the files with a `weight_map` |
| H2 | Hub sample: no file has a HIGH finding |
| H3 | Hub sample: at most 2% of files have a MEDIUM finding |
| H4 | Hub sample: at most 2% of files have STI005 |
| H5 | Hub sample: at least one variant-named index is present |
| H6 | Hub sample: every downloaded file routes to `sti`, standard and variant names alike |
| H7 | Hub sample: every downloaded file is kept by `expand_paths` of its folder |

## Grading

- **Gate H1:** fewer than 50 Hub files downloaded makes H2 to H7 **not run**.
- If P1 fails, every other row is **not run** (nothing else would be about
  the fix).
- A writer that raises, or writes a different file than predicted, is
  reported. Its rows are graded as written and are not silently dropped.
- An API or network error means the affected rows were not run.
- Reported, not graded: the exit code of model-file-scan on each whole
  writer folder (it also holds `config.json` and the shards), Hub rule
  counts, and download errors.
- **Release rule:** if every graded row holds, release v0.52.0 with the
  patched files exactly as the job wrote them (plus the OpenVINO u3/u6 fix
  if its own pre-registered check has held by then). If any row fails, no
  release: the failure is written up first.

## Limits

One tiny model and one release of each writer; the Hub sample is the most
downloaded non-gated models on one day. A clean result says our rules found
nothing, not that a file or its loader is safe. This is a check of our own
scanner. It does not test how any loader treats a shard path, and it touches
no live system.
