# Real-file check: routing variant-named shard indexes (graded)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 6 November 2026 (UTC). Pre-registration:
[research/PREREG_STI_VARIANT_FIX.md](research/PREREG_STI_VARIANT_FIX.md),
committed 6 November 2026 at 03:19 UTC (f3760a7), before job
`sti-variant-fix-v1` ran (2026-11-06 09:44 to 09:53 UTC). Scripts:
[research/sti-variant-fix/](research/sti-variant-fix/). Raw results:
[research/sti-variant-fix/results/](research/sti-variant-fix/results/).

## Result

**16 of 16 graded predictions held. None were skipped.** Under the
pre-registered release rule, the fix ships as **v0.52.0**
(model-file-scan 0.12.0, safetensors_index_scan 0.2.0), with the patched files
exactly as the job wrote them. The only other changes are two lines in
`MODEL_FILE_SCAN.md`: the Action example now pins `@v0.52.0`, and the
index row now links its checks.

The gap found by the [first check](REALFILE_CHECK_STI_2026-11.md) is closed.
An index written with a weights variant (`save_pretrained(variant="fp16")`
writes `model.safetensors.index.fp16.json`) now goes to the shard-index
scanner and is kept by both directory walks. A `..` shard path in such a file
used to pass a folder scan (exit 0). It is now reported as STI002 HIGH, and
the folder scan exits 1.

## The fix

One helper, `_is_shard_index(name)`, in `model_file_scan.py` and
`safetensors_index_scan.py`. It matches `\.index(\.[A-Za-z0-9_-]+)?\.json$`
without regard to case. Each of the three `.endswith(".index.json")` tests (two
in model-file-scan, one in the index scanner's directory walk) now calls it.
The patch applied once, and a second pass changed nothing. Only the replaced
lines differ, and no quoted `".index.json"` test remains. A new stdlib test
module, `test_safetensors_index_variant.py`, has 9 tests.

## Versions

Live `main` at f3760a7. Writers: torch 2.15.0+cpu, transformers 5.22.1,
huggingface_hub 2.4.0, safetensors 0.8.0, numpy 2.5.4. Container
`python:3.12`; the run steps had no network. Peak memory 0.23 GB.

## Rows

| # | prediction | result |
|---|---|---|
| P1 | the patch applies under the rules (both modules, `pyproject.toml`, `test_attribution.py`) | held (2 + 1 replacements, second pass empty, nothing lost) |
| S1 | full unit-test suite on the patched tree: 0 failures, 0 errors | held (1,319 tests, 0 failures, 0 errors, 3 skipped) |
| S2 | the new test module alone exits 0 and runs at least 9 tests | held (9) |
| V1 | model-file-scan 0.12.0, safetensors_index_scan 0.2.0, `pyproject.toml` 0.12.0 | held |
| W1 | transformers `save_pretrained`: `model.safetensors.index.json`, only STI000, exits 0 / 0, route `sti` | held |
| W3 | huggingface_hub `save_torch_state_dict`: the same | held |
| R1 | both variant indexes (`.index.fp16.json`, `.index.ema.json`): route `sti`, kept by `expand_paths`, `scan_path(folder)` STI000, only STI000, exit 0 on a folder holding just the index | held (both) |
| R3 | `..` edited into the fp16 index: walk STI002, `scan_path` STI002, model-file-scan exits 1 on the folder | held (it exited 0 before the fix) |
| R4 | the eight edited standard-name copies give the same single rule as in the first check; exit 1 on E1, 0 on E6 | held (E1 STI002, E2/E3 STI001, E4 STI004, E5 STI003, E6 STI005, E7 STI007, E8 STI006) |
| R5 | among all writer files, route is `sti` exactly for index names, and those are exactly the files with a `weight_map` | held (38 files, 0 mismatches) |
| H1 | gate: at least 50 Hub files | passed (394) |
| H2 | Hub sample: no HIGH finding | held (0) |
| H3 | Hub sample: at most 2% MEDIUM | held (0 of 394) |
| H4 | Hub sample: at most 2% STI005 | held (0 of 394) |
| H5 | Hub sample: at least one variant-named index | held (2, both in `openai/whisper-large-v3`: `model.safetensors.index.fp32.json` and `pytorch_model.bin.index.fp32.json`) |
| H6 | Hub sample: every file routes to `sti`, standard and variant names alike | held (0 elsewhere) |
| H7 | Hub sample: every file is kept by `expand_paths` of its folder | held (0 left out) |

## Reported, not graded

- **Writers.** All four writers ran. The two variant writers produced
  `model.fp16-0000k-of-00007.safetensors` and `model.ema-0000k-of-00007.safetensors`
  shards next to their variant index. model-file-scan exited 0 on each whole
  writer folder.
- **Hub sample.** It was drawn again on 6 November (09:45 to 09:48 UTC) under
  the first check's rules: 394 files from 359 models. 25 gated models were
  skipped. 6 index files over the 30 MB cap were not downloaded (very large
  mixture-of-experts or NVFP4 checkpoints, such as `moonshotai/Kimi-K3` and
  `nvidia/Kimi-K2.5-NVFP4`). No file had any finding above INFO.

## What this means

- Directory scans in CI now cover the documented output of `variant=` in
  transformers and diffusers. These names are rare among the most-downloaded
  models (2 of 394 files), but they are what those libraries write whenever
  a variant is asked for.
- Other name-based routes in model-file-scan are next. The same kind of audit
  can find more names that the real writers produce and the router misses.

## Limits

One tiny model and one release of each writer. The Hub sample is the most
downloaded non-gated models on one day, not a random sample. A clean result
says our rules found nothing, not that a file or its loader is safe. This
check covers our own scanner only. It does not test how any loader treats a
shard path, and it touched no live system beyond public downloads in setup.
