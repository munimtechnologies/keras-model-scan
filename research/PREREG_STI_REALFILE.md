# Pre-registration: the safetensors shard-index scanner on real index files

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 5 November 2026 (UTC), before job `sti-realfile-v1` ran.

## Why

`safetensors_index_scan` 0.1.0 checks the `weight_map` of a sharded model's
index (`model.safetensors.index.json`, `pytorch_model.bin.index.json`) for
shard paths that would leave the model folder: absolute paths (STI001,
HIGH), `..` (STI002, HIGH), URL schemes (STI004, MEDIUM), backslashes
(STI003, MEDIUM), NUL bytes (STI006, MEDIUM), non-string values (STI007,
LOW) and sub-folder paths with `/` (STI005, LOW). model-file-scan 0.11.1
routes a file to it when the name ends in `.index.json`. It has never been
checked on index files written by the libraries that write them, or on the
index files people actually publish.

Reading our own source on 5 November 2026 also showed a gap. transformers and
diffusers put a weights *variant* before the last extension, so
`save_pretrained(..., variant="fp16")` writes
`model.safetensors.index.fp16.json`. That name does not end in `.index.json`:

- `model_file_scan.route()` sends it to the Keras config scanner, not to the
  shard-index scanner;
- a directory walk (`expand_paths`, and `safetensors_index_scan.scan_path`)
  skips it entirely.

Such files are published: `stabilityai/stable-diffusion-3-medium-diffusers`
has `text_encoder_3/model.safetensors.index.fp16.json` next to
`model.safetensors.index.json` (Hub file listing, 5 November 2026). This
check measures that gap on real files before any fix is written. It is about
our own scanner's coverage. It does not test how any loader treats a shard
path, and it touches no live system.

## Setup

A sealed `python:3.12` container. Setup has network. It downloads our live
`main` as `tree/` and installs CPU torch, transformers, huggingface_hub and
safetensors (newest releases, versions recorded). It also downloads public
index files from the Hugging Face Hub (below). The run step has no network.

**Writers** (`research/sti-realfile/sti_check.py`, writing in a child
process): a seeded tiny GPT-2 (2 layers, width 64, vocabulary 1,000) saved
with `max_shard_size="100KB"` so that it splits into several shards:

| case | writer |
|---|---|
| tf_st | transformers `save_pretrained` (safetensors) |
| tf_bin | the same with `safe_serialization=False` |
| tf_st_fp16 | `save_pretrained(variant="fp16")` |
| tf_bin_fp16 | `.bin` with `variant="fp16"` |
| hub_st | huggingface_hub `save_torch_state_dict` |

**Edited copies** of the tf_st index. One `weight_map` value is changed and
the file is kept on its own in a folder: `../outside.safetensors`,
`/tmp/outside.safetensors`, `C:\outside.safetensors`,
`https://example.invalid/x.safetensors`, `sub\x.safetensors`,
`sub/x.safetensors`, the number 123, and a name containing a NUL byte. The
`..` edit is also applied to the tf_st_fp16 index, keeping its variant name.

**Hub sample** (`research/sti-realfile/fetch_hub_index.py`): the Hub's model
list sorted by downloads, from the `safetensors` filter (1,000 models) and
the `diffusers` filter (200 models). Gated and private models are skipped.
Every file whose name matches `\.index(\.[A-Za-z0-9_-]+)?\.json$` is
downloaded, at most 4 per model, 400 in all, and 30 MB each. Requests are
made one at a time.

## Predictions

| # | case | prediction |
|---|---|---|
| W1 | tf_st | writes `model.safetensors.index.json`; the scanner reports only STI000 INFO; CLI exit 0; model-file-scan exit 0 on the file |
| W2 | tf_bin | the same for `pytorch_model.bin.index.json` |
| W3 | hub_st | the same for huggingface_hub's `model.safetensors.index.json` |
| W4 | tf_st_fp16 | the index is named `model.safetensors.index.fp16.json` and every `weight_map` value is `model.fp16-0000k-of-0000N.safetensors` |
| W5 | tf_st_fp16 | that index, scanned explicitly by `safetensors_index_scan.scan_file`, gives only STI000 INFO |
| G1 | tf_st_fp16 | the gap: `route()` is not `sti`, `expand_paths` of its folder leaves it out, and `safetensors_index_scan.scan_path` of its folder reports nothing located in it |
| G2 | edited fp16 copy with `..` | explicit `scan_file` reports STI002 HIGH, but a model-file-scan directory walk of its folder reports no STI finding |
| E1 | `../outside.safetensors` | exactly STI002 HIGH (no other non-INFO rule) |
| E2 | `/tmp/outside.safetensors` | exactly STI001 HIGH |
| E3 | `C:\outside.safetensors` | exactly STI001 HIGH |
| E4 | `https://example.invalid/x.safetensors` | exactly STI004 MEDIUM |
| E5 | `sub\x.safetensors` | exactly STI003 MEDIUM |
| E6 | `sub/x.safetensors` | exactly STI005 LOW |
| E7 | the number 123 | exactly STI007 LOW |
| E8 | NUL byte in the name | exactly STI006 MEDIUM |
| E9 | E1 and E6 through model-file-scan (default `--fail-on medium`) | exit 1 on E1, exit 0 on E6 |
| C1 | every file the writers wrote | the candidate name pattern above matches exactly the files that hold a `weight_map` (no config, generation config or shard file) |
| H2 | Hub sample | no file has a HIGH finding |
| H3 | Hub sample | at most 2% of files have a MEDIUM finding |
| H4 | Hub sample | at most 2% of files have STI005 (a shard in a sub-folder) |
| H5 | Hub sample | at least one variant-named index (`*.index.<variant>.json`) is in the sample |
| H6 | Hub sample | every `*.index.json` file routes to `sti`; every variant-named one does not |

## Grading

- **Gate H1:** if fewer than 50 Hub files are downloaded, H2 to H6 are
  **not run**.
- A writer that raises an error (for example, if a transformers release has
  dropped `.bin` saving) makes its rows **not run**, never held or failed.
- An API or network error means the affected rows were not run.
- These are reported but not graded: `metadata` keys, whether `total_size`
  equals the sum of tensor bytes, the full list of Hub files with any
  non-INFO finding, and the number of Hub files the candidate pattern
  matches that hold no `weight_map`.
- If G1 and G2 hold, the next release routes variant-named indexes to the
  shard-index scanner and keeps them in directory walks, with tests. A
  second real-file check then runs on the same files before that release.

## Limits

One tiny model and one release of each writer. The Hub sample is the most
downloaded non-gated models on one day, which is not a random sample of the
Hub. A finding on a published file is a statement about our scanner's
rules, not a claim that the file is unsafe.
