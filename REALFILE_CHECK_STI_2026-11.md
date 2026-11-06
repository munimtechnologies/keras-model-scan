# Real-file check: the safetensors shard-index scanner (graded)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 6 November 2026 (UTC). Pre-registration:
[research/PREREG_STI_REALFILE.md](research/PREREG_STI_REALFILE.md), committed
5 November 2026 at 14:00 UTC, before job `sti-realfile-v1` ran (2026-11-06
02:56 to 03:04 UTC). Scripts: [research/sti-realfile/](research/sti-realfile/).

## Result

**21 of 22 graded predictions held. 0 were not run.** The one failure (W2)
is a wrong prediction about a writer, not about the scanner: transformers 5
no longer writes `.bin` checkpoints, and passing `safe_serialization=False`
did not raise in 5.22.1, so no `pytorch_model.bin.index.json` was written.

Both gap predictions held (G1, G2): an index file with a weights *variant*
in its name (`model.safetensors.index.fp16.json`, written by
`save_pretrained(variant="fp16")`) is routed by model-file-scan 0.11.1 to the
Keras config scanner and is skipped by directory walks. A `..` shard path in
such a file is caught when the file is scanned on its own (STI002 HIGH) but
**not** when its folder is scanned, which is how CI uses the tool. Under the
pre-registered rule, the next step is a routing fix with tests and a second
real-file check on the same kinds of files before release.

On 394 index files published on the Hugging Face Hub (360 models), the
scanner raised **no finding above INFO**.

## Versions

safetensors_index_scan 0.1.0 and model-file-scan 0.11.1 (live `main`).
Writers: torch 2.15.0+cpu, transformers 5.22.1, huggingface_hub 2.4.0,
safetensors 0.8.0, numpy 2.5.4. Container `python:3.12`; the run step had no
network.

## Rows

| # | case | prediction | result |
|---|---|---|---|
| W1 | transformers `save_pretrained` | `model.safetensors.index.json`; only STI000 INFO; exits 0 / 0 | held |
| W2 | the same with `safe_serialization=False` | `pytorch_model.bin.index.json`; only STI000; exits 0 / 0 | **failed**: transformers 5.22.1 wrote `model.safetensors.index.json` and safetensors shards. The scanner gave only STI000 and exit 0 / 0 on that file |
| W3 | huggingface_hub `save_torch_state_dict` | `model.safetensors.index.json`; only STI000; exits 0 / 0 | held |
| W4 | `save_pretrained(variant="fp16")` | index `model.safetensors.index.fp16.json`, shards `model.fp16-0000k-of-0000N.safetensors` | held (7 shards) |
| W5 | that variant index, scanned explicitly | only STI000 INFO | held |
| G1 | the gap | `route()` is not `sti`; `expand_paths` leaves it out; `scan_path(folder)` reports nothing in it | held: route `keras`; the walk kept `config.json` and the 7 shards, not the index; no finding located in it |
| G2 | `..` edited into the variant index | explicit `scan_file` STI002 HIGH; model-file-scan folder walk no STI finding | held: STI002 HIGH explicitly; the walk scanned no file at all and exited 0 |
| E1 | `../outside.safetensors` | exactly STI002 HIGH | held |
| E2 | `/tmp/outside.safetensors` | exactly STI001 HIGH | held |
| E3 | `C:\outside.safetensors` | exactly STI001 HIGH | held |
| E4 | `https://example.invalid/x.safetensors` | exactly STI004 MEDIUM | held |
| E5 | `sub\x.safetensors` | exactly STI003 MEDIUM | held |
| E6 | `sub/x.safetensors` | exactly STI005 LOW | held |
| E7 | the number 123 | exactly STI007 LOW | held |
| E8 | a NUL byte in the name | exactly STI006 MEDIUM | held |
| E9 | E1 and E6 through model-file-scan (default gate) | exit 1 on E1, exit 0 on E6 | held |
| C1 | the candidate name pattern `\.index(\.[A-Za-z0-9_-]+)?\.json$` on every writer file | matches exactly the files holding a `weight_map` | held: 5 matched, 0 mismatches (no config, generation config or shard file matched) |
| H1 | gate: at least 50 Hub files | | passed (394) |
| H2 | Hub sample | no HIGH finding | held (0) |
| H3 | Hub sample | at most 2% MEDIUM | held (0 of 394) |
| H4 | Hub sample | at most 2% STI005 | held (0 of 394) |
| H5 | Hub sample | at least one variant-named index | held (2: `openai/whisper-large-v3` `model.safetensors.index.fp32.json` and `pytorch_model.bin.index.fp32.json`) |
| H6 | Hub sample | every `*.index.json` routes to `sti`; every variant name does not | held (0 mismatches) |

W2 is graded as failed, as written. The pre-registration said a writer that
*raises* makes its rows "not run"; this writer did not raise, it wrote a
different format. Transformers' v5 migration guide says
`safe_serialization=False` was dropped and `save_pretrained` always writes
safetensors (huggingface/transformers `MIGRATION_GUIDE_V5.md`, issue #42556).
The case `tf_bin_fp16` was affected the same way. Real
`pytorch_model.bin.index.json` files are still covered by the Hub sample:
6 of the 394 files are `.bin` indexes (5 standard names, 1 variant), and none
had a finding above INFO.

## Reported, not graded

- **Hub sample.** The safetensors list returned 1,000 models and the
  diffusers list 200. 394 files from 360 models were downloaded; 22 gated
  models were skipped; 6 files were over the 30 MB cap and not downloaded
  (very large mixture-of-experts indexes, for example `moonshotai/Kimi-K3`
  and `nvidia/Kimi-K2.5-NVFP4`). Every downloaded file holds a `weight_map`
  (0 without). 57 of the 394 sit in a sub-folder of their repository
  (mostly diffusers `text_encoder/` and `transformer/`), but their shard
  names are bare filenames, so STI005 never fired.
- **`metadata` keys** on the Hub: `total_size` only 315, `total_parameters`
  and `total_size` 67, none 10, `format` 1, and `format`, `total_parameters`,
  `total_shards`, `total_size` 1. The scanner never reads `metadata`, so
  none of these affect a result.
- **`total_size`** equals the sum of tensor bytes in the shards in all five
  writer cases (672,768 bytes).
- **huggingface_hub's index** puts a shared-tensor note in `metadata`
  (`"transformer.wte.weight": "lm_head.weight"`), next to `total_size`.
  transformers' index has `total_parameters` and `total_size` instead.

## What this means

- For the standard names, the scanner behaves as documented on files the
  real writers produce and on every published file in the sample: no false
  alarms, and each edited case gives exactly its one rule.
- Variant-named indexes are a real coverage gap in model-file-scan's
  automatic mode. They are rare in the most-downloaded models (2 of 394
  files here) but are the documented output of `variant=` in transformers
  and diffusers. The fix (recognise `*.index.<variant>.json` in routing and
  in both directory walks) is pre-registered in
  [research/PREREG_STI_VARIANT_FIX.md](research/PREREG_STI_VARIANT_FIX.md)
  and will only be released if its own real-file check holds.

## Limits

One tiny model and one release of each writer. The Hub sample is the most
downloaded non-gated models on one day, not a random sample. A clean result
on a published file says our rules found nothing, not that the file or its
loader is safe. This check touched no live system beyond public downloads
in setup, and it tests our own scanner only.
