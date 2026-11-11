# Results: torch archive files on the Hugging Face Hub (job pt2-census-v1)

Graded 2026-11-11 against the pre-registration
[research/PREREG_PT2_CENSUS.md](research/PREREG_PT2_CENSUS.md), committed
before the job ran. Made with AI agents working in the name of MV2 of Munim,
Inc. Text CC BY 4.0, code Apache-2.0. Measurement only: the scanner was not
changed (keras-model-scan v0.58.0, model_file_scan 0.14.0, pickle_model_scan
0.7.0).

The job ran once in a sealed container on 2026-11-11 (00:26 to 00:29 UTC). It
used only the Hub's public model list API and anonymous Range requests, and
it never loaded or unpickled a file. Raw outputs are in
[research/pt2-census/results/](research/pt2-census/results/).

## Headline

- **No `torch.export` (`.pt2`) file, and no TorchScript (`.torchscript`) or
  PyTorch mobile (`.ptl`) file, in any of the 9,865 open models** among the
  10,000 most downloaded `pytorch`-tagged models.
- **98.7% of open `executorch`-tagged models (851 of 862) ship a `.pte`
  file, and none ships a `.pt2`.** On-device PyTorch models are published as
  ExecuTorch programs, not as `torch.export` archives.
- Across the 1,941 open models among the 2,000 most downloaded models of any
  kind, there is again no `.pt2`. One model has a `.ptl` file.

## Rows

| Row | Prediction | Result |
|---|---|---|
| R1 | among open `pytorch` models (at least 1,000), fewer than 0.5% have a `.pt2`, and fewer than 0.5% a `.torchscript` or `.ptl` | **held**: 0 of 9,865 and 0 of 9,865 |
| R2 | among open `executorch` models (at least 20), more than 90% have a `.pte` and fewer than 5% a `.pt2` | **held**: 851 of 862 (98.7%) and 0 |
| R3 | every downloaded `.torchscript`/`.ptl` zip gets exactly one PKL040, nothing at HIGH or above, no error (needs at least 3 files) | **untestable**: 1 file (and it did get exactly one PKL040 MEDIUM, nothing else) |
| R4 | every downloaded `.pt2` gets nothing at HIGH or above, no error (needs at least 3) | **untestable**: no `.pt2` found |
| R5 | at least half of downloaded `.pt2` files get the nested-zip PKL000 note (needs at least 3) | **untestable**: no `.pt2` found |

Untestable rows are not counted as held.

## File types among open models (models that have at least one such file)

| list | open models | `.bin` | `.safetensors` | `.gguf` | `.pt` | `.onnx` | `.pth` | `.ckpt` | `.tflite` | `.pte` | `.ptl` | `.pt2` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `pytorch`, top 10,000 | 9,865 | 7,718 | 4,328 | 1,052 | 452 | 381 | 228 | 36 | 13 | 4 | 0 | 0 |
| `executorch`, all 914 | 862 | 88 | 34 | 8 | 28 | 38 | 8 | 3 | 17 | 851 | 2 | 0 |
| any, top 2,000 | 1,941 | 625 | 1,265 | 419 | 54 | 188 | 34 | 14 | 7 | 1 | 1 | 0 |

## The TorchScript-family files that were found

Seven `.ptl` files in three public repositories. All seven are zip
archives. One (5.0 MB) was small enough to download and scan whole. It got
exactly one **PKL040 MEDIUM** ("TorchScript archive: treat as executable
code") and nothing else. For the other six (176 MB to 2.8 GB), only the zip
directory was read: each has a `data.pkl`, `constants.pkl`, `bytecode.pkl`
and TorchScript code members, as PyTorch's mobile writer lays them out. None
holds a native-library member (`.so`, `.dll`, `.dylib`, `.cubin`, `.fatbin`,
`.ptx`).

## What this means for the scanner

- Real-world frequency ranks the work. Among popular models, pickle-based
  `.bin` and `.pt`/`.pth` files and `.gguf` dominate. `.pte` is the on-device
  format. `.pt2` is not yet published at the top of the Hub, so the `.pt2`
  fixes (v0.59.0's nested-zip fix and the pre-registered raw-weights fix,
  [research/PREREG_PT2_WEIGHTS.md](research/PREREG_PT2_WEIGHTS.md)) matter
  for files people make and pass around themselves, not yet for the Hub's
  top-ranked models.
- Since no `.pt2` was found, no rule for AOTInductor packages (compiled code
  inside a `.pt2`) is proposed now, as the pre-registration said.

## Limits

One day's rankings, the API's tags and download counts as given, and models
counted by file extension, not by content. Gated and private models were
excluded. Files over 25 MB were listed, not scanned. A `.pt2` in a model
outside these lists, or in a dataset or Space, would not be counted.
