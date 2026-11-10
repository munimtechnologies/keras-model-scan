# Pre-registration: torch archive files on the Hugging Face Hub (job pt2-census-v1)

Written 2026-11-10, before the job runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

**Measurement only.** Nothing in this job changes the scanner. It uses the
released keras-model-scan v0.58.0 (model_file_scan 0.14.0, pickle_model_scan
0.7.0) unchanged.

## Why

v0.58.0 added `.torchscript`, `.ptl` and `.pt2` to folder walks, and the
queued job pt2-nest-v1 tests a fix for the PKL000 note that honest
`torch.export` files get on a member that is itself a zip. Both changes were
tested on files we wrote with torch's own writers. This job asks two
questions about files other people actually publish:

1. How common are these three formats among the most downloaded models?
2. What does v0.58.0 report on a sample of published files, and is the
   nested-zip note (the pt2-nest gap) seen in the wild?

## Method (research/pt2-census/)

- `fetch_hub_archives.py` (setup, network): Hugging Face's public model list
  API, sorted by downloads, `full=true`: models tagged `pytorch` (up to
  10 pages of 1,000), tagged `executorch` (up to 3 pages) and all models (up
  to 2 pages). For each open (not gated, not private) model it records which
  extensions its file list has. For each `.pt2` / `.torchscript` / `.ptl`
  file (first 150, most downloaded models first) one Range request reads
  64 bytes and the size. Zip files of at most 25 MB are downloaded (up to 10
  `.pt2` and 10 TorchScript-family files, distinct models first). For up to
  25 larger zip files, only the zip central directory and the first 4 bytes
  of up to 12 chosen members are read through Range requests.
- `census_scan.py` (run, no network): scans each downloaded file with
  v0.58.0's `model_file_scan.scan_path`, lists its members with Python's
  `zipfile` (names and first 4 bytes), and grades the rows below.
- Nothing is unpickled, imported or loaded. No authentication. One request
  at a time with pauses.

A peek on 2026-11-10 at the 20 most downloaded `executorch` models and the
40 most downloaded `ultralytics` models (API listing only) found `.pte`
files in all 20 ExecuTorch repos and no `.pt2`, `.ptl` or `.torchscript`
file in any of the 60. That peek informed R2 and is not part of the data.

## Rows (all predicted to hold)

| Row | Prediction |
|---|---|
| R1 | Among open models in the `pytorch` list (at least 1,000 needed), fewer than 0.5% have a `.pt2` file, and fewer than 0.5% have a `.torchscript` or `.ptl` file |
| R2 | Among open models in the `executorch` list (at least 20 needed), more than 90% have a `.pte` file and fewer than 5% have a `.pt2` file |
| R3 | Every downloaded `.torchscript` / `.ptl` file that is a zip gets exactly one PKL040 from v0.58.0, nothing at HIGH or above, and no scanner error |
| R4 | Every downloaded `.pt2` file gets nothing at HIGH or above and no scanner error |
| R5 | At least half of the downloaded `.pt2` files get a PKL000 LOW on a member whose first four bytes are `PK\x03\x04` (a zip inside the archive: the gap pt2-nest-v1 addresses) |

R3 needs at least 3 such files, R4 and R5 at least 3 `.pt2` files;
otherwise the row is reported as **untestable**, not as held.

## Recorded without prediction

Per-list extension counts (`.pt2 .torchscript .ptl .pte .pt .pth .bin .ckpt
.safetensors .onnx .gguf .tflite`), the first-bytes kind of every sampled
file, each downloaded file's findings, PKL000 notes by member role,
PKL000 notes on `data/weights/` or `data/constants/` members starting with
byte 0x80 (pt2-nest-v1's diagnostic row D1, seen in the wild), and any
native-library members (`.so .dll .dylib .cubin .fatbin .ptx`) inside a
`.pt2` (AOTInductor packages carry compiled code; v0.58.0 has no rule for
it).

## What follows from the result (fixed now)

- This job ships nothing to the scanner. The results are published under
  `research/pt2-census/results/` with a short report, whatever they show.
- If R5 holds, the report says the pt2-nest gap occurs in published files.
- If native-library members are found in published `.pt2` files, a rule
  for them gets its own pre-registration before any code changes.
- If R3 or R4 fails, the failing files are listed and the cause is
  investigated in a new pre-registered job.

## Limits

One day's rankings; the API's `pytorch` tag and download counts as given;
files of 25 MB or less are scanned whole, larger ones only listed; a static
scanner reports what is in a file, not whether a program is safe.
