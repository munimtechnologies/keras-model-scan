# Real-file check: big NeMo checkpoints in nemo_container_scan (graded, released in v0.53.0)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 7 November 2026 (UTC). Pre-registration:
[research/PREREG_NEMO_BIG.md](research/PREREG_NEMO_BIG.md), committed
before job `nemo-big-v1` ran (2026-11-07 00:07 to 00:11 UTC). Raw results:
[research/nemo-big/results/nemo_summary.json](research/nemo-big/results/nemo_summary.json).

## Result

**12 of 12 graded predictions held. None were skipped. The harness reported
no scan errors.** The release rule (P1, S1, W1, R1, N1-N5 and M1) holds, so
`nemo_container_scan` 0.2.0 ships in **v0.53.0** with the job's patched files
and the new test module.

Up to 0.1.0, `nemo_container_scan` skipped any tar member larger than 256 MiB
**with no finding**. NeMo saves the weights as one `model_weights.ckpt`, so
for any model whose checkpoint is bigger than that, the pickle that
`restore_from` loads was never checked and the scan came back clean. A
smaller honest model, by contrast, got NEMO010 (medium: "this container
holds a pickle checkpoint"). The gate failed open exactly where models are
big.

0.2.0 opens the torch-save zip inside the tar in place and reads only the
zip directory and its `*.pkl` entries, so a checkpoint of any size is
checked, and `scan_file` streams the tar from disk instead of reading the
whole file into memory.

## How common is the blind spot? (row Hb)

Among the 100 most-downloaded Hugging Face repos tagged `nemo` (file-size
metadata only, read inside the job): 63 repos hold 264 `.nemo` files (245
distinct blobs).

| size of the `.nemo` file | files |
|---|---|
| up to 50 MiB | 3 |
| 50 to 256 MiB | 3 |
| 256 MiB to 2 GiB | 218 |
| over 2 GiB | 40 |

**258 of 264 files (97.7%) are larger than 256 MiB**, and 57 of the 63
repos have at least one such file. One repo (a fine-tuning run that
publishes many checkpoints) contributes many of the files, so the repo
count is the steadier number: about nine repos in ten. File size is a
stand-in for checkpoint size. NeMo writes the tar uncompressed and the
checkpoint is almost all of it (459,243,520-byte file, 458,921,226-byte
checkpoint for parakeet-tdt_ctc-110m below).

In short: on the models people actually download, 0.1.0 of this gate was
almost always silent.

## Versions

`nemo_container_scan` 0.1.0 (live `main` after v0.52.1, model-file-scan
0.12.0) and the patched 0.2.0. torch 2.15.0+cpu, numpy 2.5.4. Container
`python:3.12`; the run steps had no network. The two published models were
downloaded in the setup step at pinned revisions and read only as bytes by
`tarfile`, `zipfile` and the scanners. Nothing was unpickled, loaded or
extracted.

## Rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once to the scanner, the old test's version pin and the doc; second pass no-op; nothing lost; compiles | held |
| S1 | full unit-test suite on the patched tree | held: 1,338 run, 0 failures, 0 errors, 3 skipped |
| W1 | torch writes each checkpoint as a zip; the NeMo-layout tars hold it; w_big's checkpoint is over 256 MiB | held (280,002,005-byte checkpoint) |
| R1 | both published files at the pinned size; checkpoint starts `PK\x03\x04`; titanet's at most 256 MiB, parakeet-110m's larger | held (101,611,209 and 458,921,226 bytes) |
| N1 | w_small: 0.1.0 {NEMO010}, 0.2.0 {NEMO010} | held |
| N2 | w_big: 0.1.0 nothing, 0.2.0 {NEMO010} | held |
| N3 | w_big_gz (older gzip NeMo tars): 0.1.0 nothing, 0.2.0 {NEMO010} | held |
| N4 | nvidia/speakerverification_en_titanet_large: 0.1.0 {NEMO010}, 0.2.0 {NEMO010} | held |
| N5 | nvidia/parakeet-tdt_ctc-110m: 0.1.0 nothing, 0.2.0 {NEMO010} | held |
| M1 | 0.2.0 scans parakeet-110m under 200 MB peak RSS | held: 19.0 MB (0.1.0 used 967.8 MB) |
| T1 | 0.2.0 scans parakeet-110m in under 60 s (not gating) | held: 0.14 s (0.1.0: 1.64 s) |
| Hb | at least 20 `.nemo` files, at least half over 256 MiB (not gating) | held: 264 files, 97.7% |

Reported, not graded: a 280 MB checkpoint saved in torch's legacy
(non-zip) format gives nothing on 0.1.0 and {NEMO030} on 0.2.0, as
predicted. NEMO030 (medium) means "a pickle still too big to check", so the
gate now says so instead of passing quietly.

## Limits

- This is a coverage gap in our own CI gate, found by reading source. NeMo
  itself is not claimed to have a bug, and no loader was given planted input.
- Two published models were downloaded; the Hub census uses file sizes only.
- NEMO010 on an honest `.nemo` is expected: its weights are a pickle.
- The bigger gzip case (N3) is slower with 0.2.0 (2.9 s against 1.3 s),
  because the scanner now decompresses the stream to reach the checkpoint
  instead of giving up.
- Prior art: promptfoo's ModelAudit marks a NeMo checkpoint above 50 MB
  inconclusive instead of scanning it (fails closed; read 2026-11-06), and
  reading only a checkpoint zip's directory and pickle entries is a known
  technique. This release brings our gate up to date; it is not a new kind
  of check.
