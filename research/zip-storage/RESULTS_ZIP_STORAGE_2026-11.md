# Results: tensor storages that start with byte 0x80 (job `zip-storage-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Graded 9 November 2026 (UTC) against the pre-registration
[../PREREG_ZIP_STORAGE.md](../PREREG_ZIP_STORAGE.md), which was published
before the job ran. Raw results: [results/](results/). This was a measurement
only. No code was changed.

**Result: 9 of 11 rows held. S1 failed (the 0x80 rate on freshly initialised
weights was 8 times what we predicted) and H1 failed (only 6 published files
fitted the caps).** The diagnosis holds: `pickle_model_scan` 0.4.0 / 0.5.0
treats raw tensor bytes as a pickle whenever a storage's first byte is 0x80,
and reports a false `PKL000 LOW` ("could not be fully parsed") on honest
PyTorch files. It never raised anything above LOW.

## The behaviour

In a zip-format PyTorch file, `torch.load` unpickles only `<prefix>/data.pkl`.
Each tensor's storage is a separate member `<prefix>/data/<key>` that it
copies as raw bytes. Our `scan_zip` also walks any member whose first byte is
0x80 as a pickle. When raw tensor data happens to start with 0x80, the walk
fails at the next byte and the scanner says the file may be damaged.

## Rows

| # | prediction | result |
|---|---|---|
| P0 | base is pms 0.4.0 / model-file-scan 0.12.1 | held |
| R1 | `bn_128.pt`, `bn_384.pt`: BatchNorm's `num_batches_tracked` storage is `80 00 ..` / `80 01 ..`, torch.load returns 128 / 384, and 0.4.0 reports PKL000 LOW at that member | held |
| R2 | `bn_127.pt`, `bn_129.pt`: no finding on that member | held |
| R3 | every finding on a storage member is on one starting with 0x80 | held (103 findings, local and published) |
| R4 | no finding on any local `data.pkl` | held (204 files) |
| R5 | CLI exits 0 on `bn_128.pt` / `bn_384.pt` at default `--fail-on medium` | held |
| S1 | of ~3,200 random storages in 200 MLP files, 3-30 start with 0x80 | **failed: 98 (3.06%)** |
| S2 | at least 90% of those get a finding | held: 98 of 98 |
| S3 | no MEDIUM or higher on any MLP file | held |
| H1 | at least 80 published zip-format files scanned | **failed: 6** |
| H2 | 5-60% of them have a storage starting with 0x80 | held: 2 of 6 |
| H3 | every finding on a published storage is LOW | held: 3 of 3 |

## Why S1 failed

We assumed the first byte of a float32 storage is close to uniform (1 in 256).
On **trained, published** weights that held: 3 of 817 storages (0.37%) started
with 0x80. On our **freshly initialised** MLPs it did not: 98 of 3,200 (3.06%),
57 of 1,600 bias storages and 41 of 1,600 weight storages. A likely cause,
**which we did not test**: PyTorch's default initialisation draws uniform
values with limited random bits and then subtracts the bound, which leaves
trailing zero bits in many float32 values, so the low byte is not uniform.

## What it means in practice

At 1 in 256 storages, a trained checkpoint with a few hundred tensors has
roughly even odds of at least one false `PKL000 LOW`. Untrained or freshly
initialised checkpoints get it more often. It is a LOW note and does not fail
the default CI gate, but it tells a reader the file may be damaged when it is
not. The agent skill already tells agents this (commit 31b8c72). The code fix
is to treat `<prefix>/data/<key>` members of a zip holding `<prefix>/data.pkl`
as raw data, as `torch.load` does. It gets its own pre-registered check before
any release.

## Reported, not graded

- TorchScript (`torch.jit.save`) file: 2 x `PKL003 MEDIUM` on `data.pkl` for
  `__torch__.torch.nn.modules...` names. That fails the default
  `--fail-on medium` gate on an honest TorchScript file. This is a false-positive
  candidate, queued for its own check.
- `torch.export` `.pt2` file: one `PKL000 LOW` on
  `data/sample_inputs/model.pt` (a non-pickle member read as a pickle).
- H1 failed because list A (hf-internal-testing) returned no models and the
  25 MB cap left only 6 of list B's files. That sample is too small to
  estimate a Hub-wide rate.

## Limits

Our own scanner only, on honest files written by torch 2.15.0+cpu or
published on the Hub and read as bytes. One day's rankings, not a random
sample. No loader was attacked and no file was built by hand.
