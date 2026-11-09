# Pre-registration: tensor storages that start with byte 0x80 (job zip-storage-v1)

Written 2026-11-09, before the job runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Text CC BY 4.0, code Apache-2.0.

## What we read in our own code

`pickle_model_scan` 0.4.0 (release v0.54.0, model-file-scan 0.12.1) opens a
zip-format PyTorch file in `scan_zip` and walks a member as a pickle when its
name ends in a pickle extension, when it is `data.pkl`, **or when its first
byte is 0x80** (`member[:1] == b"\x80"`).

PyTorch's loader reads things differently (`torch/serialization.py`, `_load`
and `load_tensor` on main, read 2026-11-09). `torch.load` unpickles only
`<prefix>/data.pkl`. Each tensor's storage is a separate member
`<prefix>/data/<key>`, which it copies as raw bytes with
`get_storage_from_record(f"data/{key}", ...)` (or slices from an mmap). Those
bytes never go to an unpickler.

So when a storage's first byte happens to be 0x80, the scanner walks raw
tensor data as if it were a pickle. A natural case: BatchNorm's
`num_batches_tracked` is an int64 scalar stored little-endian in its own
8-byte storage. After 128 training batches (or 384, 640, ...) that storage is
`80 00 00 00 00 00 00 00`. The walk reads PROTO 0, then hits byte 0x00,
which is not an opcode. We expect `PKL000 LOW` "Pickle stream could not be
fully parsed" on an honest checkpoint. The agent skill tells agents that
PKL000 means "truncated or damaged file", which would be wrong here. For
random float32 weights the first byte is close to uniform, so about 1 in 256
storages should start with 0x80.

## The job (measurement only; no code is changed)

- Setup (network): the v0.54.0 source as `base/`, CPU torch, and up to 160
  published `pytorch_model.bin` files in zip format: list A is
  hf-internal-testing models (at most 10 MB each), list B is the 1,000 most
  downloaded `pytorch` models (at most 25 MB each), with at most 600 MB in
  total. Downloads use public URLs and no authentication. Hub files are only
  ever read as bytes.
- Run (no network): torch writes honest files: `bn_<N>.pt` (a tiny
  Conv2d + BatchNorm2d + Linear state_dict after N = 127, 128, 129 and 384
  training-mode forward passes), 200 seeded 8-layer MLP state_dicts (3,200
  random float32 storages), a TorchScript file and a torch.export `.pt2`.
  Ground truth for each state_dict is `torch.load(weights_only=True)` on our
  own files. The released scanner's `scan_file` then runs on every file, and
  each finding is assigned to the member it names.

## Rows (graded)

| row | prediction |
|---|---|
| P0 | base is pickle_model_scan 0.4.0 and model-file-scan 0.12.1 |
| R1 | `bn_128.pt` and `bn_384.pt`: the 8-byte `num_batches_tracked` storage starts with 0x80, torch.load returns N, and 0.4.0 reports PKL000 LOW at that member |
| R2 | `bn_127.pt` and `bn_129.pt`: no finding on that member |
| R3 | every finding located in a `data/<key>` storage member (local and published) is on a storage whose first byte is 0x80 |
| R4 | no finding on `data.pkl` of any local state_dict |
| R5 | the model-file-scan CLI exits 0 on `bn_128.pt` and `bn_384.pt` at its default `--fail-on medium` (the false note is LOW, not a failure) |
| S1 | of about 3,200 random storages in the 200 MLP files, between 3 and 30 start with 0x80 (binomial mean 12.5) |
| S2 | at least 90% of those storages get a finding |
| S3 | no MEDIUM or higher finding on any MLP file |

## Rows (published files; predicted, not gating)

| row | prediction |
|---|---|
| H1 | at least 80 published zip-format files scanned |
| H2 | 5% to 60% of them have at least one storage starting with 0x80 |
| H3 | every finding on a published storage member is LOW |

The TorchScript and torch.export files, a histogram of rules by member type
and up to 15 published examples are reported, not graded.

## What follows

- If R1, R3 and R5 hold, the next run fixes the agent skill's PKL000 line
  (a PKL000 at `.../data/<n>` of a PyTorch zip is raw tensor data, not
  damage).
- The code fix is planned on top of the pending pickle_model_scan 0.5.0
  (job legacy-torch-v1), because both change the same file. In a zip that
  holds `<prefix>/data.pkl`, members `<prefix>/data/<key>` would not be
  sniffed as pickles. That is what `torch.load` does. It gets its own
  pre-registered check before any release.
- If S3 or H3 fails, the false alarm is worse than a LOW note, and the code
  fix comes first.

## Limits

Scope is our own scanner only, on honest files written by torch or published
on the Hub. Only small published files fit the caps, and the lists are one
day's rankings, not a random sample. No loader is attacked and no file is
built by hand.
