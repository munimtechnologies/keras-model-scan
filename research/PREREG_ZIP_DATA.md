# Pre-registration: raw tensor storages in a torch.save zip are not pickles (job `zip-data-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Written 9 November 2026 (UTC), before the job runs. Job code:
[research/zip-data/](zip-data/). The new unit-test module
(`test_pickle_model_scan_zip_storage.py`, 10 tests) is published only if and
when the fix ships, because a test file in this repository runs against
released code.

## Why

Job zip-storage-v1 ([zip-storage/RESULTS_ZIP_STORAGE_2026-11.md](zip-storage/RESULTS_ZIP_STORAGE_2026-11.md))
confirmed that `pickle_model_scan` walks any zip member whose first byte is
0x80 as a pickle. In a zip-format PyTorch file that includes the raw tensor
storages `<prefix>/data/<key>`, which `torch.load` copies as raw bytes and
never unpickles. When a storage happens to start with 0x80, the scanner
reports a false `PKL000 LOW` ("could not be fully parsed", that is, damaged).
This happens with BatchNorm's `num_batches_tracked` after 128 batches, with 3 of
817 storages in trained published files, and with 98 of 3,200 in freshly
initialised ones.

## The fix: `pickle_model_scan` 0.6.0 (on top of release v0.56.0)

- `_torch_storage_members(names)`: for every prefix that has
  `<prefix>/data.pkl`, the members `<prefix>/data/<key>` with exactly one path
  part after `data/`.
- `scan_zip` skips **only the first-byte (0x80) sniff** for those members. A
  member with a pickle extension, every `data.pkl`, and every member of a zip
  without `<prefix>/data.pkl` are read exactly as before. No rule, severity
  or other module changes. `model-file-scan` gets a patch version bump when
  this ships.

## The job

Sealed container, CPU only. Network is used only in setup. Base = tag
v0.56.0 untouched (`pickle_model_scan` 0.5.0, `model-file-scan` 0.13.1).
Tree = the same tag patched to 0.6.0. Each version scans every file in its own
process. Local files are written by torch itself with the same writers and
seeds as zip-storage-v1: `bn_127/128/129/384.pt`, 200 MLP state_dicts, a
TorchScript file, a `torch.export` `.pt2` (reported only), plus two non-zip
controls (a legacy-format `bn_128` and a plain `pickle.dump`). Ground truth
is `torch.load(weights_only=True)` on our own files. Published files are the
zip-format `pytorch_model.bin` of the most downloaded `pytorch` models on the
Hugging Face Hub, up to 140 MB each, 50 files or 1.5 GB in all. They are read
only as bytes. Which members are storages is computed in the check from
zipfile's name list, by code independent of the patch.

## Rows

Release rule: **P1 V1 S1 S2 W1 G1 F1 F2 F3 C1 E1 must all hold.**

| # | prediction |
|---|---|
| P1 | The patch applies once (docstring, version, helper, scan_zip). A second pass is a no-op, no line is lost, and the result compiles. |
| V1 | base pms 0.5.0, tree 0.6.0; model-file-scan 0.13.1 in both |
| S1 | The full suite passes on the patched tree and runs exactly the base suite's count + 10 tests. |
| S2 | The new module alone: exit 0, exactly 10 tests. |
| W1 | All 4 bn files, 200 MLP files and the TorchScript file load back, and both controls are written. |
| G1 | `torch.load` gives `num_batches_tracked` = N. In bn_128 and bn_384 exactly one 8-byte storage starts with 0x80, and its bytes are N as a little-endian int64. bn_127 and bn_129 have no 8-byte storage that starts with 0x80. |
| F1 | 0.6.0 reports no finding in any storage member of any local zip file. |
| F2 | On every local and published file, the 0.6.0 findings equal the 0.5.0 findings minus those in storage members (same rule, severity and location, same counts). |
| F3 | TorchScript `data.pkl` is still read: its findings are identical in both versions and not empty. |
| C1 | The non-zip controls get identical findings in both versions. |
| E1 | `model-file-scan --json` (tree) exits 0 with no finding on bn_128.pt and bn_384.pt. |

Graded, not gating:

| # | prediction |
|---|---|
| B1 | 0.5.0 reports exactly one `PKL000 LOW` in storage members of bn_128 and bn_384, and none on bn_127 and bn_129 (zip-storage-v1 again). |
| H1 | At least 30 published zip-format files are scanned by both versions. |
| H2 | 0.6.0 reports no finding in any storage member of any published file. |
| H3 | 15% to 85% of the published files get at least one 0.5.0 finding in a storage member. |
| H4 | 0.2% to 0.6% of published storages start with 0x80 (1 in 256 is 0.39%). |
| H5 | On every zip file, the storage members with a 0.5.0 finding are exactly the storages that start with 0x80. |

Reported: the 0x80 count among local storages, the `.pt2` findings in both
versions, the untouched base suite result, and the list of published files.

## Limits

- Only the first-byte sniff is changed. Nested zips, compressed members and
  `.pt2` archives (no `data.pkl`) are out of scope; they are queued as
  separate checks. TorchScript's `PKL003 MEDIUM` on `__torch__` names is
  also queued separately.
- One release of torch as the writer, one day's Hub ranking (not a random
  sample), files up to 140 MB.
- This checks our own scanner on honest files. It crafts no hostile file,
  tests no loader for flaws, and touches no live system beyond public
  downloads during setup.
