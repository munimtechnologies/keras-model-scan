# Real-file check: raw tensor storages in a torch.save zip are not pickles (job `zip-data-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Graded 10 November 2026 (UTC) against the pre-registration
[research/PREREG_ZIP_DATA.md](research/PREREG_ZIP_DATA.md), which was published
(commit 021b274) before the job ran. Job code: [research/zip-data/](research/zip-data/).
Raw results: [research/zip-data/results/](research/zip-data/results/).

**Result: all 11 release rows held, so `pickle_model_scan` 0.6.0 ships in
release v0.57.0 (`model-file-scan` 0.13.2). Of the 6 graded, non-gating rows,
4 held and 2 failed (H1: 21 published files, not 30; H4: 0.68% of published
storages start with 0x80, just above the predicted 0.2-0.6%).**

## The change

In a zip-format PyTorch file, `torch.load` unpickles only `<prefix>/data.pkl`
and copies each tensor storage `<prefix>/data/<key>` as raw bytes. Up to 0.5.0,
`scan_zip` also walked any member whose first byte is 0x80 as a pickle, so a
storage whose raw data happened to start with 0x80 got a false `PKL000 LOW`
("could not be fully parsed", that is, damaged) on an honest file
([research/zip-storage/RESULTS_ZIP_STORAGE_2026-11.md](research/zip-storage/RESULTS_ZIP_STORAGE_2026-11.md)).

0.6.0 skips **only that first-byte sniff**, and only for members
`<prefix>/data/<key>` (exactly one path part after `data/`) of a zip that
holds `<prefix>/data.pkl`. Every `data.pkl`, every member with a pickle
extension, and every member of a zip without a `data.pkl` is read exactly as
before. No rule, severity or other module changed.

## Rows

Release rule: P1 V1 S1 S2 W1 G1 F1 F2 F3 C1 E1 must all hold.

| # | prediction | result |
|---|---|---|
| P1 | patch applies once, second pass no-op, nothing lost | held (978 -> 1,014 lines) |
| V1 | base pms 0.5.0 / tree 0.6.0, model-file-scan 0.13.1 in both | held |
| S1 | full suite passes on the tree with base count + 10 | held: 1,431 tests (base 1,421), 0 failures, 3 skipped |
| S2 | new module alone: exit 0, 10 tests | held |
| W1 | all local files written by torch load back | held: 208 files |
| G1 | `num_batches_tracked` storage is N as little-endian int64; 0x80 only for N = 128, 384 | held (`80 00 ..`, `80 01 ..`) |
| F1 | 0.6.0: no finding in any storage member of any local zip | held |
| F2 | on every file, 0.6.0 findings = 0.5.0 findings minus storage-member findings | held: 229 files, no other difference |
| F3 | TorchScript `data.pkl` is still read, same findings in both | held (2 x `PKL003 MEDIUM`, see below) |
| C1 | non-zip controls (legacy torch file, plain pickle) unchanged | held |
| E1 | `model-file-scan --json` exits 0 with no finding on bn_128 / bn_384 | held (0.5.0 gave 1 finding each) |
| B1 | 0.5.0 gives exactly one `PKL000 LOW` on bn_128 / bn_384 storages, none on 127 / 129 | held |
| H1 | at least 30 published files scanned | **failed: 21** |
| H2 | 0.6.0: no finding in any published storage member | held |
| H3 | 15-85% of published files get a 0.5.0 storage finding | held: 8 of 21 (38%) |
| H4 | 0.2-0.6% of published storages start with 0x80 | **failed: 25 of 3,658 (0.68%)** |
| H5 | on every zip, storages with a 0.5.0 finding = storages starting with 0x80 | held |

## Why H1 and H4 failed

- **H1:** the download budget (1.5 GB in all, 140 MB per file) ran out after
  21 files, because the most downloaded zip-format `pytorch_model.bin` files
  average about 72 MB. 1.5 GB / 50 MB was wrong arithmetic in the
  pre-registration, not a fault in the job. 853 of the top 1,000 `pytorch`
  models had a candidate file.
- **H4:** 25 of 3,658 published storages (0.68%) start with 0x80, against 3 of
  817 (0.37%) in zip-storage-v1. Both are near 1 in 256 (0.39%) and the
  samples overlap; we do not read anything into the difference.

## What it means in practice

8 of the 21 most downloaded zip-format `pytorch_model.bin` files we read
(38%), among them widely used sentence-transformers and timm models, got a
false "could not be fully parsed" note from 0.5.0. With 0.6.0 they get none,
and every other finding on all 229 files is unchanged. Local files written
fresh by torch hit it more often: 100 of 3,252 storages (3.1%), matching the
98 of 3,200 seen in zip-storage-v1.

## Reported, not graded

- TorchScript (`torch.jit.save`) `data.pkl`: 2 x `PKL003 MEDIUM` on
  `__torch__...` names in both versions. On an honest TorchScript file this
  fails the CLI's default `--fail-on medium` gate. It is the next queued
  check; this release does not change it.
- `torch.export` `.pt2`: one `PKL000 LOW` on `data/sample_inputs/model.pt` in
  both versions (that archive has no `data.pkl`, so it is out of this fix's
  scope). Queued separately.

## Limits

One torch release as the writer (2.15.0+cpu); one day's Hub ranking, not a
random sample; files up to 140 MB. Published files were only read as bytes.
This checks our own scanner on honest files: it crafts no hostile file, tests
no loader for flaws, and touched no live system beyond public downloads during
setup.
