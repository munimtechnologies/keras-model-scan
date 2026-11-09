# Real-file check: does the pickle scanner read every pickle the loader reads? (job `legacy-torch-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Graded 9 November 2026 (UTC) against the pre-registration
[research/PREREG_LEGACY_TORCH.md](research/PREREG_LEGACY_TORCH.md), which was
published before the job ran. Job code: [research/legacy-torch/](research/legacy-torch/).
Raw results: [research/legacy-torch/results/](research/legacy-torch/results/).

**Result: 19 of 19 predictions held, including all 12 release rows.** The fix
(`pickle_model_scan` 0.5.0) ships in release v0.56.0.

## The gap

`torch.save(obj, f, _use_new_zipfile_serialization=False)` writes PyTorch's
legacy format: five pickles back to back (torch's magic number, the protocol
version, a `sys_info` dict, the object, the storage keys), then raw tensor
bytes. It was the default before PyTorch 1.6, and `torch.load` still reads it.
`pickle_model_scan` 0.4.0 stopped at the first STOP opcode, so on a legacy file
it read only the 15-byte magic-number pickle and reported the file clean
without seeing a single import of the model.

## What the job did

A sealed container with CPU only. Network was used only during setup.
Base = tag v0.54.0 untouched (`pickle_model_scan` 0.4.0); tree = the same tag
with the 0.5.0 patch. Each version ran in its own process. torch 2.15.0+cpu,
joblib 1.6.0 and numpy 2.5.4 wrote nine honest files. Ground truth came from
`torch.load` / `pickle.load` on those files only, through a recording pickle
module that logs every `find_class` call and where each pickle ends.
Published Hub files were only read as bytes, never loaded.

## Graded rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once, second pass no-op, nothing lost, compiles | held |
| V1 | base pms 0.4.0, tree 0.5.0, model-file-scan 0.12.1 in both | held |
| S1 | whole suite passes on the patched tree, at least 1,350 tests | held: 1,396 ran, 0 failures, 0 errors (3 skipped) |
| S2 | new test module alone: exit 0, exactly 15 tests | held |
| W1 | all nine writer files written | held |
| G1 | `torch.load` reads exactly 5 pickles on T1-T4, magic-number header, OrderedDict + `_rebuild_tensor_v2` | held |
| B1 | **the diagnosis**: 0.4.0 on T1-T4 reads only the first pickle, resolves none of the loader's imports, reports nothing | held on all 4 |
| B2 | 0.4.0 on the multi-`pickle.dump` files M1/M2 reads only the first pickle and misses later imports | held (missed 3 and 4 imports) |
| F1 | 0.5.0 on T1-T4: legacy detected, 5 streams, walk ends exactly where the loader's fifth pickle ends | held on all 4 |
| F2 | 0.5.0 resolves every import the loader asked for, on all 8 files with ground truth | held, 0 missing |
| F3 | 0.5.0 on M1/M2: 3 streams, ending where the loader's last pickle ends | held |
| F4 | 0.5.0 on all nine honest files: nothing above LOW, CLI exit 0 | held (no finding at all) |
| C1 | controls (zip-format torch file, single pickle, joblib file): same findings and same walk in both versions | held |
| E1 | CLI on the folder of all nine files: exit 0, nine files scanned | held |
| H1 | at least 100 `pytorch_model.bin` headers read on the Hub | held: 500 |
| H2 | at least 5% of them are legacy format | held: **79 of 500 (15.8%)** |
| H3 | 0.5.0 on each downloaded legacy Hub file: legacy detected, 5 streams, no PKL000 | held on 4 files |
| H4 | on those files 0.4.0 resolves no import and is clean; 0.5.0 resolves at least 2 | held: 0 vs 3-4 |
| H5 | 0.5.0 raises nothing above MEDIUM on them | held (no finding) |

## Coverage on our own files (bytes of pickle the loader reads)

| file | what | loader's pickle bytes | 0.4.0 read | 0.5.0 read |
|---|---|---|---|---|
| T1 | legacy `state_dict`, protocol 2 | 758 | 15 (2.0%) | 758 |
| T2 | legacy checkpoint dict with SGD momentum | 1,563 | 15 (1.0%) | 1,563 |
| T3 | legacy, `pickle_protocol=4` | 674 | 24 (3.6%) | 674 |
| T4 | legacy, five dtypes + a shared-storage view | 987 | 15 (1.5%) | 987 |
| M1 | three `pickle.dump` calls, protocol 4 | 190 | 41 (21.6%) | 190 |
| M2 | three `pickle.dump` calls, protocol 2 | 228 | 45 (19.7%) | 228 |
| S1 | one `pickle.dump` (control) | 90 | 90 | 90 |

## Published files (static census, nothing loaded)

The 1,000 most downloaded public models tagged `pytorch` on the Hugging Face
Hub (one day's ranking, 9 November 2026). 853 have a top-level
`pytorch_model.bin`. The first 500 of those headers were read with 64-byte
Range requests: **421 zip format, 79 legacy format (15.8%)**. Legacy files
include `openai-community/gpt2`, `google-bert/bert-base-uncased`,
`google-t5/t5-small`, `FacebookAI/xlm-roberta-base`, `FacebookAI/roberta-base`
and `distilbert/distilbert-base-uncased`. The full list with rank, size and
last-modified date is in `results/legacy_summary.json`.

The four legacy files of 25 MB or less (`sshleifer/tiny-gpt2`,
`julien-c/dummy-unknown`, `google/bert_uncased_L-2_H-128_A-2`,
`DeepChem/ChemBERTa-77M-MLM`) were downloaded and scanned as bytes. 0.4.0 read
15 bytes of each and reported it clean with no import seen. 0.5.0 read 5,530
to 14,292 bytes of pickle per file, resolved 3-4 imports each, and raised
nothing.

## What this does and does not mean

- It is a coverage gap in **our own scanner**, now closed. PyTorch is not
  claimed to have a bug. None of these published files is suspected of
  anything; they are honest files we read as bytes.
- Many of these repos also ship `model.safetensors`, which `transformers`
  prefers when present, so a legacy `pytorch_model.bin` is not necessarily
  what users load. We did not check this per repo.
- `torch.load(weights_only=True)` (the default since PyTorch 2.6) restricts
  what a legacy file can import, but a CI gate that scans files before anyone
  loads them should still see what is in them.

## Limits

- A protocol 0 or 1 pickle written after another one is not followed (Python
  writes a PROTO header only from protocol 2). Legacy torch files at protocol
  0/1 are still walked, because the magic number decides.
- The pre-2017 legacy **tar** layout (torch < 0.1.10) is not covered.
- One release of each writer, tiny models, a census of one day's most
  downloaded models (not a random sample), and the header budget stopped at 500
  of 853 files.
- This checks our own scanner's coverage on honest files. It tests no loader
  for flaws, crafts no hostile file, and touched no live system beyond public
  downloads during setup.
