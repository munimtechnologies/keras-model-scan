# Pre-registration: does the pickle scanner read every pickle the loader reads?

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 9 November 2026 (UTC), before job `legacy-torch-v1` runs. Job code:
[research/legacy-torch/](legacy-torch/). The new unit-test module
(`test_pickle_model_scan_streams.py`) is published only with the fix,
because a test file in this repository runs against released code.

## The gap, found by reading our own code

`torch.save(obj, f, _use_new_zipfile_serialization=False)` writes PyTorch's
legacy format. It was the default before PyTorch 1.6, `torch.load` still reads
it, and older Hugging Face `pytorch_model.bin` files use it. PyTorch's own
`_legacy_save` writes **five pickles back to back** and then the raw tensor
storage:

1. the magic number `0x1950A86A20F9469CFC6C` (15 bytes at protocol 2:
   `80 02 8a 0a 6c fc 9c 46 f9 20 6a a8 50 19 2e`),
2. the protocol version `1001`,
3. a `sys_info` dict,
4. the object itself (the state_dict or checkpoint, with every import),
5. the sorted storage keys.

`_legacy_load` unpickles all five, each with a fresh unpickler, and then
reads the storage as raw bytes (`torch/serialization.py`).

`model-file-scan` sends `.pt`, `.pth` and `.bin` files to `pickle_model_scan`.
Its `_walk_pickle` (0.4.0, release v0.54.0) makes one `_walk_stream` call,
and that call ends at the first STOP opcode. **So on a legacy-format file it
reads only the 15-byte magic-number pickle and reports the file clean
without seeing the object's imports.** Files written with several
`pickle.dump` calls (read back with repeated `pickle.load`) have the same
problem from their second pickle on. The 6 November check
(REALFILE_CHECK_WALK_NAMES_2026-11.md) reported its legacy-format torch file
as "clean". That was true but empty: a clean result on an honest file cannot
tell a full read from a 15-byte one.

## The fix (pickle_model_scan 0.5.0)

After a stream reaches STOP, `_walk_pickle` walks the next one with a fresh
memo:

- when the first pickle is torch's magic number: exactly five pickles in all
  (then raw storage follows, which torch reads raw, whatever its bytes look
  like). A legacy file that ends sooner gets `PKL000` LOW (truncated);
- otherwise: while the next bytes open a protocol 2-5 pickle (`80 02`-`80 05`),
  up to 4,096 pickles (then `PKL000` LOW).

`pickle_walk()` gains the keys `streams` and `torch_legacy`. Nothing else
changes. No new rule is added and no severity changes. `model_file_scan.py`
is not touched by this job; its version is bumped when the fix is released.

## What the job does

Sealed container, CPU only, network only during setup. Base = tag v0.54.0
untouched (`pickle_model_scan` 0.4.0). Tree = the same tag patched to 0.5.0.
Each scanner version runs in its own process.

- **Writers (honest files only):** T1 a `state_dict` of a small
  `nn.Sequential` (legacy format, protocol 2, `pytorch_model.bin`); T2 a
  pytorch/examples-style checkpoint dict with an SGD-momentum optimizer state
  (legacy, `checkpoint.pth`); T3 T1 at `pickle_protocol=4` (legacy,
  `model_p4.pt`); T4 tensors of float16, bfloat16, int64, bool and uint8,
  plus a view that shares storage (legacy, `tensors.pt`); Z1 T1 in the
  default zip format (control); M1/M2 three `pickle.dump` calls into one file
  (a dict, an OrderedDict, a date and a Decimal) at protocol 4 and 2;
  S1 one `pickle.dump` (control); J1 a `joblib.dump` with a numeric and an
  object array (control).
- **Ground truth from the loaders, on these files only:** `torch.load`
  (`weights_only=False`, needed to pass a pickle module; our own files, in
  the sealed container) and a `pickle.load` loop, through a recording pickle
  module that logs every `find_class` call and the file offset where each
  pickle the loader reads ends. torch resolves `*Storage` names itself
  before they reach `find_class`, so those are not in the ground truth.
- **Hub census (static only, nothing is loaded):** the 1,000 most downloaded
  public models tagged `pytorch`. One 64-byte Range request per top-level
  `pytorch_model.bin`, then one other `*.bin/.pt/.pth/.ckpt` per model while
  a budget of 500 headers lasts. Each header is classed legacy / zip / other
  pickle / other. Up to 12 legacy files of 25 MB or less are downloaded and
  scanned as bytes by both versions.

## Predictions (graded rows)

| # | prediction |
|---|---|
| P1 | the patch applies once (docstring, version, `_walk_pickle`, `pickle_walk` keys), a second pass changes nothing, no other line is lost, and the result compiles |
| V1 | base `pickle_model_scan` 0.4.0, tree 0.5.0; `model_file_scan` 0.12.1 in both |
| S1 | the whole suite passes on the patched tree: 0 failures, 0 errors, at least 1,350 tests |
| S2 | the new test module alone: exit 0, exactly 15 tests |
| W1 | all nine writer files are written |
| G1 | ground truth is sound: on T1-T4, `torch.load` reads exactly 5 pickles, the header is torch's magic number, and the imports include `collections OrderedDict` and `torch._utils _rebuild_tensor_v2` |
| B1 | **the diagnosis** (0.4.0 on T1-T4): it reads exactly the first pickle the loader reads, resolves none of the loader's imports, and reports no finding |
| B2 | 0.4.0 on M1/M2: it reads exactly the first pickle and misses at least one import of the later ones |
| F1 | 0.5.0 on T1-T4: `torch_legacy` true, 5 streams, and the walk ends exactly where the loader's fifth pickle ends |
| F2 | 0.5.0 resolves every import the loader asked for, on all 8 files with ground truth (T1-T4, Z1's `data.pkl`, M1, M2, S1) |
| F3 | 0.5.0 on M1/M2: 3 streams, ending exactly where the loader's last pickle ends |
| F4 | 0.5.0 on all nine honest files: nothing above LOW, and `model-file-scan` exits 0 on each |
| C1 | controls Z1, S1, J1: 0.4.0 and 0.5.0 give the same findings and the same walk (imports, stop, unresolved, arrays, nested pickles, rules) |
| E1 | `model-file-scan` on the folder of all nine files: exit 0, nine files scanned |
| H1 | at least 100 `pytorch_model.bin` headers are read |
| H2 | at least 5% of them are legacy format |
| H3 | 0.5.0 on each downloaded legacy Hub file: `torch_legacy`, 5 streams, no `PKL000` |
| H4 | on the same files 0.4.0 resolves no import and is clean; 0.5.0 resolves at least 2 distinct imports |
| H5 | 0.5.0 raises nothing above MEDIUM on them |

H3-H5 are "not run" (not passed) if no legacy Hub file of 25 MB or less is
found. **Release rule: the fix ships only if P1 V1 S1 S2 W1 G1 F1 F2 F3 F4 C1
E1 all pass** (`release_rows_all_pass` in `legacy_summary.json`). B1, B2 and
H1-H5 are graded and reported, but they do not gate the release.

## Reported, not graded

Per-file coverage (bytes 0.4.0 read / bytes of pickle the loader reads), the
untouched v0.54.0 suite result, writer versions, and for the Hub: legacy /
zip / other counts, and the rank, model, size and last-modified date of each
legacy file.

## Limits, stated before the run

- A protocol 0 or 1 pickle written after another one is not followed. Python
  writes a PROTO header only from protocol 2 on. Legacy torch files at
  protocol 0/1 are still walked, because the magic number decides.
- The pre-2017 legacy **tar** layout (torch < 0.1.10) is not covered.
- One release of each writer, tiny models, and a Hub list of the most
  downloaded models on one day, not a random sample. Only files of 25 MB or
  less are scanned whole.
- This checks our own scanner's coverage on honest files. It tests no loader
  for flaws, crafts no hostile file, and touches no live system beyond
  public downloads during setup.
