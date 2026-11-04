# ModelAudit on GGUF files of the newest ggml tensor types: 8 of 8 pre-registered predictions held

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 4 November 2026 (UTC) from sealed job `gguf-xtool-v1` (run 3 November
2026, 16:31-16:34 UTC). Pre-registration, written before the run:
[research/PREREG_GGUF_XTOOL.md](research/PREREG_GGUF_XTOOL.md). Scripts:
[research/gguf-xtool/](research/gguf-xtool/).

## In one paragraph

promptfoo's ModelAudit (MIT) is an open model-file scanner that covers 42+
formats, more than any other scanner in our coverage matrix. On GGUF
files written by llama.cpp's own `gguf-py` (tag b12034), its newest PyPI
release **0.2.54** reports every tensor of type TQ2_0 (35), MXFP4 (39), NVFP4
(40), Q1_0 (41), Q2_0 (42) or F8_E4M3 (43) as an "unknown GGML type" and ends
the scan **inconclusive (exit 2)**. Its `main` branch (commit `415819f`,
21 October 2026), which carries ModelAudit PR #1909 but is not yet released,
reads ids 35-42 cleanly but still reports **43, `GGML_TYPE_F8_E4M3`**, as
unknown (exit 2). llama.cpp added that type on 29 October 2026 (PR #27512);
`GGML_TYPE_COUNT` is 44. This fails closed: no file was passed as clean that
should not have been, and nothing here is a vulnerability. It is a
compatibility gap that makes honest files inconclusive, the same kind of gap
our own `gguf_scan` 0.1.0 had ([report](REALFILE_CHECK_GGUF_TYPES_2026-11.md),
fixed in `gguf_scan` 0.2.0).

## What ran

- A sealed `python:3.12` container; network only during setup, none while
  scanning. ModelAudit's telemetry was switched off with the environment
  variables its README names.
- `rel`: `pip install modelaudit==0.2.54`.
- `main`: the same, then promptfoo/modelaudit at
  `415819fa0b58d097dd201c0fa3f41eba33431c78` installed over it with
  `--no-deps`. It installed and its GGUF scanner imported, so `main` was
  graded directly. The fallback `overlay` (0.2.54 with only main's
  `gguf_scanner.py` copied in) also ran; it is reported for completeness
  and gave the same exit codes as `main` on every file.
- Files: one GGUF per type (F32, F16, Q4_0, Q8_0, Q4_K, Q6_K, IQ4_XS, BF16,
  TQ2_0, MXFP4, NVFP4, Q1_0, Q2_0, F8_E4M3; one 2 x 256 tensor each, seeded
  random contents), one file holding all 14 tensors, and a copy of the NVFP4
  file with its type id edited to 44. All written with `gguf.GGUFWriter`
  from llama.cpp b12034's `gguf-py`.
- Each file: `modelaudit FILE --format json --output OUT.json`. An "unknown
  type" report is any match of `unknown GGML type N`.

Type tables found by importing each installed scanner:

| install | ids in `_GGML_TYPE_INFO` |
|---|---|
| 0.2.54 (PyPI) | 17 ids: 0-3, 6-15, 21, 23, 30 |
| main `415819f` | 38 ids: 0-3, 6-35, 39-42 (highest 42) |

## Results

| # | tool | case | predicted | result |
|---|---|---|---|---|
| R0 | gguf-py | read every honest file back | each tensor has the type it was written with | **held** (14 of 14 types read back with their ids) |
| A1 | 0.2.54 | F32, F16, Q4_0, Q8_0, Q4_K, Q6_K, IQ4_XS, BF16 | no unknown-type report | **held** (none; exit 0 on all 8) |
| A2 | 0.2.54 | TQ2_0, MXFP4, NVFP4, Q1_0, Q2_0, F8_E4M3 | each reports its own id as unknown, exit 2 | **held** (35, 39, 40, 41, 42, 43; exit 2 on all 6) |
| V0 | main | the scanner's type table | has 40, 41, 42, not 43 | **held** (38 ids, highest 42) |
| M1 | main | every honest file except F8_E4M3 | no unknown-type report | **held** (none; exit 0 on all 13) |
| M2 | main | the F8_E4M3 file | reports 43 as unknown, exit 2 | **held** |
| M3 | main | the file holding every type | reports only 43 as unknown | **held** (unknown: [43]; exit 2) |
| M4 | main | the NVFP4 copy with type id 44 | reports 44 as unknown (control) | **held** (exit 2) |

Nothing was "not run". No WARNING or CRITICAL finding appeared on any file
under any install.

Not graded, reported in full: on the all-types file, 0.2.54 reported ids 35,
39, 40, 41, 42 and 43 (exit 2); on the id-44 copy it reported 44 (exit 2).

What main reports for the F8_E4M3 file (from its JSON output):

```
"message": "Tensor w.f8_e4m3 uses unknown GGML type 43",
"severity": "info", "rule_code": "S902"
...
"analysis_incomplete": true,
"scan_outcome": "inconclusive",
"scan_outcome_reasons": ["gguf_structure_validation_failed"]
```

## What it means for users

- Anyone gating on ModelAudit 0.2.54 today gets exit 2 (inconclusive) on any
  GGUF that uses TQ2_0, MXFP4, NVFP4, Q1_0, Q2_0 or F8_E4M3 tensors. MXFP4 is
  the type llama.cpp added for OpenAI's gpt-oss models, so this is not only
  a corner case. The next release (release PR #1910, still open on
  4 November 2026) fixes ids 35-42.
- F8_E4M3 (43) is missing even on main. One more table entry (block size 1,
  type size 1 byte, matching `gguf-py`'s `GGML_QUANT_SIZES` at b12034) would
  close it.
- In `keras-model-scan`, `gguf_scan` 0.2.0 accepts every id below 44 and
  still flags 44 and above (GG010), checked on the same kind of files.

## Limits

One small file per type with random contents, written by llama.cpp's Python
writer, not by its quantizer. This tests how a scanner treats tensor type
ids, not its false-positive rate on published models. ModelAudit's main may
change before its next release; the commit tested is named above. One run,
one platform (Linux, Python 3.12).
