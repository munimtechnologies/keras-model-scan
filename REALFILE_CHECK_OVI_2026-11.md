# Real-file check: OpenVINO IR scanner, November 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`openvino_ir_scan.py` 0.1.1 checks an OpenVINO IR model (`.xml` plus its
`.bin` weights) without loading it. It checks every Const's `offset`/`size`
against the `.bin` length, `size` against shape times element width, shape
arithmetic that overflows, custom or Python layers and library references,
and it refuses to parse DTD/entity declarations. Its unit tests use
hand-built XML. This check asked two things. Does the scanner read what
OpenVINO really writes the same way? And does the one-command
`model-file-scan` stay quiet on an honest OpenVINO folder? (Every `.bin` also
goes to the pickle scanner, because a `.bin` can be a PyTorch pickle.) The
predictions and grading rules were fixed in advance in
[research/PREREG_OVI_REALFILE.md](research/PREREG_OVI_REALFILE.md).

**Result: all 14 graded rows held in the third run (`ovi-realfile-v3`), plus
the unit tests (U1, 29 of 29). Every pre-registered case ran. The second run
(`ovi-realfile-v2`) had held all 13 rows it could grade. Every row that ran
in both runs gave the same result.**

## Setup

- Jobs `ovi-realfile-v2` and `ovi-realfile-v3`, run on 2 November 2026 (UTC)
  in a sealed `python:3.12` container. Network was on only for `pip install`
  and for the keras-model-scan source tarball. The run steps had no network.
- Versions: openvino 2026.4.1 (build 2026.4.1-22982-e213a147257), numpy
  2.5.4, openvino_ir_scan 0.1.1. Opset module: `openvino.opset13`.
- Small models (a parameter, a MatMul with seeded random f32 weights, an Add,
  a ReLU), built with OpenVINO's Python API and written with
  `openvino.save_model`, each in its own child process. Edited copies of
  `plain-f32/model.xml` were scanned. Only E1 and E2 were also given to the
  runtime, in a child process, because the scanner's documentation says the
  runtime rejects them.
- Script: [research/ovi-realfile/realfile_check_ovi.py](research/ovi-realfile/realfile_check_ovi.py)
  (v3; v2 differs only as described in the pre-registration's second
  amendment).

The first run (`ovi-realfile-v1`, 1 November) crashed in the check script's
own process before any result was written, so nothing from it is graded. The
pre-registration was amended before v2 ran, and again before v3 ran.

## Predictions and results

| # | case | predicted | v3 got | held |
|---|---|---|---|---|
| H1 | honest models from `save_model`: plain-f32, plain-fp16, reshape-i64, string-const | no findings | no findings on all four | yes |
| E1 | largest f32 Const `offset` set to the `.bin` length | exactly {OVI003} | {OVI003}: "Const range offset 1088 size 1024 is outside the 1088-byte .bin" | yes |
| E2 | largest f32 Const `size` 4 bytes short | exactly {OVI005} | {OVI005}: "size 1020, needs 1024 (f32 16, 16)" | yes |
| E3 | largest f32 Const shape `4294967296, 4294967296` | exactly {OVI004} | {OVI004}: element count 2^64 overflows 64-bit size arithmetic | yes |
| E4 | first ReLU layer type changed to `Custom` | exactly {OVI002} | {OVI002}: layer 5 (act) | yes |
| E5 | DOCTYPE with an internal ENTITY | exactly {OVI001} | {OVI001}: parsing refused | yes |
| E6 | the `.xml` alone, no `.bin` | exactly {OVI005} | {OVI005} | yes |
| M1 | `model-file-scan` on the honest plain-f32 folder | exit 0; `.xml` clean; `.bin` nothing at MEDIUM+ | exit 0; `.xml` no findings; `.bin` one PKL000 (LOW) | yes |
| M2 | `model-file-scan` on the E1 folder | exit 1; `.xml` carries OVI003 | exit 1; `.xml` OVI003 (HIGH); `.bin` PKL000 (LOW) | yes |
| S1 | 50 honest pairs in one folder | all 50 `.xml` listed, none with a finding | 50 listed, none with a finding | yes |
| S2 | same run | no `.bin` finding at MEDIUM+ | none; histogram below | yes |
| R0 | OpenVINO `Core().read_model` on each honest file | every one loads | all four loaded | yes |
| R1 | `read_model` on E1 | rejected, no crash | rejected: "Incorrect weights in bin file!" | yes |
| R2 | `read_model` on E2 | rejected, no crash | rejected: "Attribute and shape size are inconsistent for Const op!1020, 1024, 1024" | yes |
| U1 | published `test_openvino_ir_scan.py` in the same container | all pass | 29 of 29 passed | yes |

**v2 compared with v3.** v2 graded 13 rows. H1 and R0 covered three models,
because string-const was not built, and E4 did not run. Every row that ran
in both runs gave the same result, with the same evidence text, and the S2
histogram was identical. The two v2 gaps:

- **string-const.** In v2 the child process that builds this model ended on
  signal 11 inside `opset13.constant(...)`, called with a numpy array of
  dtype `<U5`, before anything was saved. This is a known OpenVINO bug,
  [openvinotoolkit/openvino#23611](https://github.com/openvinotoolkit/openvino/issues/23611),
  fixed by [PR #38942](https://github.com/openvinotoolkit/openvino/pull/38942)
  (merged 30 October 2026, milestone 2026.5). It happens while building a
  model from the caller's own data, not while reading a file, and it is not
  a finding of this check. v3 built the same constant through
  `openvino.Tensor(array)` and `op.Constant(tensor)`. That worked, and the
  model was scanned and loaded.
- **E4.** OpenVINO's IR writer spells the layer type `ReLU`, but the v2
  anchor was `type="Relu"`. That was our mistake. v3 accepted either
  spelling, found `type="ReLU"`, and the prediction held.

## What OpenVINO wrote for a string constant (reported, not predicted)

For the constant `["alpha", "beta", "gamma"]`, the Const element was
`element_type="string" shape="3" offset="0" size="34"`, and the 34 bytes in
the `.bin` were:

```
03000000 00000000 05000000 09000000 0e000000 616c706861 62657461 67616d6d61
count=3  0        5        9        14       "alpha"    "beta"   "gamma"
```

That is a 32-bit element count, then count + 1 32-bit offsets into the
character data that follows, then the characters. The total is
4 + 4 x 4 + 14 = 34 bytes, which matches `size`. `openvino_ir_scan` 0.1.1
range-checks a string Const's `offset`/`size` against the `.bin` length. It
does not check the packed header: whether the count matches the shape, and
whether the offsets are in order and inside `size`. A rule for that would
need its own pre-registration and a real-file check before it ships. It is
noted here as a possible next step for the scanner, not as a result.

## The one silent `.bin` (reported, not predicted)

**S2 histogram, verbatim (v2 and v3):** `{"PKL000 LOW": 49}` over 50 `.bin`
files. Nothing reached MEDIUM, so the default CI gate (`--fail-on medium`)
passes an honest OpenVINO folder. In 49 files the pickle scanner gave one LOW
note (the bytes are not a pickle it can parse). The 50th, `m12.bin`, got no
finding at all. Its first bytes are `2e b3 df bb 06 e8 85 3f`. `0x2e` is the
pickle `STOP` opcode, so the pickle scanner reads a pickle that stops at its
first byte and has nothing in it, and so has nothing to report. That is a
correct reading. Loading such a "pickle" would fail with an empty stack and
run nothing. Seeded random weights start with `0x2e` about once in 256
files, so this is expected now and then.

## Limits

- One OpenVINO release, tiny random-weight models, one file per case. This
  is not a false-positive rate on published OpenVINO models.
- The edited files test the scanner's rules, not OpenVINO. R1 and R2 only
  confirm that the runtime rejects the two cases the scanner's documentation
  says it rejects, with an error and no crash.
- One string constant of three short ASCII strings. Other string layouts
  (empty strings, non-ASCII, larger shapes) were not written.
