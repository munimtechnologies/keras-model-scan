# Real-file check: OpenVINO IR scanner, November 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`openvino_ir_scan.py` 0.1.1 checks an OpenVINO IR model (`.xml` plus its
`.bin` weights) without loading it: every Const's `offset`/`size` against the
`.bin` length, `size` against shape times element width, shape arithmetic that
overflows, custom or Python layers and library references, and a refusal to
parse DTD/entity declarations. Its unit tests use hand-built XML. This check
asked whether it reads what OpenVINO really writes the same way, and whether
the one-command `model-file-scan` stays quiet on an honest OpenVINO folder
(every `.bin` also goes to the pickle scanner, because a `.bin` can be a
PyTorch pickle). The predictions and grading rules were fixed in advance in
[research/PREREG_OVI_REALFILE.md](research/PREREG_OVI_REALFILE.md).

**Result: every prediction that ran held (13 graded rows plus the unit tests,
U1). Two cases were not run, both for reasons on our side or already fixed
upstream. A third run that covers them is queued (see the end of this page).**

## Setup

- Job `ovi-realfile-v2`, run on 2 November 2026 (UTC) in a sealed
  `python:3.12` container. Network was on only for `pip install` and for the
  keras-model-scan v0.49.0 source tarball; the run steps had none.
- Versions: openvino 2026.4.1 (build 2026.4.1-22982-e213a147257), numpy
  2.5.4, openvino_ir_scan 0.1.1; opset module `openvino.opset13`.
- Small models (a parameter, a MatMul with seeded random f32 weights, an Add,
  a ReLU) built with OpenVINO's Python API and written with
  `openvino.save_model`, each in its own child process. Edited copies of
  `plain-f32/model.xml` were scanned; only E1 and E2 were also given to the
  runtime, in a child process, because the scanner's documentation says the
  runtime rejects them.
- Script: [research/ovi-realfile/realfile_check_ovi.py](research/ovi-realfile/realfile_check_ovi.py)
  (the version in the repository is v3; v2 differs only as described in the
  pre-registration's second amendment).

The first run (`ovi-realfile-v1`, 1 November) ended on a crash in the check
script's own process before any result was written, so nothing from it is
graded. The pre-registration was amended before v2 ran.

## Predictions and results

| # | case | predicted | got | held |
|---|---|---|---|---|
| H1 | honest models from `save_model`: plain-f32, plain-fp16, reshape-i64 (string-const not run, below) | no findings | no findings on all three | yes |
| E1 | largest f32 Const `offset` set to the `.bin` length | exactly {OVI003} | {OVI003}: "Const range offset 1088 size 1024 is outside the 1088-byte .bin" | yes |
| E2 | largest f32 Const `size` 4 bytes short | exactly {OVI005} | {OVI005}: "size 1020, needs 1024 (f32 16, 16)" | yes |
| E3 | largest f32 Const shape `4294967296, 4294967296` | exactly {OVI004} | {OVI004}: element count 2^64 overflows 64-bit size arithmetic | yes |
| E4 | first ReLU layer type changed to `Custom` | exactly {OVI002} | not run: the anchor `type="Relu"` was not in the file | not run |
| E5 | DOCTYPE with an internal ENTITY | exactly {OVI001} | {OVI001}: parsing refused | yes |
| E6 | the `.xml` alone, no `.bin` | exactly {OVI005} | {OVI005} | yes |
| M1 | `model-file-scan` on the honest plain-f32 folder | exit 0; `.xml` clean; `.bin` nothing at MEDIUM+ | exit 0; `.xml` no findings; `.bin` one PKL000 (LOW) | yes |
| M2 | `model-file-scan` on the E1 folder | exit 1; `.xml` carries OVI003 | exit 1; `.xml` OVI003 (HIGH); `.bin` PKL000 (LOW) | yes |
| S1 | 50 honest pairs in one folder | all 50 `.xml` listed, none with a finding | 50 listed, none with a finding | yes |
| S2 | same run | no `.bin` finding at MEDIUM+ | none; histogram below | yes |
| R0 | OpenVINO `Core().read_model` on each honest file | every one loads | plain-f32, plain-fp16, reshape-i64 loaded | yes |
| R1 | `read_model` on E1 | rejected, no crash | rejected: "Incorrect weights in bin file!" | yes |
| R2 | `read_model` on E2 | rejected, no crash | rejected: "Attribute and shape size are inconsistent for Const op!1020, 1024, 1024" | yes |
| U1 | published `test_openvino_ir_scan.py` in the same container | all pass | 29 of 29 passed | yes |

**S2 histogram, verbatim:** `{"PKL000 LOW": 49}` over 50 `.bin` files. 49
honest weight files got one LOW note (the bytes are not a pickle the scanner
can parse) and one got no finding at all. Nothing reached MEDIUM, so the
default CI gate (`--fail-on medium`) passes an honest OpenVINO folder. The
one silent `.bin` is not a failure of any prediction; v3 records its first
bytes so the reason can be stated rather than guessed.

## The two cases that did not run

- **string-const.** The child process that builds this model ended on
  signal 11 inside `opset13.constant(...)` called with a numpy array of
  dtype `<U5`, before anything was saved. This is a known OpenVINO bug,
  [openvinotoolkit/openvino#23611](https://github.com/openvinotoolkit/openvino/issues/23611)
  (making a Constant directly from a numpy string array crashes), fixed by
  [PR #38942](https://github.com/openvinotoolkit/openvino/pull/38942), merged
  30 October 2026 for the 2026.5 milestone. It happens while building a
  model from the caller's own data, not while reading a file, and it is not
  a finding of this check. Running each build in its own process (the v2
  change) is what let the other cases finish.
- **E4.** OpenVINO's IR writer spells the layer type `ReLU`
  (`<layer id="5" name="act" type="ReLU" version="opset1">`), while the
  pre-registration's anchor was `type="Relu"`. That was our mistake. The
  scanner itself compares the custom-layer names case-insensitively, so this
  says nothing about it either way.

## Limits

- One OpenVINO release, tiny random-weight models, one file per case. This
  is not a false-positive rate on published OpenVINO models.
- The edited files test the scanner's rules, not OpenVINO. R1 and R2 only
  confirm that the runtime rejects the two cases the scanner's documentation
  says it rejects, with an error and no crash.
- `string` Consts are only range-checked against the `.bin` by this scanner
  version; their packed contents are not checked. Whether a stricter rule is
  worth adding will be decided from what v3 records about real string
  Consts, with its own pre-registered check first.

## What happens next

`ovi-realfile-v3` (queued, amendment written before it runs) builds the same
string constant through `openvino.Tensor` and the documented
`op.Constant(tensor)` constructor, which avoid the crashing call, and accepts
either spelling for E4. It re-runs every case; if any v3 row differs from
v2, both will be reported here.
