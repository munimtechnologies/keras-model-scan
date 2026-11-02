# Pre-registration: openvino_ir_scan on files written by OpenVINO

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 1 November 2026 (UTC), before the job ran. Amended 2 November 2026
(UTC), before the second run, and again before the third run; see the end of
this page.

`openvino_ir_scan.py` 0.1.1 is the only scanner routed by `model-file-scan`
0.10.0 (release v0.49.0) that has never been checked against files the real
library writes. Its unit tests use hand-built XML. This check asks whether it
reads OpenVINO's own `.xml` + `.bin` output the same way. It also asks a
question that matters for anyone running the one-command scan on an OpenVINO
model folder. `model-file-scan` sends every `.bin`, including OpenVINO weight
files, to the pickle scanner, because a `.bin` can be a PyTorch pickle and a
file must not choose its own checks. Does that make honest OpenVINO weights
noisy in CI?

## Setup

A sealed `python:3.12` container. Setup has network only for
`pip install openvino==2026.4.1` and for downloading the v0.49.0 source
tarball of keras-model-scan (`research/ovi-realfile/fetch_kms.py`). The run
steps have no network. The script `research/ovi-realfile/realfile_check_ovi.py`
builds small models with OpenVINO's Python opset API (a parameter, a MatMul
with seeded random f32 weights, an Add with a bias, a ReLU) and writes them
with `openvino.save_model`. It then:

- scans four honest models: `plain-f32` (16x16 weights), `plain-fp16`
  (the same model with `compress_to_fp16=True`), `reshape-i64` (plus an i64
  shape constant), and `string-const` (plus a `string` constant as a second
  output);
- edits text copies of `plain-f32/model.xml` and scans them. **Edited files
  are only scanned, except E1 and E2, which the runtime is also asked to read
  (R1, R2).** E1 and E2 are the two cases whose rejection the scanner's own
  documentation states. They are checked here because the documentation
  should be checked against the runtime it describes;
- runs the one-command `model-file-scan --json` (default `--fail-on medium`);
- writes 50 more honest pairs (seeds 1-50, input width 4 + seed mod 13,
  output width 2 + seed mod 7) into one folder and runs `model-file-scan` on
  it.

"The largest f32 Const" below means the `<data>` element of the Const layer
with the biggest `size` among those with `element_type="f32"`. In `plain-f32`
that is the 16x16 weight matrix, 1024 bytes.

## Predictions

| # | case | prediction |
|---|---|---|
| H1 | the four honest models (each written) | no findings on any file |
| E1 | largest f32 Const `offset` set to the `.bin` length | exactly {OVI003} |
| E2 | largest f32 Const `size` set to 4 bytes short | exactly {OVI005} |
| E3 | largest f32 Const `shape` set to `4294967296, 4294967296` | exactly {OVI004} |
| E4 | the first `type="Relu"` changed to `type="Custom"` | exactly {OVI002} |
| E5 | `<!DOCTYPE net [<!ENTITY e "x">]>` inserted after the XML declaration | exactly {OVI001} |
| E6 | the honest `.xml` alone, with no `.bin` beside it | exactly {OVI005} |
| M1 | `model-file-scan` on the honest `plain-f32` folder | exit 0; the `.xml` has no findings; the `.bin` has nothing at MEDIUM or above |
| M2 | `model-file-scan` on the E1 folder | exit 1, and the `.xml` entry carries OVI003 (so the `.xml` really reached `openvino_ir_scan`) |
| S1 | `model-file-scan` on the 50-pair folder | all 50 `.xml` entries are listed and none has a finding |
| S2 | same run | none of the 50 `.bin` entries has a finding at MEDIUM or above |
| R0 | OpenVINO's `Core().read_model` on each honest file, in a child process | every one loads |
| R1 | `read_model` on E1 | raises an exception (rejected), no crash |
| R2 | `read_model` on E2 | raises an exception (rejected), no crash |
| U1 | the published `test_openvino_ir_scan.py`, run in the same container | all pass |

**Confidence.** S2 is the least certain. The pickle scanner treats a `.bin` as
pickle bytes, and seeded random float32 weights begin with an arbitrary byte.
The expectation is that the parse fails early and is reported as LOW
(PKL000), but stray bytes that happen to decode as opcodes could produce
something louder. The rule histogram over the 50 `.bin` files is reported,
whatever it is.

**Reported, not predicted:** which opset module loaded, the attribute text of
the edited Const, and the per-rule histogram of `.bin` findings.

## Grading

- A scanner prediction holds only if the rule set is exactly the one listed.
- If OpenVINO's API fails to build or save a model, the cases that need that
  model are **not run**, never held or failed. That covers a model that cannot
  be built, a string constant that is not written as `element_type="string"`,
  and anything else of that kind.
- If a crafted case's anchor is missing (no f32 Const with a size, no offset
  or shape attribute, no `type="Relu"` layer), that case is **not run**.
- If R1 or R2 does not hold (the runtime loads the edited file, or the child
  process ends on a signal), the public report will say only that the
  prediction did not hold. The details go to OpenVINO's private security
  channel after a human has checked them, and to no public page first.
- Everything else is reported in full, whatever it is.

## Limits

One small model per case, one OpenVINO release, and tiny random-weight
models. This is not a false-positive rate on published models. The S2 count
says how 50 small random-weight files behave, not how every OpenVINO model
does.

## Amendment, 2 November 2026 (before job ovi-realfile-v2 ran)

The first run (job `ovi-realfile-v1`, 1 November 2026) ended with a
segmentation fault in the check script's own process after it had written the
first three honest models (`plain-f32`, `plain-fp16`, `reshape-i64`) and
before the `string-const` model was written. No result file was produced, so
**nothing was graded** and no prediction is counted as held or failed.

The crash happened while the script was *building or writing* an honest model
with OpenVINO's Python API from its own in-memory data, not while reading any
file, and the files it had already written are ordinary.

Changes for `ovi-realfile-v2`, made before it ran:

- Every honest model (the four H1 models and the 50 sweep pairs) is now built
  and saved in a child process. A child that ends on a signal makes the cases
  that need that model **not run**, as the grading rules above already say
  for API failures. The report names the model, the signal and the last stage
  the child reached (building the string constant, building the model, or
  `save_model`).
- If `string-const` is not run, H1 is graded on the honest models that were
  written.
- The predictions, the edits, the grading rules and the private-channel rule
  for R1 and R2 are unchanged.

If the writer crash can be reproduced and narrowed to one OpenVINO call, it
is reported to OpenVINO through its own channel after a human has looked at
it. It is not counted as a finding of this check.

## Second amendment, 2 November 2026 (after v2, before job ovi-realfile-v3 ran)

`ovi-realfile-v2` ran and is graded in
[REALFILE_CHECK_OVI_2026-11.md](../REALFILE_CHECK_OVI_2026-11.md). Every
prediction that ran held (13 graded rows and U1). Two cases were **not run**,
for reasons that are both on our side or already known upstream:

- **`string-const` (part of H1, and of R0).** The child process ended on
  signal 11 inside `opset13.constant(numpy array of dtype <U5)`, before any
  model was saved. This is OpenVINO's known issue
  [#23611](https://github.com/openvinotoolkit/openvino/issues/23611)
  (making a Constant directly from a numpy string array crashes). Its fix,
  [PR #38942](https://github.com/openvinotoolkit/openvino/pull/38942), was
  merged on 30 October 2026 for the 2026.5 milestone, after 2026.4.1 was
  released. So the paragraph above about reporting the crash no longer
  applies: there is nothing new to report.
- **E4.** OpenVINO's IR writer spells the layer type `ReLU`
  (`<layer ... type="ReLU" version="opset1">`), so the anchor `type="Relu"`
  was not found. That was a mistake in this pre-registration, not a result.

Changes for `ovi-realfile-v3`, made before it ran:

- `string-const` builds the same string constant (`["alpha", "beta",
  "gamma"]`, a second model output) through `openvino.Tensor(numpy array)`
  and the documented `op.Constant(tensor)` constructor, which avoid the
  crashing path. H1 and R0 then include it if it is written.
- E4's anchor is the first `type="Relu"` **or** `type="ReLU"`; the edit and
  the prediction (exactly {OVI002}) are unchanged.
- Newly reported, not predicted: the attribute text of each string Const and
  up to 96 bytes of `.bin` data it points at, and the first 8 bytes of every
  sweep `.bin` on which the pickle scanner reports nothing.
- Everything else (the same OpenVINO release, the same keras-model-scan
  v0.49.0 source, all other predictions and grading rules) is unchanged. v3
  re-runs every case. If a v3 row differs from v2, both are reported.
