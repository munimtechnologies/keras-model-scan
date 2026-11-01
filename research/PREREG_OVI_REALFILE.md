# Pre-registration: openvino_ir_scan on files written by OpenVINO

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 1 November 2026 (UTC), before the job ran.

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
