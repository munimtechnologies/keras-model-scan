# Real-file check: Core ML scanner, October 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`coreml_model_scan.py` was written and unit-tested against hand-encoded
protobuf bytes. This check asks whether it reads files written by Apple's own
Python tooling the same way. The expectations were written down before the job
ran, in [research/PREREG_COREML_REALFILE.md](research/PREREG_COREML_REALFILE.md),
and the job built every file with coremltools' own interfaces (`ct.convert` on
a MIL program, `NeuralNetworkBuilder`, the `Model_pb2` spec classes and
`save_spec`), then scanned it. A coremltools API refusing a case would have
counted as a failure, not a pass. None did.

The job (`coreml-realfile-v2`) ran in a sealed `python:3.12` container on
31 October 2026 (UTC), with network for `pip install coremltools` only and no
network while files were built and scanned. Nothing was compiled or run by
Core ML: the Core ML runtime only exists on Apple platforms, and coremltools
said so on Linux (`Failed to load _MLModelProxy`), which is expected here.

**Result: 7 of 7 pre-registered predictions held.** No false alarm on the two
normal models, and each crafted case was flagged by exactly the rule that was
predicted, with the predicted evidence.

Versions: `coremltools 9.0`, `coreml_model_scan 0.1.0`.

| # | Prediction | Result | Evidence |
|---|-----------|--------|----------|
| P1 | An ML Program package from `ct.convert` (one 64x64 `linear` weight) has no findings | **PASS** | `got []` |
| P2 | Its `model.mlmodel` holds `@model_path/weights/weight.bin`, and the scanner's string walk finds it | **PASS** | in bytes: true; walk found `@model_path/weights/weight.bin` |
| P3 | A `NeuralNetworkBuilder` model with one ReLU layer has no findings | **PASS** | `got []` |
| P4 | `add_custom` with className `MyCustomLayer` gives exactly one CML001 naming it | **PASS** | `custom.mlmodel > layer cust: className MyCustomLayer` |
| P5 | A custom layer inside a `branch` layer's `ifBranch` gives exactly one CML001 naming it and `(if)` | **PASS** | `branch.mlmodel > layer br (if) > layer deep: className DeepCustom` |
| P6 | A `linkedModel` with search path `$BUNDLE_MAIN:/abs/path` gives exactly one CML002 naming `/abs/path` | **PASS** | `linked.mlmodel: linkedModelSearchPath entry /abs/path` |
| P7 | A copy of the P1 package whose weights item path in `Manifest.json` is changed to `../../w` gives exactly one CML004 | **PASS** | `item 876c652c-...: ../../w` |

P1 and P3 matter most for anyone running the scanner as a CI gate: normal
files written by the current coremltools release raise nothing. P2 confirms
that a real ML Program refers to its weights by `@model_path/...`, which is
the form CML003 accepts. P5 confirms the walk reaches a custom class nested
inside control flow, not just top-level layers.

The manifest coremltools 9.0 wrote for the package (kept in the job output)
lists two items, `com.apple.CoreML/model.mlmodel` and `com.apple.CoreML/weights`,
both relative to `Data/`, with `rootModelIdentifier` pointing at the first.
That is the layout CML004 checks paths against.

The scanner's own 34 unit tests also passed in the same container.

About the job name: `coreml-realfile-v1` was filed with an earlier copy of the
module whose crash guard dropped an argument (fixed before the module was
published), so its results would not have meant anything. `-v2` ran the same
pre-registered P1-P7 script unchanged against the published module.

## Honest limits

- One file per prediction, built by this job, not a corpus of published
  models. This is not a false-positive rate on real-world `.mlmodel` or
  `.mlpackage` files.
- coremltools on Linux writes files but cannot compile or load them, so this
  checks the scanner's reading of real files, not what Core ML does with them
  on an Apple device.
- A finding says a file asks for something a CI gate should look at (an app
  class, an outside path). It does not show that any app is exploitable.
- Static review only: nothing was loaded or executed.
