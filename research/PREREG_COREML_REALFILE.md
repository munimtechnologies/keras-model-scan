# Pre-registration: coreml_model_scan on files written by coremltools

Written 30 October 2026 (UTC), before the job runs. Made with AI agents working
in the name of MV2 of Munim, Inc. Defensive check of a static scanner; every
file is built locally inside a sealed container with no network at run time.

Setup: `python:3.12`, `pip install coremltools` (latest on PyPI at run time).
Files are written with coremltools' own APIs (`ct.convert` on a MIL program,
`NeuralNetworkBuilder`, the `Model_pb2` spec classes and
`coremltools.models.utils.save_spec`). Nothing is compiled or run by Core ML.

| id | file | prediction |
|----|------|------------|
| P1 | `lin.mlpackage`: `ct.convert` of a MIL program with one 64x64 `linear` weight, `convert_to="mlprogram"` | `scan_file` returns no findings |
| P2 | the same package's `Data/com.apple.CoreML/model.mlmodel` | its bytes contain `@model_path/weights/weight.bin`, and the scanner's string walk finds that reference |
| P3 | `plain.mlmodel`: NeuralNetworkBuilder, one ReLU layer | no findings |
| P4 | `custom.mlmodel`: NeuralNetworkBuilder `add_custom` with className `MyCustomLayer` | exactly one finding, CML001, evidence names `MyCustomLayer` |
| P5 | `branch.mlmodel`: plain model plus a `branch` layer whose `ifBranch` holds a custom layer `DeepCustom` | exactly one finding, CML001, evidence names `DeepCustom` and `(if)` |
| P6 | `linked.mlmodel`: spec with `linkedModel`, file name `x.mlmodelc`, search path `$BUNDLE_MAIN:/abs/path` | exactly one finding, CML002, evidence names `/abs/path` |
| P7 | copy of `lin.mlpackage` whose Manifest.json weights item path is set to `../../w` | exactly one finding, CML004 |

A prediction that fails, or a case that errors because a coremltools API
differs from what we expected, will be reported as such.
