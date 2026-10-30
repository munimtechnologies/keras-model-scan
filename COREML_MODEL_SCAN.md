# coreml_model_scan

Static scanner for **Core ML** models: `.mlmodel` spec files and `.mlpackage`
folders. Part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan)
toolkit. Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.

```bash
python coreml_model_scan.py Model.mlpackage
python coreml_model_scan.py model.mlmodel
```

It exits `1` on any high finding (so it can gate CI), `2` on a usage error or
an unreadable file, and `0` when clean or only medium findings remain. It uses
**only the Python standard library**: no coremltools, no protobuf package.
It runs on Linux and Windows CI as well as macOS.

## Why

A Core ML `.mlmodel` is a `CoreML.Specification.Model` protobuf (coremltools
`mlmodel/format/Model.proto`). An `.mlpackage` is a folder whose
`Manifest.json` lists items by a `path` relative to `Data/`; the root item is
the `model.mlmodel` spec, and ML Program weights sit in
`Data/com.apple.CoreML/weights/weight.bin`. Some parts of a model make Core ML
reach outside the file itself:

| spec location | what Core ML does with it |
|---|---|
| `Model.customModel` (field 555), `className` (10) | instantiates and runs the named app class (`MLCustomModel`) |
| `NeuralNetworkLayer.custom` (field 500), `className` (10) | instantiates and runs the named app class (`MLCustomLayer`) |
| `branch` (605: `ifBranch` 1, `elseBranch` 2) and `loop` (615: `conditionNetwork` 3, `bodyNetwork` 4) layers | hold whole nested networks, so custom layers can sit at any depth |
| `Model.linkedModel` (field 556) → `LinkedModelFile` | loads another compiled model by `linkedModelFileName` (1) and a `:`-separated `linkedModelSearchPath` (2); entries may be relative, absolute, `$BUNDLE_MAIN` or `$BUNDLE_IDENTIFIER(id)` |
| `Model.mlProgram` (field 502) → `Value.blobFileValue` (5) → `fileName` (1) | names the weights file, written by coremltools as `@model_path/weights/weight.bin` |
| `Manifest.json` `itemInfoEntries[*].path` | resolved relative to `Data/` |

Field numbers are taken from coremltools' `Model.proto`, `NeuralNetwork.proto`,
`CustomModel.proto`, `LinkedModel.proto`, `Parameters.proto` and `MIL.proto`.

## Rules

| rule | severity | CWE | what it means |
|------|----------|-----|---------------|
| CML001 | high | CWE-829 | A `customModel` or `custom` layer names an app class that Core ML would run. Found at any depth: pipeline members, and networks inside `branch` and `loop` layers. Repeats of one class are reported once with a count. |
| CML002 | high | CWE-73 | A `linkedModel` file name or search-path entry leaves the model's own location: absolute, `~`, a `..` segment, or a `$` variable other than `$BUNDLE_MAIN` / `$BUNDLE_IDENTIFIER(...)`. |
| CML003 | high | CWE-22 | An ML Program weight-file reference escapes the package: after `@model_path/` it is absolute, `~`, a URL, or has a `..` segment; or a `.bin` reference without `@model_path/` is absolute. |
| CML004 | high | CWE-22 | An `.mlpackage` `Manifest.json` item path escapes `Data/` (absolute, drive letter, `~`, `..`, or through a symbolic link), or a symbolic link under `Data/` points outside the package. |
| CML005 | medium | CWE-693 | Not a parseable Core ML spec or manifest, the root item missing, nesting deeper than 32 levels, or findings capped. |

## Prior art and honest limits

promptfoo's ModelAudit has a Core ML scanner (`coreml_scanner.py`) with its
own protobuf parser. It flags `customModel`, custom layers and unsafe
`linkedModel` paths, walks nested pipelines and checks metadata strings, and
it is more thorough than this module on metadata. As we read its source
(30 October 2026), it checks custom layers only at the top level of a neural
network (not inside `branch`/`loop` bodies), does not read ML Program
`blobFileValue` file names, handles `.mlmodel` files only (no `.mlpackage`
manifest or symlink checks), and marks files over 10 MB as inconclusive.
`coreml_model_scan` covers exactly those four gaps and reads files of any
size. It does not repeat ModelAudit's metadata command/URL heuristics.

Limits:

- Static review only: nothing is loaded, compiled or executed. A CML001
  finding means the model needs app code to run; if the class is your own,
  the finding is expected.
- ML Program weight references are found by walking every printable string in
  the program's message tree, not by a full MIL schema decode. A reference is
  checked only if it starts with `@model_path/` or ends in `.bin`.
- Compiled `.mlmodelc` bundles are not read. Weight blob contents are not
  checked against tensor shapes.
- The search-path split is on `:` as Core ML documents; an identifier inside
  `$BUNDLE_IDENTIFIER(...)` that itself contains `:` would be split.
- These tests use hand-encoded spec bytes. A check against files written by
  coremltools itself has not been run yet.

If you spot a mistake, the repo is the place to raise it.
