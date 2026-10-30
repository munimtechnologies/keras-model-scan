# tflite_model_scan.py — TensorFlow Lite (LiteRT) model files

`tflite_model_scan.py` is a static, dependency-free scanner for `.tflite`
files. It is part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan) toolkit.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

## Why the Flex op name matters

A `.tflite` file is a FlatBuffer (identifier `TFL3`). Built-in operators run
TFLite's own kernels. A custom operator runs whatever the application has
registered under its `custom_code`, with one standard exception: a custom op
whose `custom_code` starts with `Flex` is claimed by the Flex delegate
("select TF ops"), which builds and runs a full TensorFlow op. According to
the LiteRT docs, the TensorFlow pip package installs this support
automatically.

Reading TensorFlow's source (`tensorflow/lite/delegates/flex/delegate.cc` and
`kernel.cc`, master, checked 2026-10-30):

- the delegate claims a node when `IsFlexOp(custom_name)` is true, which is a
  prefix check for `Flex`;
- the kernel then reads the operator's `custom_options` as a FlexBuffer
  vector, takes element 0 as a name and parses element 1 as a serialized
  `NodeDef`, and looks `nodedef.op()` up in TensorFlow's op registry;
- neither file compares the op with the rest of `custom_code`, and neither
  has an allowlist check.

So `FlexAbs` in `custom_code` is a label. The op that runs is the one in the
NodeDef. The TFLite converter writes the three names equal; a file in which
they differ was edited after conversion.

ModelAudit's TFLite scanner (promptfoo/modelaudit, `tflite_scanner.py`, read
2026-10-30) flags every custom operator and names it from `custom_code`; it
does not decode `custom_options`. A public proof of concept with Flex file
operators (Rammadaeus/tflite-flex-bypass-poc, cited in promptfoo's ModelAudit
announcement) already shows that Flex ops are a risk. This module adds the
next step: it reports the op the delegate would actually build, and flags a
file whose labels disagree.

## What it does

- Parses the FlatBuffer itself (no `tensorflow`, `tflite` or `flatbuffers`
  import) with bounds-checked reads, and memory-maps files.
- Resolves each operator's builtin code as TFLite does,
  `max(deprecated_builtin_code, builtin_code)`, and looks at every `CUSTOM`
  (32) operator in every subgraph.
- For a Flex operator, decodes the FlexBuffer root vector and the NodeDef's
  `op` field (protobuf field 2) from `custom_options`, or from
  `large_custom_options_offset/size` for models over 2 GB.
- Checks indices the interpreter relies on: `opcode_index`, operator and
  subgraph tensor indices (`-1` is allowed, as TFLite's optional tensor),
  tensor buffer indices, buffer `offset + size` against the file size, and
  shape dimensions below -1.

## Rules

| rule | severity | class | condition |
|------|----------|-------|-----------|
| **TFL001** | high | CWE-829 | Flex operator whose TensorFlow op reads or writes files, copies tensors to debug URLs, or calls back into Python (`ReadFile`, `WriteFile`, `MatchingFiles`, checkpoint save/restore, record and text-line readers and datasets, table init from a text file, summary writers, `Debug*`, `PyFunc`/`EagerPyFunc`). |
| **TFL002** | high | CWE-436 | Flex operator whose labels disagree: the `custom_code` suffix, the name in the options and the NodeDef op are not all the same. |
| **TFL003** | medium | CWE-829 | Any other Flex operator (it runs the full TensorFlow runtime), or a non-Flex custom operator (it runs native code the application registers). Listed once per op name with a count. |
| **TFL004** | medium | CWE-129 | Out-of-range references in a subgraph or buffer table: opcode, tensor or buffer index past its table, buffer data outside the file, or a shape dimension below -1. One finding per subgraph with a count and the first three examples. |
| **TFL005** | medium | CWE-693 | Not a well-formed TFLite FlatBuffer, Flex options that do not decode to a name and a NodeDef with an op, or more than 1000 findings. |

`cve` is empty for every rule: each describes a class, not one advisory.

## Usage

```bash
python tflite_model_scan.py model.tflite
```

Exit `1` on any high finding, `0` otherwise, `2` on usage error or unreadable
input. `scan_bytes(data, name=...)` and `scan_file(path)` return a list of
finding dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Honest limits

- Static review only. TFL001 shows that a file asks for a TensorFlow op with
  file or Python access; whether it runs depends on the runtime. A runtime
  without the Flex delegate rejects the model, and `PyFunc`-style ops need a
  Python callback registered in the same process.
- The op list is a denylist of well-known TensorFlow ops, not every op with a
  side effect. `PrintV2` (which can append to a file) is reported as TFL003,
  not TFL001. Op attributes and inputs, such as file names, are not decoded.
- Only FlexBuffer string and key elements are read, as the delegate's
  `AsString()` does; other element types are reported as TFL005.
- The delegate's behaviour above comes from reading TensorFlow's source on
  2026-10-30, not from running it. Tests use FlatBuffer, FlexBuffer and
  NodeDef bytes built by hand from the published schemas; checking against
  files written by the TFLite converter itself is the next step.
