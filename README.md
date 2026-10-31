# keras-model-scan

A static, **no-execution** safety scanner for `.keras` model files.

A `.keras` model is a ZIP archive whose `config.json` is turned back into a live
model when you call `keras.models.load_model()`. That rebuild step decides, from
attacker-controllable strings in `config.json`, which Python callables get resolved
and what archive members get written to disk — and it has been the source of a run
of remote-code-execution and path-traversal CVEs.

`keras-model-scan` answers one question *before* you load a model someone sent you:

> Does this file contain any of the patterns behind the known Keras load-time CVEs?

## One command for many model formats: `model-file-scan`

The repository also ships `model-file-scan`, which sends each file to the right
static scanner and reports everything in one place (text, `--json`, or `--sarif`
for GitHub code scanning). Version 0.9.0 routes:

| Files | Scanner | What it checks |
|-------|---------|----------------|
| `.keras` `.h5` `.hdf5` `config.json` | `keras_model_scan` | the Keras load-time CVE patterns below |
| `*.index.json` | `safetensors_index_scan` | shard paths that leave the model directory |
| `.safetensors` | `safetensors_scan` | header and offset integrity |
| `.gguf` | `gguf_scan` | header and tensor-info integrity |
| `.tflite` | `tflite_model_scan` | Flex ops that touch files or call Python, custom ops, index and buffer bounds |
| `.pte` | `executorch_pte_scan` | every tensor, segment and index against its region |
| `.mlmodel` `.mlpackage` | `coreml_model_scan` | custom classes, linked-model and weight paths, manifest paths |
| `.pdmodel` | `paddle_program_scan` | ops that read or write files by a stored path, `py_func` |
| `.rds` `.rda` `.RData` | `r_serialized_scan` | promises, active bindings, risky calls in stored code, non-base namespaces |
| `.msgpack` | `msgpack_weights_scan` | pickled object arrays and size mismatches |
| `.nemo` | `nemo_container_scan` | pickled callables in the archive, member paths and links that leave the folder |
| `.onnx` | `onnx_external_data_scan` | external-data locations that leave the model directory |
| `.xml` beside a `.bin` | `openvino_ir_scan` | DOCTYPE/entities, weight ranges against the `.bin`, external-code layers |
| everything else (`.pkl` `.pt` `.pth` `.bin` `.joblib` `.npy` `.npz` `.ckpt` ...) | `pickle_model_scan` | dangerous imports and opcodes |

```bash
pip install git+https://github.com/munimtechnologies/keras-model-scan
model-file-scan path/to/models --fail-on high
model-file-scan model.tflite fit.rds Model.mlpackage --sarif > results.sarif
```

Each standalone scanner also runs on its own (`python r_serialized_scan.py fit.rds`)
and has its own notes file in this repository. The TFLite, ExecuTorch, Core ML,
PaddlePaddle, R, MessagePack and archive scanners have each been checked against
files written by the real libraries, with the predictions written down before the
check ran (`REALFILE_CHECK_*.md`).

## It never runs the model

This tool is deliberately defensive and conservative:

- It **never** imports `keras` / `tensorflow` and **never** calls `load_model` or
  `model_from_json`.
- It **never** executes, unpickles, marshals, or evaluates anything in the file.
- It only opens the archive with the standard-library `zipfile`, reads `config.json`
  as text, parses it as JSON, and walks the data structure for known-bad patterns.

A hit means *"this matches a pattern associated with a known class of malicious model
file and deserves review"* — not a proof of maliciousness. A clean result means only
that none of the catalogued patterns were found; it is **not** a guarantee of safety.

## Install / run

No dependencies — Python 3.8+ standard library only.

```bash
python keras_model_scan.py path/to/model.keras
python keras_model_scan.py model.keras other.keras --json
```

Exit code is `1` if anything is flagged and `0` if clean, so it works as a CI or
pre-load gate:

```bash
python keras_model_scan.py downloaded_model.keras || echo "do not load this file"
```

You can also point it at a raw `config.json` (the `model_from_json` payload), since
the config alone is enough to trigger the RCE lineage.

## What it detects

| Rule | Severity | Pattern | CVE / advisory |
|------|----------|---------|----------------|
| KMS001 | HIGH / MEDIUM | A `function`/`class` node resolving a callable from a module **outside** the Keras import allowlist (`keras`, `keras_hub`, `keras_cv`, `keras_nlp`) — e.g. `module: "subprocess"`, `config: "Popen"`, with args supplied via `inbound_nodes` | CVE-2025-1550 |
| KMS002 | HIGH | A `__lambda__` node carrying a serialized Python code object | CVE-2025-1550, CVE-2026-12481 |
| KMS003 | CRITICAL | The config references `enable_unsafe_deserialization` — a model that turns off safe mode from inside its own load | CVE-2025-9906 |
| KMS004 | MEDIUM | A `TFSMLayer` that loads an external TensorFlow SavedModel during deserialization (ran even under `safe_mode=True`) | CVE-2026-1462 |
| KMS005 | HIGH | An archive member with an absolute path or `..` that escapes the extraction directory (Zip/TarSlip) | CVE-2026-11816 |
| KMS007 | INFO | Legacy `.h5`/`.hdf5` format, which has had load paths that did not honour `safe_mode` | CVE-2025-9905 |

The allowlist mirrors the one Keras itself uses in `_retrieve_class_or_fn`, so a
legitimately registered custom object outside it will be flagged for review (a
false positive you can clear by confirming the object is one you trust).

## Good practice this does not replace

- Always load models with `safe_mode=True` (the default) and only from sources you
  trust; keep Keras/TensorFlow updated past the CVEs above.
- Combine static scanning with a maintained model-scanning service for coverage of
  patterns this tool does not yet know about.

## About

Made by AI agents working as **MV2 of Munim, Inc.** Built from public CVE/advisory
research into Keras model deserialization. Contributions and new rules welcome via
issues and pull requests. Apache-2.0 licensed.
