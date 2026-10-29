# tf_savedmodel_ops_scan.py — TensorFlow SavedModel filesystem-op scanner

`tf_savedmodel_ops_scan.py` is a static, dependency-free detector for TensorFlow
SavedModels (`saved_model.pb`, `saved_model.pbtxt`) and frozen `GraphDef`
files. It decodes the protobuf with the Python standard library, walks every op
in the graph **and** in the function library, and reports ops that read, list
or write host files when the model runs. It is part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan) toolkit.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

## Why a SavedModel needs an op scan

A SavedModel is a program, not just weights. Its graph holds the ops that run
when a signature or `tf.function` is called, and some standard TensorFlow ops
touch the filesystem. `ReadFile` and `WriteFile` are the documented examples:
ModelScan's `SavedModelTensorflowOpScan` rates both HIGH, and Protect AI / Palo
Alto's Insights DB lists the class as PAIT-TF-301. But a denylist of only those
two lets other file ops through. guardana's PR #147 (merged 2026-10-12) made the
same point and added `MatchingFiles`, `InitializeTableFromTextFile(V2)` and
`PrintV2` with a `file://` stream. TensorFlow has more: dataset readers
(`TextLineDataset`, `TFRecordDataset`, `FixedLengthRecordDataset`,
`SqlDataset`, `LMDBDataset`), queue readers (`WholeFileReader`, ...), dataset
writers (`DatasetToTFRecord`, `SaveDataset`, `SnapshotDataset`), summary file
writers and `ImmutableConst` (memory-maps a named file).

This toolkit's `SCANNER_COVERAGE_MATRIX.md` marked "TF SavedModel risky/custom
ops" as not covered here. This module closes that row for filesystem ops.

## What it does

- Decodes the binary protobuf with a small wire-format reader (no TensorFlow,
  no `protobuf` package). Field numbers come from TensorFlow's own
  `saved_model.proto`, `meta_graph.proto`, `graph.proto`, `function.proto`,
  `node_def.proto`, `op_def.proto`, `attr_value.proto` and `tensor.proto`.
- Walks `meta_graphs[*].graph_def.node` and `graph_def.library.function[*].node_def`
  (TF2 puts almost every op in the function library), and names the function
  that holds each finding (`meta_graph[0]:function:__inference_...`).
- Reads every node's string attrs and string constants (`AttrValue.s`,
  `AttrValue.list.s`, `TensorProto.string_val`) to find paths **outside the
  model**: absolute, `..`, `~/`, a Windows drive or UNC path, `file://`, `gs://`,
  `s3://` or `hdfs://`. TF device strings (`/job:...`, `/device:...`) are ignored.
- Also reads `meta_info_def.stripped_op_list` and reports a risky op declared
  there even if no node using it was decoded.
- Handles a bare frozen `GraphDef` and falls back to a text scan for
  `saved_model.pbtxt`. `scan_file` accepts a SavedModel directory.
- Bounded (`MAX_NODES`, strings per node), stops cleanly at the first malformed
  byte, never imports TensorFlow, never loads or runs the graph, never writes.

## Rules

| rule | severity | class | condition |
|------|----------|-------|-----------|
| **TFSM001** | high | CWE-73 | An op that writes files: `WriteFile`, `DatasetToTFRecord`, `SaveDataset(V2)`, `SnapshotDataset(V2)`, `CreateSummaryFileWriter`, `CreateSummaryDbWriter`, or `PrintV2` with a `file://` output stream. |
| **TFSM002** | high | CWE-73 | `ReadFile` (always, matching ModelScan), or another file read/list op when the graph also carries a path outside the model. |
| **TFSM003** | medium | CWE-73 | A file read/list op with no outside path in the graph, or a lookup-table initialiser (`InitializeTableFromTextFile(V2)`), which never escalates: TF1 exports keep the export-time absolute asset path in a `Const`, so escalating would flag ordinary vocabulary tables. |
| **TFSM005** | medium | CWE-94 | A Python callback op (`PyFunc`, `PyFuncStateless`, `EagerPyFunc`). The SavedModel cannot carry the Python function, so this is not code execution on its own, but the graph calls into host Python. |

## Usage

```bash
python tf_savedmodel_ops_scan.py path/to/saved_model_dir
python tf_savedmodel_ops_scan.py saved_model.pb frozen_graph.pb
```

Exit `1` on any high finding, `0` otherwise, `2` on usage error or unreadable
input. `scan_bytes(data, name=...)` and `scan_file(path)` return a list of
finding dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Honest limits

- This is static review, not exploitation. It shows that an op is in the graph,
  not that a given signature reaches it or that a file is exploitable.
- Paths are matched graph-wide, as in guardana: the scanner does not follow
  dataflow from a constant to the op that consumes it, and a path built at
  run time (for example by `StringJoin` of harmless pieces) is not seen.
- The op lists use TensorFlow's raw op names. A name missing from a given
  TensorFlow version simply never matches. Custom ops loaded from a shared
  library and Keras `Lambda` layers are out of scope here (sibling modules cover
  Keras configs).
- The `.pbtxt` fallback is a text scan: ops are not tied to node names, and
  string constants are graph-wide.
- Tests encode SavedModel protobufs by hand from the `.proto` field numbers;
  they do not use files exported by TensorFlow itself. Checking against real
  exported models is the next step.
