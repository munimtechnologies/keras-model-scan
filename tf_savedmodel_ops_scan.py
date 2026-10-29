"""Static, dependency-free scanner for TensorFlow SavedModel graph ops.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

A TensorFlow SavedModel (``saved_model.pb``) is a **program**, not just weights:
its ``GraphDef`` and function library hold the ops that run when a loaded
signature or tf.function is called. Some standard TensorFlow ops touch the host
filesystem. ``ReadFile`` / ``WriteFile`` are the documented examples (ModelScan's
``SavedModelTensorflowOpScan`` rates both HIGH; Protect AI / Palo Alto Insights
PAIT-TF-301), but they are not the only ones: dataset readers
(``TextLineDataset``, ``TFRecordDataset``, ...), file listers (``MatchingFiles``),
dataset writers (``DatasetToTFRecord``, ``SaveDataset``), summary file writers
and ``PrintV2`` with a ``file://`` output stream also read, list or write files.
A denylist of just ReadFile/WriteFile lets those through.

This module decodes the protobuf wire format with the standard library only
(no TensorFlow, no ``protobuf`` package), walks every ``NodeDef`` in each
meta graph's ``graph_def`` **and** in its ``FunctionDefLibrary`` (where TF2 puts
almost all ops), reads the string constants and string attrs of every node, and
reports filesystem ops by the function that holds them. It also reads
``meta_info_def.stripped_op_list`` and a bare (frozen) ``GraphDef``, and falls
back to a text scan for ``saved_model.pbtxt``. It never imports TensorFlow,
never loads or runs the graph, and never writes to disk.

Proto field numbers used (tensorflow/core/{protobuf,framework}/*.proto):
SavedModel.meta_graphs=2; MetaGraphDef.meta_info_def=1, graph_def=2;
MetaInfoDef.stripped_op_list=2; OpList.op=1; OpDef.name=1; GraphDef.node=1,
library=2; FunctionDefLibrary.function=1; FunctionDef.signature=1,
node_def=3; NodeDef.name=1, op=2, attr=5; AttrValue.list=1, s=2, tensor=8;
ListValue.s=2, tensor=8; TensorProto.string_val=8.

Rules
-----
TFSM001  high    CWE-73  An op that writes files (WriteFile, dataset/TFRecord
                         writers, snapshot, summary file writers, or PrintV2
                         with a file:// output stream). Calling the function
                         writes a file whose path the model author chose.
TFSM002  high    CWE-73  ReadFile (always, matching ModelScan's HIGH), or any
                         other file read/list op when the graph also carries a
                         path outside the model (absolute, '..', file://, ~/,
                         or a gs:// / s3:// / hdfs:// URL).
TFSM003  medium  CWE-73  A file read/list op with no outside path in the graph's
                         strings -- common for input pipelines and vocabulary
                         tables loaded from assets/. Table initialisers stay
                         here even with an outside path (TF1 exports keep the
                         export-time absolute asset path in a Const).
TFSM005  medium  CWE-94  A Python callback op (PyFunc, PyFuncStateless,
                         EagerPyFunc). The SavedModel cannot carry the Python
                         function itself, so this is not code execution on its
                         own, but the graph calls into host Python.

Scope note: Keras ``Lambda`` layers in ``keras_metadata.pb`` and HDF5/.keras
configs are handled by sibling modules in this repo; this module reports graph
ops only.
"""

__version__ = "0.1.0"

# Caps so a huge or hostile graph cannot exhaust the scanner.
MAX_NODES = 2000000
MAX_STRINGS_PER_NODE = 64
MAX_OUTSIDE_PATHS = 50

# Ops that write files when they run.
_WRITE_OPS = frozenset({
    "WriteFile",
    "DatasetToTFRecord", "ExperimentalDatasetToTFRecord",
    "SaveDataset", "SaveDatasetV2",
    "SnapshotDataset", "SnapshotDatasetV2",
    "CreateSummaryFileWriter", "CreateSummaryDbWriter",
})
# Read ops reported HIGH unconditionally (parity with ModelScan).
_READ_ALWAYS_HIGH = frozenset({"ReadFile"})
# Ops that read or list files; HIGH only when an outside path is present.
_READ_OPS = frozenset({
    "MatchingFiles", "MatchingFilesDataset", "ExperimentalMatchingFilesDataset",
    "ImmutableConst",
    "WholeFileReader", "WholeFileReaderV2",
    "TextLineReader", "TextLineReaderV2",
    "TFRecordReader", "TFRecordReaderV2",
    "FixedLengthRecordReader", "FixedLengthRecordReaderV2",
    "LMDBReader",
    "TextLineDataset", "TFRecordDataset", "TFRecordDatasetV2",
    "FixedLengthRecordDataset", "FixedLengthRecordDatasetV2",
    "SqlDataset", "ExperimentalSqlDataset",
    "LMDBDataset", "ExperimentalLMDBDataset",
    "LoadDataset", "LoadAndRemapMatrix",
    "InitializeTableFromTextFile", "InitializeTableFromTextFileV2",
})
# Read ops that never escalate to HIGH (legitimate vocab tables in TF1 exports
# keep the export-time absolute asset path in a Const).
_NO_ESCALATE = frozenset({
    "InitializeTableFromTextFile", "InitializeTableFromTextFileV2",
})
_PY_CALLBACK_OPS = frozenset({"PyFunc", "PyFuncStateless", "EagerPyFunc"})

_REMOTE_SCHEMES = ("file://", "gs://", "s3://", "hdfs://")
_PBTXT_TOKENS = (b"node {", b"node_def {", b"meta_graphs {",
                 b"saved_model_schema_version")

_RULES = {
    "TFSM001": ("high", "CWE-73",
                "Graph op writes to the filesystem when it runs. A SavedModel "
                "is a program: calling the function that holds this op writes a "
                "file whose path the model author chose (overwriting a host file "
                "can lead to code execution). Do not run this model untrusted."),
    "TFSM002": ("high", "CWE-73",
                "Graph op reads or lists host files when it runs, and either it "
                "is ReadFile or the graph carries a path outside the model "
                "(absolute, '..', file://, ~/ or a remote filesystem URL). "
                "Calling the function can read local files into model outputs."),
    "TFSM003": ("medium", "CWE-73",
                "Graph op reads or lists files. No path outside the model was "
                "found that it could use, or it is a lookup-table initialiser; "
                "common for input pipelines and vocabularies in assets/. Check "
                "that the path it reads is the model's own asset."),
    "TFSM005": ("medium", "CWE-94",
                "Graph calls back into host Python (PyFunc/EagerPyFunc). The "
                "SavedModel cannot carry the Python function itself, so this is "
                "not code execution on its own, but the graph is not portable "
                "and depends on code registered in the loading process."),
}


def _finding(rule, severity, cve, cwe, message, evidence):
    return {
        "rule": rule,
        "severity": severity,
        "cve": cve,
        "cwe": cwe,
        "message": message,
        "evidence": evidence,
    }


def _read_varint(buf, pos):
    result = 0
    shift = 0
    n = len(buf)
    while True:
        if pos >= n:
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _fields(buf):
    """Yield (field_number, wire_type, value) for each field of a protobuf
    message. Length-delimited values are memoryview slices (no copy). Stops
    silently at the first malformed byte."""
    pos = 0
    n = len(buf)
    while pos < n:
        try:
            key, pos = _read_varint(buf, pos)
        except ValueError:
            return
        field, wt = key >> 3, key & 7
        if field == 0:
            return
        if wt == 0:
            try:
                val, pos = _read_varint(buf, pos)
            except ValueError:
                return
        elif wt == 1:
            if pos + 8 > n:
                return
            val = buf[pos:pos + 8]
            pos += 8
        elif wt == 2:
            try:
                ln, pos = _read_varint(buf, pos)
            except ValueError:
                return
            if pos + ln > n:
                return
            val = buf[pos:pos + ln]
            pos += ln
        elif wt == 5:
            if pos + 4 > n:
                return
            val = buf[pos:pos + 4]
            pos += 4
        else:
            return  # groups (3/4) and invalid wire types: not a TF message
        yield field, wt, val


def _str(view):
    return bytes(view).decode("utf-8", "replace")


def _tensor_strings(buf, out):
    for f, wt, v in _fields(buf):
        if f == 8 and wt == 2 and len(out) < MAX_STRINGS_PER_NODE:
            out.append(_str(v))


def _attr_strings(buf, out):
    """Collect AttrValue.s, AttrValue.tensor.string_val and the same inside
    AttrValue.list."""
    for f, wt, v in _fields(buf):
        if wt != 2 or len(out) >= MAX_STRINGS_PER_NODE:
            continue
        if f == 2:
            out.append(_str(v))
        elif f == 8:
            _tensor_strings(v, out)
        elif f == 1:
            for f2, wt2, v2 in _fields(v):
                if wt2 != 2 or len(out) >= MAX_STRINGS_PER_NODE:
                    continue
                if f2 == 2:
                    out.append(_str(v2))
                elif f2 == 8:
                    _tensor_strings(v2, out)


def _parse_node(buf):
    """Return (name, op, strings) for a NodeDef."""
    name = ""
    op = ""
    strings = []
    for f, wt, v in _fields(buf):
        if wt != 2:
            continue
        if f == 1:
            name = _str(v)
        elif f == 2:
            op = _str(v)
        elif f == 5:
            for f2, wt2, v2 in _fields(v):  # map entry: key=1, value=2
                if f2 == 2 and wt2 == 2:
                    _attr_strings(v2, strings)
    return name, op, strings


def _add_node(buf, where, nodes):
    if len(nodes) >= MAX_NODES:
        return
    name, op, strings = _parse_node(buf)
    if op:
        nodes.append((where, name, op, strings))


def _walk_function(buf, prefix, nodes):
    fname = ""
    fnodes = []
    for f, wt, v in _fields(buf):
        if wt != 2:
            continue
        if f == 1:
            for f2, wt2, v2 in _fields(v):
                if f2 == 1 and wt2 == 2:
                    fname = _str(v2)
                    break
        elif f == 3:
            fnodes.append(v)
    where = "%sfunction:%s" % (prefix, fname or "?")
    for v in fnodes:
        _add_node(v, where, nodes)


def _walk_graph(buf, prefix, nodes):
    for f, wt, v in _fields(buf):
        if wt != 2:
            continue
        if f == 1:
            _add_node(v, prefix + "graph", nodes)
        elif f == 2:
            for f2, wt2, v2 in _fields(v):
                if f2 == 1 and wt2 == 2:
                    _walk_function(v2, prefix, nodes)


def _walk_meta_graph(buf, prefix, nodes, op_list):
    for f, wt, v in _fields(buf):
        if wt != 2:
            continue
        if f == 1:
            for f2, wt2, v2 in _fields(v):
                if f2 != 2 or wt2 != 2:
                    continue
                for f3, wt3, v3 in _fields(v2):
                    if f3 != 1 or wt3 != 2 or len(op_list) >= MAX_NODES:
                        continue
                    for f4, wt4, v4 in _fields(v3):
                        if f4 == 1 and wt4 == 2:
                            op_list.append((prefix + "stripped_op_list", _str(v4)))
                            break
        elif f == 2:
            _walk_graph(v, prefix, nodes)


def _collect_binary(data):
    """Return (nodes, op_list) from a binary SavedModel or bare GraphDef."""
    view = memoryview(data)
    nodes = []
    op_list = []
    if data[:1] == b"\x0a":
        # field 1 length-delimited: a bare (frozen) GraphDef starting with a node.
        _walk_graph(view, "", nodes)
        return nodes, op_list
    index = 0
    for f, wt, v in _fields(view):
        if f == 2 and wt == 2:
            _walk_meta_graph(v, "meta_graph[%d]:" % index, nodes, op_list)
            index += 1
    if not nodes and not op_list:
        # e.g. a GraphDef holding only a function library (starts with field 2).
        _walk_graph(view, "", nodes)
    return nodes, op_list


def _outside_path(s):
    """True if a string names a location outside the model directory."""
    if not s or len(s) > 4096:
        return False
    t = s.strip().replace("\\", "/")
    low = t.lower()
    if low.startswith(_REMOTE_SCHEMES):
        return True
    if low.startswith("/job:") or low.startswith("/device:"):
        return False  # TF device strings, not paths
    if t.startswith("/"):
        rest = t.lstrip("/")
        return bool(rest) and not rest[0].isspace()
    if t.startswith("~/"):
        return True
    if len(t) >= 3 and t[0].isalpha() and t[1] == ":" and t[2] == "/":
        return True  # Windows drive path
    return ".." in t.split("/")


def _classify(op, own_strings, outside):
    if op in _WRITE_OPS:
        return "TFSM001"
    if op == "PrintV2":
        if any(s.strip().lower().startswith("file://") for s in own_strings):
            return "TFSM001"
        return None
    if op in _READ_ALWAYS_HIGH:
        return "TFSM002"
    if op in _READ_OPS:
        if outside and op not in _NO_ESCALATE:
            return "TFSM002"
        return "TFSM003"
    if op in _PY_CALLBACK_OPS:
        return "TFSM005"
    return None


def _report(rule, where, op, node_name, outside):
    severity, cwe, message = _RULES[rule]
    evidence = "%s: op=%s" % (where, op)
    if node_name:
        evidence += " node=%r" % node_name
    if outside and rule in ("TFSM001", "TFSM002", "TFSM003"):
        evidence += "; outside_paths=%s" % ", ".join(
            repr(p[:120]) for p in outside[:3])
    return _finding(rule, severity, "", cwe, message, evidence)


def _findings_from(nodes, op_list, outside):
    findings = []
    seen = set()
    seen_ops = set()
    for where, node_name, op, strings in nodes:
        seen_ops.add(op)
        rule = _classify(op, strings, outside)
        if rule is None:
            continue
        key = (rule, where, node_name, op)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_report(rule, where, op, node_name, outside))
    # Ops declared in stripped_op_list but not seen in any node (e.g. a node
    # list we could not fully decode) are still reported.
    for where, op in op_list:
        if op in seen_ops:
            continue
        rule = _classify(op, [], outside)
        if rule is None:
            continue
        key = (rule, where, "", op)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_report(rule, where, op, "", outside))
    return findings


def _outside_from(strings_iter):
    outside = []
    for s in strings_iter:
        if len(outside) >= MAX_OUTSIDE_PATHS:
            break
        if _outside_path(s) and s not in outside:
            outside.append(s)
    return outside


def _looks_like_pbtxt(data):
    if b"\x00" in data[:1 << 20]:
        return False
    return any(t in data for t in _PBTXT_TOKENS)


def _scan_pbtxt(data):
    """Text-format fallback (saved_model.pbtxt). Ops are not tied to node
    names, and string constants are graph-wide."""
    import re

    text = data.decode("utf-8", "replace")
    ops = re.findall(r'\bop\s*:\s*"([^"\\]+)"', text)
    strings = re.findall(r'(?:\bstring_val|\bs)\s*:\s*"((?:[^"\\]|\\.)*)"', text)
    outside = _outside_from(strings)
    nodes = [("pbtxt", "", op, strings if op == "PrintV2" else []) for op in ops]
    return _findings_from(nodes, [], outside)


def scan_bytes(data, name=""):
    """Scan the bytes of a saved_model.pb / .pbtxt or a frozen GraphDef.
    Returns a list of finding dicts (possibly empty)."""
    if not data:
        return []
    data = bytes(data)
    nodes, op_list = _collect_binary(data)
    if nodes or op_list:
        outside = _outside_from(s for n in nodes for s in n[3])
        return _findings_from(nodes, op_list, outside)
    if _looks_like_pbtxt(data):
        return _scan_pbtxt(data)
    return []


def scan_file(path):
    """Scan a saved_model.pb file, or a SavedModel directory holding one.
    Raises OSError if it cannot be read."""
    import os

    if os.path.isdir(path):
        for candidate in ("saved_model.pb", "saved_model.pbtxt"):
            full = os.path.join(path, candidate)
            if os.path.isfile(full):
                path = full
                break
        else:
            raise OSError("no saved_model.pb or saved_model.pbtxt in %s" % path)
    with open(path, "rb") as fh:
        data = fh.read()
    return scan_bytes(data, name=os.path.basename(path))


def main(argv=None):
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write(
            "usage: tf_savedmodel_ops_scan.py <saved_model.pb | dir> [...]\n")
        return 2
    exit_code = 0
    for path in argv:
        try:
            findings = scan_file(path)
        except OSError as exc:
            sys.stderr.write("error: cannot read %s: %s\n" % (path, exc))
            return 2
        for f in findings:
            print("%s %s [%s] %s: %s | %s" % (
                f["severity"].upper(), f["rule"], f["cve"] or f["cwe"], path,
                f["message"], f["evidence"]))
            if f["severity"] == "high":
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    import sys

    sys.exit(main())
