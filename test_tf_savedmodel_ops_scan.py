"""Self-contained tests for tf_savedmodel_ops_scan.py (stdlib only).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

Fixtures are SavedModel / GraphDef protobufs encoded by hand with the field
numbers from tensorflow/core/{protobuf,framework}/*.proto; TensorFlow is not
needed and nothing is ever loaded or run.

Run: python -m unittest -v test_tf_savedmodel_ops_scan
"""

import os
import shutil
import tempfile
import unittest

import tf_savedmodel_ops_scan as scan


# --- minimal protobuf encoder ------------------------------------------------

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def ld(field, payload):
    """Length-delimited field."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return varint((field << 3) | 2) + varint(len(payload)) + payload


def vi(field, n):
    """Varint field."""
    return varint(field << 3) + varint(n)


def attr_tensor(*vals):
    """AttrValue{tensor: TensorProto{dtype: DT_STRING, string_val: vals}}."""
    tensor = vi(1, 7) + b"".join(ld(8, v) for v in vals)
    return ld(8, tensor)


def attr_s(val):
    """AttrValue{s: val}."""
    return ld(2, val)


def attr_list_s(*vals):
    """AttrValue{list: ListValue{s: vals}}."""
    return ld(1, b"".join(ld(2, v) for v in vals))


def node(name, op, attrs=()):
    out = ld(1, name) + ld(2, op)
    for key, attr_value in attrs:
        out += ld(5, ld(1, key) + ld(2, attr_value))
    return out


def const(name, *vals):
    return node(name, "Const", [("value", attr_tensor(*vals))])


def function(name, nodes):
    return ld(1, ld(1, name)) + b"".join(ld(3, n) for n in nodes)


def graph(nodes=(), functions=()):
    out = b"".join(ld(1, n) for n in nodes)
    if functions:
        out += ld(2, b"".join(ld(1, f) for f in functions))
    return out


def meta_graph(graph_bytes, op_list=()):
    out = b""
    if op_list:
        ops = b"".join(ld(1, ld(1, o)) for o in op_list)
        out += ld(1, ld(2, ops))
    out += ld(2, graph_bytes)
    return out


def saved_model(*metas):
    return vi(1, 1) + b"".join(ld(2, m) for m in metas)


def rules(findings):
    return sorted(f["rule"] for f in findings)


BENIGN_NODES = [
    node("x", "Placeholder"),
    node("w", "VarHandleOp"),
    node("mm", "MatMul"),
    const("sep", "_temp/part"),
    node("save", "SaveV2"),
    node("restore", "RestoreV2"),
    node("merge", "MergeV2Checkpoints"),
]


class TestWriteOps(unittest.TestCase):
    def test_writefile_in_graph_flags_tfsm001(self):
        data = saved_model(meta_graph(graph([node("wf", "WriteFile")])))
        f = scan.scan_bytes(data, name="saved_model.pb")
        self.assertEqual(rules(f), ["TFSM001"])
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["cwe"], "CWE-73")
        self.assertEqual(f[0]["cve"], "")
        self.assertIn("meta_graph[0]:graph", f[0]["evidence"])
        self.assertIn("node='wf'", f[0]["evidence"])

    def test_dataset_writer_in_function_flags_tfsm001(self):
        fn = function("__inference_export_123", [node("w", "DatasetToTFRecord")])
        data = saved_model(meta_graph(graph(functions=[fn])))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM001"])
        self.assertIn("function:__inference_export_123", f[0]["evidence"])

    def test_printv2_file_stream_flags_tfsm001(self):
        p = node("p", "PrintV2", [("output_stream", attr_s("file:///tmp/out.txt"))])
        data = saved_model(meta_graph(graph([p])))
        self.assertEqual(rules(scan.scan_bytes(data)), ["TFSM001"])

    def test_printv2_stderr_is_clean(self):
        p = node("p", "PrintV2", [("output_stream", attr_s("stderr"))])
        data = saved_model(meta_graph(graph([p])))
        self.assertEqual(scan.scan_bytes(data), [])


class TestReadOps(unittest.TestCase):
    def test_readfile_in_function_flags_tfsm002(self):
        fn = function("__inference_serve_7", [node("rf", "ReadFile")])
        data = saved_model(meta_graph(graph(functions=[fn])))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM002"])
        self.assertEqual(f[0]["severity"], "high")
        self.assertIn("function:__inference_serve_7", f[0]["evidence"])

    def test_reader_without_outside_path_is_tfsm003(self):
        data = saved_model(meta_graph(graph([
            const("fn", "data/train.txt"),
            node("ds", "TextLineDataset"),
        ])))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM003"])
        self.assertEqual(f[0]["severity"], "medium")

    def test_reader_with_absolute_path_escalates_tfsm002(self):
        data = saved_model(meta_graph(graph([
            const("fn", "/etc/passwd"),
            node("ds", "TextLineDataset"),
        ])))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM002"])
        self.assertIn("/etc/passwd", f[0]["evidence"])

    def test_matchingfiles_with_dotdot_escalates(self):
        data = saved_model(meta_graph(graph([
            const("pat", "../../secrets/*"),
            node("mf", "MatchingFiles"),
        ])))
        self.assertEqual(rules(scan.scan_bytes(data)), ["TFSM002"])

    def test_immutableconst_attr_path_escalates(self):
        ic = node("ic", "ImmutableConst",
                  [("memory_region_name", attr_s("/dev/shm/region"))])
        data = saved_model(meta_graph(graph([ic])))
        self.assertEqual(rules(scan.scan_bytes(data)), ["TFSM002"])

    def test_list_attr_string_counts_as_path(self):
        n = node("ds", "TFRecordDataset",
                 [("filenames_hint", attr_list_s("ok", "gs://bucket/x"))])
        data = saved_model(meta_graph(graph([n])))
        self.assertEqual(rules(scan.scan_bytes(data)), ["TFSM002"])

    def test_table_init_never_escalates(self):
        data = saved_model(meta_graph(graph([
            const("asset", "/home/user/export/vocab.txt"),
            node("init", "InitializeTableFromTextFileV2"),
        ])))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM003"])
        self.assertIn("outside_paths", f[0]["evidence"])

    def test_device_string_is_not_a_path(self):
        data = saved_model(meta_graph(graph([
            const("d", "/job:localhost/replica:0/task:0/device:CPU:0"),
            node("ds", "TextLineDataset"),
        ])))
        self.assertEqual(rules(scan.scan_bytes(data)), ["TFSM003"])


class TestPythonCallback(unittest.TestCase):
    def test_pyfunc_flags_tfsm005(self):
        fn = function("f", [node("cb", "EagerPyFunc")])
        data = saved_model(meta_graph(graph(functions=[fn])))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM005"])
        self.assertEqual(f[0]["severity"], "medium")
        self.assertEqual(f[0]["cwe"], "CWE-94")


class TestStructure(unittest.TestCase):
    def test_benign_model_is_clean(self):
        fn = function("__inference_call_1", [node("relu", "Relu")])
        data = saved_model(meta_graph(graph(BENIGN_NODES, [fn])))
        self.assertEqual(scan.scan_bytes(data), [])

    def test_frozen_graphdef(self):
        data = graph([node("x", "Placeholder"), node("wf", "WriteFile")])
        self.assertEqual(data[:1], b"\x0a")
        f = scan.scan_bytes(data, name="frozen.pb")
        self.assertEqual(rules(f), ["TFSM001"])
        self.assertTrue(f[0]["evidence"].startswith("graph:"))

    def test_graphdef_with_only_library(self):
        data = graph(functions=[function("lib_fn", [node("rf", "ReadFile")])])
        self.assertEqual(data[:1], b"\x12")
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM002"])
        self.assertIn("function:lib_fn", f[0]["evidence"])

    def test_stripped_op_list_reported_when_no_node(self):
        data = saved_model(meta_graph(graph([node("x", "Placeholder")]),
                                      op_list=["Placeholder", "WriteFile"]))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM001"])
        self.assertIn("stripped_op_list", f[0]["evidence"])

    def test_stripped_op_list_not_double_reported(self):
        data = saved_model(meta_graph(graph([node("wf", "WriteFile")]),
                                      op_list=["WriteFile"]))
        self.assertEqual(rules(scan.scan_bytes(data)), ["TFSM001"])

    def test_second_meta_graph(self):
        data = saved_model(meta_graph(graph(BENIGN_NODES)),
                           meta_graph(graph([node("rf", "ReadFile")])))
        f = scan.scan_bytes(data)
        self.assertEqual(rules(f), ["TFSM002"])
        self.assertIn("meta_graph[1]:graph", f[0]["evidence"])

    def test_same_node_reported_once(self):
        data = saved_model(meta_graph(graph([node("wf", "WriteFile"),
                                             node("wf", "WriteFile")])))
        self.assertEqual(len(scan.scan_bytes(data)), 1)

    def test_truncated_input_does_not_raise(self):
        data = saved_model(meta_graph(graph([node("wf", "WriteFile")])))
        for cut in range(1, len(data)):
            self.assertIsInstance(scan.scan_bytes(data[:cut]), list)


class TestPbtxt(unittest.TestCase):
    def test_pbtxt_readfile(self):
        text = (b'saved_model_schema_version: 1\nmeta_graphs {\n  graph_def {\n'
                b'    node {\n      name: "rf"\n      op: "ReadFile"\n    }\n'
                b'  }\n}\n')
        f = scan.scan_bytes(text, name="saved_model.pbtxt")
        self.assertEqual(rules(f), ["TFSM002"])
        self.assertTrue(f[0]["evidence"].startswith("pbtxt:"))

    def test_pbtxt_reader_with_path(self):
        text = (b'node {\n  name: "c"\n  op: "Const"\n  attr {\n    key: "value"\n'
                b'    value {\n      tensor {\n        dtype: DT_STRING\n'
                b'        string_val: "/etc/shadow"\n      }\n    }\n  }\n}\n'
                b'node {\n  name: "ds"\n  op: "TextLineDataset"\n}\n')
        self.assertEqual(rules(scan.scan_bytes(text)), ["TFSM002"])

    def test_pbtxt_benign(self):
        text = b'node {\n  name: "x"\n  op: "Placeholder"\n}\n'
        self.assertEqual(scan.scan_bytes(text), [])


class TestOutsidePathHelper(unittest.TestCase):
    def test_cases(self):
        self.assertTrue(scan._outside_path("/etc/passwd"))
        self.assertTrue(scan._outside_path("../x"))
        self.assertTrue(scan._outside_path("a/../../b"))
        self.assertTrue(scan._outside_path("file:///tmp/x"))
        self.assertTrue(scan._outside_path("gs://bucket/obj"))
        self.assertTrue(scan._outside_path("~/.ssh/id_rsa"))
        self.assertTrue(scan._outside_path("C:\\Windows\\x"))
        self.assertTrue(scan._outside_path("\\\\host\\share"))
        self.assertFalse(scan._outside_path("/"))
        self.assertFalse(scan._outside_path("/job:localhost/device:CPU:0"))
        self.assertFalse(scan._outside_path("assets/vocab.txt"))
        self.assertFalse(scan._outside_path("_temp/part"))
        self.assertFalse(scan._outside_path("..."))
        self.assertFalse(scan._outside_path(""))


class TestOutOfScope(unittest.TestCase):
    def test_empty_and_garbage(self):
        self.assertEqual(scan.scan_bytes(b""), [])
        self.assertEqual(scan.scan_bytes(b"not a saved model at all"), [])

    def test_pickle_and_zip_are_out_of_scope(self):
        self.assertEqual(scan.scan_bytes(b"cos\nsystem\n(S'id'\ntR."), [])
        self.assertEqual(scan.scan_bytes(b"\x80\x04\x8c\x02os\x8c\x06system\x93)R."), [])
        self.assertEqual(scan.scan_bytes(b"PK\x03\x04" + b"\x00" * 26), [])


class TestFindingShape(unittest.TestCase):
    def test_keys_and_lowercase_severity(self):
        data = saved_model(meta_graph(graph([
            node("wf", "WriteFile"), node("rf", "ReadFile"),
            node("ds", "TextLineDataset"), node("cb", "PyFunc"),
        ])))
        findings = scan.scan_bytes(data)
        self.assertEqual(rules(findings), ["TFSM001", "TFSM002", "TFSM003", "TFSM005"])
        for f in findings:
            self.assertEqual(set(f), {"rule", "severity", "cve", "cwe",
                                      "message", "evidence"})
            self.assertEqual(f["severity"], f["severity"].lower())
            self.assertIn(f["severity"], {"high", "medium", "low"})
            self.assertTrue(f["cwe"])

    def test_version(self):
        self.assertEqual(scan.__version__, "0.1.0")


class TestScanFileAndMain(unittest.TestCase):
    def _write(self, data, suffix=".pb"):
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        with open(path, "wb") as fh:
            fh.write(data)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_scan_file_roundtrip(self):
        path = self._write(saved_model(meta_graph(graph([node("wf", "WriteFile")]))))
        self.assertEqual(rules(scan.scan_file(path)), ["TFSM001"])

    def test_scan_savedmodel_directory(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "saved_model.pb"), "wb") as fh:
            fh.write(saved_model(meta_graph(graph([node("rf", "ReadFile")]))))
        self.assertEqual(rules(scan.scan_file(d)), ["TFSM002"])

    def test_directory_without_saved_model_raises(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with self.assertRaises(OSError):
            scan.scan_file(d)

    def test_main_high_returns_1(self):
        path = self._write(saved_model(meta_graph(graph([node("wf", "WriteFile")]))))
        self.assertEqual(scan.main([path]), 1)

    def test_main_medium_only_returns_0(self):
        path = self._write(saved_model(meta_graph(graph([node("cb", "PyFunc")]))))
        self.assertEqual(scan.main([path]), 0)

    def test_main_benign_returns_0(self):
        path = self._write(saved_model(meta_graph(graph(BENIGN_NODES))))
        self.assertEqual(scan.main([path]), 0)

    def test_main_usage_returns_2(self):
        self.assertEqual(scan.main([]), 2)

    def test_main_unreadable_returns_2(self):
        self.assertEqual(scan.main([os.path.join(tempfile.gettempdir(),
                                                 "nope-tfsm-missing.pb")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
