"""Self-contained tests for onnx_external_data_key_scan.

The scanner parses the ONNX protobuf wire format with a hand-written reader. These
tests build crafted, header-only ModelProto bytes with an INDEPENDENT hand-written
encoder (no onnx dependency, no shared code with the scanner) and assert the scanner
flags exactly the unexpected external_data keys -- including keys nested in node
attributes, subgraphs and sparse initializers. If the encoder and the scanner's
reader disagreed on the wire format, these tests would fail, so a green run is a
genuine round-trip proof, not a tautology.

Made with AI by MV2 of Munim, Inc. Licence: Apache-2.0.
"""

import os
import tempfile
import unittest

import onnx_external_data_key_scan as scan


# --- independent protobuf encoder (reused by every fixture) ---------------------

def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field, wire):
    return _varint((field << 3) | wire)


def _ld(field, payload):  # length-delimited (wire type 2)
    return _tag(field, 2) + _varint(len(payload)) + payload


def _vint(field, value):  # varint (wire type 0)
    return _tag(field, 0) + _varint(value)


def _string(field, s):
    return _ld(field, s.encode("utf-8"))


def _sse(key, value):  # StringStringEntryProto: key=1, value=2
    return _string(1, key) + _string(2, value)


def _tensor(entries, data_location=1):
    """TensorProto with data_location (14) and external_data entries (13)."""
    body = _vint(14, data_location)
    for key, value in entries:
        body += _ld(13, _sse(key, value))
    return body


def _graph(initializers=(), nodes=(), sparse_inits=()):
    body = b""
    for n in nodes:
        body += _ld(1, n)          # node = 1
    for t in initializers:
        body += _ld(5, t)          # initializer = 5
    for st in sparse_inits:
        body += _ld(15, st)        # sparse_initializer = 15
    return body


def _model(graph):
    return _ld(7, graph)           # ModelProto.graph = 7


def _attr_subgraph(graph):
    return _ld(6, graph)           # AttributeProto.g = 6


def _node(attrs=()):
    body = b""
    for a in attrs:
        body += _ld(5, a)          # NodeProto.attribute = 5
    return body


def _sparse_tensor(values_tensor):
    return _ld(1, values_tensor)   # SparseTensorProto.values = 1


# --- tests ----------------------------------------------------------------------

class TestKeyScan(unittest.TestCase):

    def _keys(self, findings):
        return sorted(f.key for f in findings if f.rule == "OEK001")

    def test_clean_location_only(self):
        data = _model(_graph(initializers=[_tensor([("location", "w.bin")])]))
        self.assertEqual(scan.scan_bytes(data), [])

    def test_clean_full_spec_keys(self):
        data = _model(_graph(initializers=[_tensor([
            ("location", "w.bin"), ("offset", "0"),
            ("length", "1024"), ("checksum", "abc")])]))
        self.assertEqual(scan.scan_bytes(data), [])

    def test_basepath_is_allowed(self):
        data = _model(_graph(initializers=[_tensor([
            ("location", "w.bin"), ("basepath", "/models")])]))
        self.assertEqual(scan.scan_bytes(data), [])

    def test_dunder_key_flagged(self):
        data = _model(_graph(initializers=[_tensor([
            ("location", "w.bin"), ("__class__", "evil")])]))
        findings = [f for f in scan.scan_bytes(data) if f.rule == "OEK001"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].key, "__class__")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("attribute-injection", findings[0].message)

    def test_arbitrary_key_flagged(self):
        data = _model(_graph(initializers=[_tensor([
            ("location", "w.bin"), ("owner", "x")])]))
        self.assertEqual(self._keys(scan.scan_bytes(data)), ["owner"])

    def test_nested_subgraph_tensor(self):
        inner = _graph(initializers=[_tensor([("location", "w"), ("evil", "1")])])
        node = _node(attrs=[_attr_subgraph(inner)])
        data = _model(_graph(nodes=[node]))
        self.assertEqual(self._keys(scan.scan_bytes(data)), ["evil"])

    def test_sparse_initializer_tensor(self):
        st = _sparse_tensor(_tensor([("location", "w"), ("__dict__", "1")]))
        data = _model(_graph(sparse_inits=[st]))
        self.assertEqual(self._keys(scan.scan_bytes(data)), ["__dict__"])

    def test_multiple_bad_keys(self):
        data = _model(_graph(initializers=[_tensor([
            ("location", "w"), ("a", "1"), ("b", "2")])]))
        self.assertEqual(self._keys(scan.scan_bytes(data)), ["a", "b"])

    def test_empty_graph_clean(self):
        self.assertEqual(scan.scan_bytes(_model(_graph())), [])

    def test_unparseable_reports_oek000(self):
        findings = scan.scan_bytes(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
        self.assertTrue(any(f.rule == "OEK000" for f in findings))

    def test_scan_file_and_main_exit(self):
        data = _model(_graph(initializers=[_tensor([
            ("location", "w"), ("__class__", "evil")])]))
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "model.onnx")
        with open(path, "wb") as fh:
            fh.write(data)
        self.assertEqual(self._keys(scan.scan_file(path)), ["__class__"])
        # a HIGH finding must make the CLI exit non-zero at the default threshold
        self.assertEqual(scan.main([path]), 1)
        clean = os.path.join(tmp, "clean.onnx")
        with open(clean, "wb") as fh:
            fh.write(_model(_graph(initializers=[_tensor([("location", "w")])])))
        self.assertEqual(scan.main([clean]), 0)


if __name__ == "__main__":
    unittest.main()
