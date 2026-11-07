# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Tests for onnx_external_data_scan 0.2.0 and onnx_external_data_key_scan 0.2.0:
# tensors in a model's local functions (ModelProto.functions, field 25) and in
# training_info graphs (field 20) are now walked, and onnx_external_data_scan
# reads up to protobuf's 2 GiB message limit instead of stopping at 256 MiB.
#
# onnx's own loader (external_data_helper._get_all_tensors) loads external data
# for attribute tensors of FunctionProto nodes, and onnx.save_model(...,
# convert_attribute=True) writes them, so a CI gate has to read them too.
# Standard library only: the protobuf bytes are built by hand.
#
# This work was made with AI agents working in the name of MV2 of Munim, Inc.

import os
import shutil
import tempfile
import unittest

import onnx_external_data_key_scan as oek
import onnx_external_data_scan as oed


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


def _ld(field, payload):
    return _varint((field << 3) | 2) + _varint(len(payload)) + payload


def _vint(field, value):
    return _varint(field << 3) + _varint(value)


def _str(field, s):
    return _ld(field, s.encode("utf-8"))


def _entry(key, value):
    return _str(1, key) + _str(2, value)


def _tensor(entries, name="t"):
    # TensorProto: name=8, data_location=14 (EXTERNAL=1), external_data=13
    body = _str(8, name) + _vint(14, 1)
    for key, value in entries:
        body += _ld(13, _entry(key, value))
    return body


def _tensor_attr(tensor, name="value"):
    # AttributeProto: name=1, type=20 (TENSOR=4), t=5
    return _str(1, name) + _vint(20, 4) + _ld(5, tensor)


def _node(op, attrs=()):
    # NodeProto: op_type=4, attribute=5
    body = _str(4, op)
    for a in attrs:
        body += _ld(5, a)
    return body


def _graph(initializers=(), nodes=()):
    body = b""
    for n in nodes:
        body += _ld(1, n)
    body += _str(2, "g")
    for t in initializers:
        body += _ld(5, t)
    return body


def _function(nodes=(), attribute_protos=()):
    # FunctionProto: name=1, node=7, domain=10, attribute_proto=11
    body = _str(1, "F")
    for n in nodes:
        body += _ld(7, n)
    body += _str(10, "local")
    for a in attribute_protos:
        body += _ld(11, a)
    return body


def _training_info(initialization=None, algorithm=None):
    body = b""
    if initialization is not None:
        body += _ld(1, initialization)
    if algorithm is not None:
        body += _ld(2, algorithm)
    return body


def _model(graph=None, functions=(), training=()):
    body = _vint(1, 10) + _str(2, "test")
    if graph is not None:
        body += _ld(7, graph)
    for t in training:
        body += _ld(20, t)
    for f in functions:
        body += _ld(25, f)
    return body


def _honest_graph():
    return _graph(initializers=[_tensor([("location", "weights.bin")], "W")])


def _rules(findings):
    return {f.rule for f in findings}


def _version(mod):
    return tuple(int(p) for p in mod.__version__.split("."))


class TestVersions(unittest.TestCase):

    def test_versions(self):
        self.assertGreaterEqual(_version(oed), (0, 2, 0))
        self.assertGreaterEqual(_version(oek), (0, 2, 0))


class TestFunctions(unittest.TestCase):

    def _func_model(self, location):
        const = _node("Constant", [_tensor_attr(
            _tensor([("location", location)], "fconst"))])
        return _model(_honest_graph(), functions=[_function([const])])

    def test_honest_function_tensor_is_clean(self):
        self.assertEqual(oed.scan_bytes(self._func_model("weights.bin"),
                                        "m.onnx"), [])

    def test_function_constant_parent_dir(self):
        f = oed.scan_bytes(self._func_model("../outside.bin"), "m.onnx")
        self.assertEqual(_rules(f), {"OED001"})

    def test_function_attribute_proto_absolute(self):
        default = _tensor_attr(_tensor([("location", "/abs/w.bin")], "d"),
                               name="bias")
        model = _model(_honest_graph(),
                       functions=[_function(attribute_protos=[default])])
        self.assertEqual(_rules(oed.scan_bytes(model, "m.onnx")), {"OED002"})

    def test_function_subgraph(self):
        sub = _graph(initializers=[_tensor([("location", "../s.bin")], "s")])
        attr = _str(1, "then_branch") + _vint(20, 5) + _ld(6, sub)
        model = _model(_honest_graph(),
                       functions=[_function([_node("If", [attr])])])
        self.assertEqual(_rules(oed.scan_bytes(model, "m.onnx")), {"OED001"})

    def test_functions_without_graph(self):
        const = _node("Constant", [_tensor_attr(
            _tensor([("location", "../x.bin")]))])
        model = _model(None, functions=[_function([const])])
        self.assertEqual(_rules(oed.scan_bytes(model, "m.onnx")), {"OED001"})

    def test_key_scan_function_tensor(self):
        const = _node("Constant", [_tensor_attr(
            _tensor([("location", "w.bin"), ("owner", "x")]))])
        model = _model(_honest_graph(), functions=[_function([const])])
        keys = sorted(f.key for f in oek.scan_bytes(model)
                      if f.rule == "OEK001")
        self.assertEqual(keys, ["owner"])

    def test_key_scan_honest_function_clean(self):
        const = _node("Constant", [_tensor_attr(
            _tensor([("location", "w.bin"), ("offset", "0"),
                     ("length", "4096")]))])
        model = _model(_honest_graph(), functions=[_function([const])])
        self.assertEqual(oek.scan_bytes(model), [])


class TestTrainingInfo(unittest.TestCase):

    def test_training_initialization(self):
        init = _graph(initializers=[_tensor([("location", "..\\t.bin")])])
        model = _model(_honest_graph(),
                       training=[_training_info(initialization=init)])
        self.assertEqual(_rules(oed.scan_bytes(model, "m.onnx")),
                         {"OED001", "OED005"})

    def test_training_algorithm(self):
        algo = _graph(initializers=[_tensor([("location", "/abs/a.bin")])])
        model = _model(_honest_graph(),
                       training=[_training_info(algorithm=algo)])
        self.assertEqual(_rules(oed.scan_bytes(model, "m.onnx")), {"OED002"})

    def test_honest_training_clean(self):
        init = _graph(initializers=[_tensor([("location", "t.bin")])])
        model = _model(_honest_graph(),
                       training=[_training_info(initialization=init)])
        self.assertEqual(oed.scan_bytes(model, "m.onnx"), [])

    def test_key_scan_training(self):
        init = _graph(initializers=[_tensor([("location", "t.bin"),
                                             ("evil", "1")])])
        model = _model(_honest_graph(),
                       training=[_training_info(initialization=init)])
        keys = sorted(f.key for f in oek.scan_bytes(model)
                      if f.rule == "OEK001")
        self.assertEqual(keys, ["evil"])


class TestSizeLimit(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_limit_is_protobuf_limit(self):
        self.assertGreaterEqual(oed.MAX_BYTES, 2 * 1024 * 1024 * 1024)

    def test_memoryview_input(self):
        model = _model(_graph(initializers=[_tensor([("location", "../m")])]))
        self.assertEqual(_rules(oed.scan_bytes(memoryview(model), "m")),
                         {"OED001"})

    def test_file_over_limit_reports_oed006(self):
        path = os.path.join(self.tmp, "big.onnx")
        with open(path, "wb") as fh:
            fh.write(_model(_honest_graph()) + b"\x00" * 64)
        saved = oed.MAX_BYTES
        try:
            oed.MAX_BYTES = 16
            findings = oed.scan_file(path)
        finally:
            oed.MAX_BYTES = saved
        self.assertIn("OED006", _rules(findings))
        f6 = [f for f in findings if f.rule == "OED006"][0]
        self.assertEqual(f6.severity, "MEDIUM")
        self.assertEqual(oed.scan_file(path), [])

    def test_cli_over_limit_fails_closed(self):
        path = os.path.join(self.tmp, "big.onnx")
        with open(path, "wb") as fh:
            fh.write(_model(_honest_graph()) + b"\x00" * 64)
        saved = oed.MAX_BYTES
        try:
            oed.MAX_BYTES = 16
            self.assertEqual(oed.main([path]), 1)
            self.assertEqual(oed.main([path, "--fail-on", "HIGH"]), 0)
        finally:
            oed.MAX_BYTES = saved


if __name__ == "__main__":
    unittest.main()
