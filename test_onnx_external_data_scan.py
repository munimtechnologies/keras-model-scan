# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Self-contained tests for onnx_external_data_scan. Builds tiny ONNX protobufs
# by hand (standard library only) so no onnx package or network is needed.
#
# This work was made with AI, by MV2 of Munim, Inc.

import os
import tempfile
import unittest

import onnx_external_data_scan as oed


# ---- minimal protobuf encoders (mirror of the wire format) ----------------

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _tag(field: int, wt: int) -> bytes:
    return _varint((field << 3) | wt)


def _ld(field: int, payload: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(payload)) + payload


def _vint(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def _str(field: int, s: str) -> bytes:
    return _ld(field, s.encode("utf-8", "surrogateescape"))


# ---- ONNX message builders ------------------------------------------------

def _ext_entry(key: str, value: str) -> bytes:
    # StringStringEntryProto: key=1, value=2
    return _str(1, key) + _str(2, value)


def _tensor(location: str, name: str = "w", data_location: int = 1) -> bytes:
    # TensorProto: name=8, external_data=13, data_location=14
    body = _str(8, name)
    body += _vint(14, data_location)
    body += _ld(13, _ext_entry("location", location))
    return body


def _graph_with_initializer(location: str, name: str = "w") -> bytes:
    # GraphProto: name=2, initializer=5
    body = _str(2, "g")
    body += _ld(5, _tensor(location, name))
    return body


def _model(graph: bytes) -> bytes:
    # ModelProto: ir_version=1, producer_name=2, graph=7
    body = _vint(1, 9)
    body += _str(2, "test")
    body += _ld(7, graph)
    return body


def _model_with_location(location: str) -> bytes:
    return _model(_graph_with_initializer(location))


def _rules(findings) -> set:
    return {f.rule for f in findings}


class TestScanBytes(unittest.TestCase):

    def _scan(self, location: str):
        return oed.scan_bytes(_model_with_location(location), "m.onnx")

    def test_clean_relative_location(self):
        self.assertEqual(self._scan("weights.bin"), [])

    def test_clean_relative_subdir(self):
        self.assertEqual(self._scan("shards/weights-00001.bin"), [])

    def test_absolute_posix(self):
        f = self._scan("/etc/passwd")
        self.assertEqual(_rules(f), {"OED002"})
        self.assertEqual(f[0].severity, "HIGH")
        self.assertEqual(f[0].cve, "CWE-22")

    def test_absolute_windows_drive(self):
        f = self._scan("C:\\Windows\\win.ini")
        # drive-letter absolute path AND a backslash separator
        self.assertEqual(_rules(f), {"OED002", "OED005"})

    def test_traversal(self):
        f = self._scan("../../../etc/passwd")
        self.assertEqual(_rules(f), {"OED001"})
        self.assertEqual(f[0].severity, "HIGH")

    def test_url_scheme(self):
        f = self._scan("https://evil.example/w.bin")
        self.assertEqual(_rules(f), {"OED003"})
        self.assertEqual(f[0].cve, "CWE-918")

    def test_file_url_scheme(self):
        f = self._scan("file:///etc/shadow")
        self.assertIn("OED003", _rules(f))

    def test_nul_byte(self):
        f = self._scan("weights.bin\x00.png")
        self.assertEqual(_rules(f), {"OED004"})

    def test_backslash_separator(self):
        f = self._scan("sub\\weights.bin")
        self.assertEqual(_rules(f), {"OED005"})
        self.assertEqual(f[0].severity, "MEDIUM")

    def test_backslash_traversal(self):
        f = self._scan("..\\..\\secret")
        self.assertEqual(_rules(f), {"OED001", "OED005"})

    def test_offset_key_is_ignored(self):
        # only the "location" key is linted, not offset/length/checksum
        tensor = _str(8, "w") + _vint(14, 1)
        tensor += _ld(13, _ext_entry("offset", "../../etc/passwd"))
        model = _model(_str(2, "g") + _ld(5, tensor))
        self.assertEqual(oed.scan_bytes(model, "m.onnx"), [])

    def test_nested_subgraph_recursion(self):
        # bad tensor hidden inside an If-node subgraph (AttributeProto.g)
        sub = _graph_with_initializer("../../../etc/passwd")
        attr = _str(1, "then_branch") + _vint(20, 5) + _ld(6, sub)  # type=GRAPH
        node = _str(4, "If") + _ld(5, attr)                         # op_type, attr
        graph = _str(2, "g") + _ld(1, node)                         # node=1
        f = oed.scan_bytes(_model(graph), "m.onnx")
        self.assertEqual(_rules(f), {"OED001"})

    def test_malformed_tail_does_not_raise(self):
        data = _model_with_location("weights.bin") + b"\xff\xff\xff"
        # should not raise; truncated tail is ignored
        oed.scan_bytes(data, "m.onnx")

    def test_empty_input(self):
        self.assertEqual(oed.scan_bytes(b"", "m.onnx"), [])


class TestScanFileAndCli(unittest.TestCase):

    def _write(self, dirpath: str, name: str, location: str) -> str:
        p = os.path.join(dirpath, name)
        with open(p, "wb") as fh:
            fh.write(_model_with_location(location))
        return p

    def test_scan_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "bad.onnx", "/etc/passwd")
            self.assertEqual(_rules(oed.scan_file(p)), {"OED002"})

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "a.onnx", "../x")
            self._write(d, "b.onnx", "weights.bin")
            self.assertEqual(_rules(oed.scan_path(d)), {"OED001"})

    def test_cli_fail_on_high(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "bad.onnx", "../../etc/passwd")
            self.assertEqual(oed.main([p, "--fail-on", "HIGH"]), 1)

    def test_cli_fail_on_critical_passes(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "bad.onnx", "../../etc/passwd")
            # highest finding is HIGH, so a CRITICAL threshold does not fail
            self.assertEqual(oed.main([p, "--fail-on", "CRITICAL"]), 0)

    def test_cli_clean_passes(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "ok.onnx", "weights.bin")
            self.assertEqual(oed.main([p, "--fail-on", "LOW"]), 0)

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "bad.onnx", "/etc/passwd")
            self.assertEqual(oed.main([p, "--json", "--fail-on", "CRITICAL"]), 0)

    def test_cli_no_args(self):
        self.assertEqual(oed.main([]), 2)


if __name__ == "__main__":
    unittest.main()
