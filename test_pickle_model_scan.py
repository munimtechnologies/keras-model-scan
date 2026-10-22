"""Tests for pickle_model_scan.

These tests build pickle *opcode streams* by hand from pickle's opcode byte
constants. They are detector fixtures, not runnable exploits, and nothing here is
ever unpickled: only pickle_model_scan's static disassembler (pickletools.genops)
ever touches the bytes. Made with AI by MV2 of Munim, Inc.
"""
import io
import os
import pickle
import struct
import tempfile
import unittest
import zipfile

import pickle_model_scan as pms


def su(s):
    """SHORT_BINUNICODE push of a short string."""
    b = s.encode("utf-8")
    return pickle.SHORT_BINUNICODE + bytes([len(b)]) + b


def stack_global(module, name):
    """Opcodes that push a global reference via STACK_GLOBAL (proto 4). No call."""
    return (pickle.PROTO + b"\x04" + su(module) + pickle.MEMOIZE
            + su(name) + pickle.MEMOIZE + pickle.STACK_GLOBAL)


def rules(findings):
    return {f.rule for f in findings}


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def make_npy(descr, payload=b""):
    hdr = "{'descr': %r, 'fortran_order': False, 'shape': (1,), }" % (descr,)
    total = 10 + len(hdr) + 1
    pad = (64 - (total % 64)) % 64
    hdr = hdr + " " * pad + "\n"
    return (b"\x93NUMPY\x01\x00" + struct.pack("<H", len(hdr))
            + hdr.encode("latin1") + payload)


def safetensors_blob():
    js = b'{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    return struct.pack("<Q", len(js)) + js + b"\x00\x00\x00\x00"


class PickleOpcodeTests(unittest.TestCase):
    def test_benign_global_no_findings(self):
        data = stack_global("collections", "OrderedDict") + pickle.STOP
        self.assertEqual(pms.scan_pickle_bytes(data, "x"), [])

    def test_dangerous_with_reduce_is_critical(self):
        data = (stack_global("os", "system") + pickle.EMPTY_TUPLE
                + pickle.REDUCE + pickle.STOP)
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertIn("PKL001", rules(findings))
        self.assertEqual(by_rule(findings, "PKL001")[0].severity, "CRITICAL")

    def test_dangerous_without_reduce_is_high(self):
        data = stack_global("subprocess", "Popen") + pickle.STOP
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertIn("PKL002", rules(findings))
        self.assertEqual(by_rule(findings, "PKL002")[0].severity, "HIGH")

    def test_builtins_eval_is_dangerous(self):
        data = stack_global("builtins", "eval") + pickle.STOP
        self.assertIn("PKL002", rules(pms.scan_pickle_bytes(data, "x")))

    def test_unknown_module_is_medium(self):
        data = stack_global("acme_models", "Widget") + pickle.STOP
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertIn("PKL003", rules(findings))
        self.assertEqual(by_rule(findings, "PKL003")[0].severity, "MEDIUM")

    def test_functools_partial_is_gadget(self):
        data = stack_global("functools", "partial") + pickle.STOP
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertIn("PKL004", rules(findings))
        self.assertEqual(by_rule(findings, "PKL004")[0].severity, "HIGH")

    def test_unresolved_stack_global_is_flagged(self):
        # Operands fetched from the memo (BINGET) instead of pushed as strings:
        # the documented picklescan bypass (GHSA-9gvj-pp9x-gcfr).
        data = (pickle.PROTO + b"\x04" + su("x") + pickle.MEMOIZE
                + pickle.BINGET + b"\x00" + pickle.BINGET + b"\x00"
                + pickle.STACK_GLOBAL + pickle.STOP)
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertIn("PKL007", rules(findings))
        self.assertEqual(by_rule(findings, "PKL007")[0].severity, "HIGH")


class NumpyTests(unittest.TestCase):
    def test_object_dtype_npy_is_flagged(self):
        payload = stack_global("collections", "OrderedDict") + pickle.STOP
        findings = pms.scan_npy(make_npy("|O", payload), "a.npy")
        self.assertIn("PKL010", rules(findings))
        self.assertEqual(by_rule(findings, "PKL010")[0].severity, "HIGH")

    def test_float_dtype_npy_is_clean(self):
        self.assertEqual(pms.scan_npy(make_npy("<f8"), "a.npy"), [])


class SafeFormatTests(unittest.TestCase):
    def test_safetensors_is_info(self):
        findings = pms.scan_safetensors(safetensors_blob(), "m.safetensors")
        self.assertIn("PKL020", rules(findings))
        self.assertEqual(by_rule(findings, "PKL020")[0].severity, "INFO")

    def test_safetensors_malformed(self):
        bad = struct.pack("<Q", 9999) + b"{}"
        self.assertIn("PKL021", rules(pms.scan_safetensors(bad, "m.safetensors")))

    def test_gguf_is_info(self):
        findings = pms.scan_blob(b"GGUF" + b"\x00" * 20, "m.gguf")
        self.assertIn("PKL022", rules(findings))


class ContainerTests(unittest.TestCase):
    def test_zip_torch_pickle_detected(self):
        buf = io.BytesIO()
        danger = (stack_global("os", "system") + pickle.EMPTY_TUPLE
                  + pickle.REDUCE + pickle.STOP)
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", danger)
        findings = pms.scan_blob(buf.getvalue(), "m.pt")
        self.assertTrue({"PKL001", "PKL002"} & rules(findings))

    def test_zip_slip_detected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(zipfile.ZipInfo("../evil.txt"), b"hi")
        self.assertIn("PKL030", rules(pms.scan_blob(buf.getvalue(), "m.zip")))

    def test_gzip_wrapped_pickle_detected(self):
        import gzip
        raw = stack_global("subprocess", "Popen") + pickle.STOP
        findings = pms.scan_blob(gzip.compress(raw), "m.joblib")
        self.assertIn("PKL002", rules(findings))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_exit_code_dangerous(self):
        danger = (stack_global("os", "system") + pickle.EMPTY_TUPLE
                  + pickle.REDUCE + pickle.STOP)
        path = self._write("m.pkl", danger)
        self.assertEqual(pms.main([path]), 1)
        self.assertEqual(pms.main([path, "--json"]), 1)

    def test_exit_code_safe_format(self):
        path = self._write("m.safetensors", safetensors_blob())
        self.assertEqual(pms.main([path]), 0)

    def test_exit_code_missing_file(self):
        self.assertEqual(pms.main([os.path.join(self.dir, "nope.pkl")]), 2)


class F2pyGadgetTests(unittest.TestCase):
    def test_f2py_eval_length_with_reduce_is_critical(self):
        data = (stack_global("numpy.f2py.crackfortran", "_eval_length")
                + pickle.EMPTY_TUPLE + pickle.REDUCE + pickle.STOP)
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertIn("PKL005", rules(findings))
        hit = by_rule(findings, "PKL005")[0]
        self.assertEqual(hit.severity, "CRITICAL")
        self.assertEqual(hit.cve, "CVE-2025-71339")

    def test_f2py_getlincoef_without_reduce_is_high(self):
        data = stack_global("numpy.f2py.crackfortran", "getlincoef") + pickle.STOP
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertIn("PKL005", rules(findings))
        self.assertEqual(by_rule(findings, "PKL005")[0].severity, "HIGH")

    def test_plain_numpy_reconstruct_stays_clean(self):
        # A normal numpy reconstructor must NOT become a false positive.
        data = stack_global("numpy.core.multiarray", "_reconstruct") + pickle.STOP
        findings = pms.scan_pickle_bytes(data, "x")
        self.assertNotIn("PKL005", rules(findings))
        self.assertEqual(findings, [])

    def test_f2py_gadget_inside_object_npy_payload(self):
        payload = (stack_global("numpy.f2py.crackfortran", "_eval_length")
                   + pickle.EMPTY_TUPLE + pickle.REDUCE + pickle.STOP)
        findings = pms.scan_npy(make_npy("|O", payload), "a.npy")
        self.assertIn("PKL005", rules(findings))


if __name__ == "__main__":
    unittest.main()
