"""Tests for msgpack_weights_scan.py. Standard library only; fixtures are
MessagePack and pickle bytes built by hand and are never loaded or run.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import contextlib
import io
import os
import shutil
import struct
import tempfile
import unittest

import msgpack_weights_scan as mws


class Ext(object):
    def __init__(self, code, data):
        self.code = code
        self.data = data


class RawStr(object):
    """A str-typed value holding raw bytes, as old raw-mode packers wrote."""

    def __init__(self, data):
        self.data = data


def pack(obj):
    if obj is None:
        return b"\xc0"
    if obj is True:
        return b"\xc3"
    if obj is False:
        return b"\xc2"
    if isinstance(obj, int):
        if 0 <= obj < 128:
            return bytes([obj])
        if -32 <= obj < 0:
            return struct.pack("b", obj)
        if 0 <= obj < 2 ** 32:
            return b"\xce" + struct.pack(">I", obj)
        return b"\xd3" + struct.pack(">q", obj)
    if isinstance(obj, float):
        return b"\xcb" + struct.pack(">d", obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        if len(raw) < 32:
            return bytes([0xA0 | len(raw)]) + raw
        return b"\xda" + struct.pack(">H", len(raw)) + raw
    if isinstance(obj, RawStr):
        return b"\xdb" + struct.pack(">I", len(obj.data)) + obj.data
    if isinstance(obj, (bytes, bytearray)):
        return b"\xc6" + struct.pack(">I", len(obj)) + bytes(obj)
    if isinstance(obj, Ext):
        return b"\xc9" + struct.pack(">Ib", len(obj.data), obj.code) + obj.data
    if isinstance(obj, (list, tuple)):
        return b"\xdd" + struct.pack(">I", len(obj)) + b"".join(
            pack(x) for x in obj)
    if isinstance(obj, dict):
        return b"\xdf" + struct.pack(">I", len(obj)) + b"".join(
            pack(k) + pack(v) for k, v in obj.items())
    raise TypeError(type(obj))


def flax_array(shape, dtype, buffer, code=1):
    return Ext(code, pack([list(shape), dtype, buffer]))


def mn_array(data, kind=b"O", str_keys=False):
    """A msgpack-numpy array map, keys as bin (as msgpack-numpy writes them)
    or as str."""
    def k(s):
        return s.decode("ascii") if str_keys else s

    return {k(b"nd"): True, k(b"type"): [["", "|O"]], k(b"kind"): kind,
            k(b"shape"): [1], k(b"data"): data}


# Pickle opcode streams (never loaded).
P_NUMPY = (b"\x80\x02cnumpy.core.multiarray\n_reconstruct\n"
           b"cnumpy\nndarray\nK\x00\x85\x86R.")
P_GLOBAL = b"\x80\x02cbuiltins\nprint\nX\x02\x00\x00\x00hi\x85R."
P_STACK = b"\x80\x04\x8c\x08builtins\x94\x8c\x05print\x94\x93."
P_MEMO = b"\x80\x04\x8c\x08builtins\x94\x8c\x05print\x94K\x01h\x00h\x01\x93."
P_STALE = b"\x80\x04\x8c\x05numpy\x94\x8c\x07ndarray\x94K\x01\x93."
P_COMPUTED = b"\x80\x04K\x01K\x02\x93."
P_BROKEN = b"\x80\x02cbuiltins\nprint\n\xff"


def rules(findings):
    return [f["rule"] for f in findings]


def scan(obj):
    return mws.scan_bytes(pack(obj), "w.msgpack")


class FlaxTests(unittest.TestCase):
    def test_clean_flax_state_dict(self):
        state = {
            "params": {"Dense_0": {
                "kernel": flax_array([2, 3], "float32", b"\x00" * 24),
                "bias": flax_array([3], "float32", b"\x00" * 12),
            }},
            "step": flax_array([], "int64", b"\x00" * 8, code=3),
        }
        self.assertEqual(scan(state), [])

    def test_bfloat16_and_complex_and_timestamp(self):
        doc = [flax_array([4], "bfloat16", b"\x00" * 8),
               Ext(2, pack([1.0, 2.0])), Ext(-1, b"\x00" * 4)]
        self.assertEqual(scan(doc), [])

    def test_size_mismatch(self):
        f = scan({"k": flax_array([2, 3], "float32", b"\x00" * 20)})
        self.assertEqual(rules(f), ["MPK003"])
        self.assertIn("needs 24 bytes", f[0]["evidence"])
        self.assertIn("holds 20", f[0]["evidence"])
        self.assertIn("w.msgpack:/k", f[0]["evidence"])

    def test_object_dtypes(self):
        for name in ("object", "O", "|O", "i4,f8", "(2,)i4"):
            f = scan(flax_array([1], name, b"\x00" * 8))
            self.assertEqual(rules(f), ["MPK003"], name)
            self.assertIn("object or structured", f[0]["evidence"])

    def test_datetime_dtype_not_structured(self):
        self.assertEqual(scan(flax_array([1], "datetime64[ns]",
                                         b"\x00" * 8)), [])

    def test_unknown_dtype_skips_size_check(self):
        self.assertEqual(scan(flax_array([3], "float8_e8m0fnu",
                                         b"\x00" * 5)), [])

    def test_payload_not_triple(self):
        f = scan(Ext(1, pack([1, 2])))
        self.assertEqual(rules(f), ["MPK003"])
        self.assertIn("triple", f[0]["evidence"])

    def test_payload_not_msgpack(self):
        f = scan(Ext(3, b"\xc1"))
        self.assertEqual(rules(f), ["MPK003"])
        self.assertIn("scalar payload is not MessagePack", f[0]["evidence"])

    def test_bad_shape(self):
        f = scan(flax_array([-1], "float32", b""))
        self.assertEqual(rules(f), ["MPK003"])
        self.assertIn("non-negative", f[0]["evidence"])
        f = scan(flax_array([1] * 65, "float32", b"\x00" * 4))
        self.assertEqual(rules(f), ["MPK003"])
        self.assertIn("65 dimensions", f[0]["evidence"])

    def test_unknown_ext_type(self):
        f = scan({"x": Ext(42, b"abc")})
        self.assertEqual(rules(f), ["MPK004"])
        self.assertIn("extension type 42", f[0]["evidence"])


class MsgpackNumpyTests(unittest.TestCase):
    def test_numpy_only_pickle_is_medium(self):
        f = scan({"a": mn_array(P_NUMPY)})
        self.assertEqual(rules(f), ["MPK002"])
        self.assertEqual(f[0]["severity"], "medium")
        self.assertIn("numpy.core.multiarray._reconstruct", f[0]["evidence"])

    def test_global_import_is_high(self):
        f = scan({"a": mn_array(P_GLOBAL)})
        self.assertEqual(rules(f), ["MPK001"])
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["cwe"], "CWE-502")
        self.assertIn("builtins.print", f[0]["evidence"])

    def test_stack_global_and_memo(self):
        for p in (P_STACK, P_MEMO):
            f = scan(mn_array(p))
            self.assertEqual(rules(f), ["MPK001"])
            self.assertIn("builtins.print", f[0]["evidence"])

    def test_stale_or_computed_names_are_high(self):
        for p in (P_STALE, P_COMPUTED):
            f = scan(mn_array(p))
            self.assertEqual(rules(f), ["MPK001"])
            self.assertIn("<computed>", f[0]["evidence"])

    def test_broken_pickle_still_lists_imports(self):
        f = scan(mn_array(P_BROKEN))
        self.assertEqual(rules(f), ["MPK001"])
        self.assertIn("builtins.print", f[0]["evidence"])
        self.assertIn("breaks off", f[0]["evidence"])

    def test_str_keys_and_raw_str_data(self):
        f = scan(mn_array(RawStr(P_GLOBAL), kind="O", str_keys=True))
        self.assertEqual(rules(f), ["MPK001"])
        self.assertIn("builtins.print", f[0]["evidence"])

    def test_plain_arrays_and_scalars_clean(self):
        doc = [{b"nd": True, b"type": "<f4", b"kind": b"",
                b"shape": [2], b"data": b"\x00" * 8},
               {b"nd": False, b"type": "<f8", b"data": b"\x00" * 8}]
        self.assertEqual(scan(doc), [])

    def test_nested_path(self):
        f = scan({"layers": [{"w": 1}, mn_array(P_GLOBAL)]})
        self.assertEqual(rules(f), ["MPK001"])
        self.assertIn("w.msgpack:/layers[1]:", f[0]["evidence"])

    def test_missing_data(self):
        f = scan({b"nd": True, b"kind": b"O"})
        self.assertEqual(rules(f), ["MPK004"])

    def test_found_before_truncation(self):
        data = pack([mn_array(P_GLOBAL), {"x": 1}])[:-1]
        f = mws.scan_bytes(data, "t")
        self.assertEqual(rules(f), ["MPK001", "MPK004"])
        self.assertIn("ends early", f[1]["evidence"])


class ParserTests(unittest.TestCase):
    MIXED = (b"\x87"
             b"\xa1a\xcd\x01\x00"
             b"\xa1b\xd0\xff"
             b"\xa1c\xca" + struct.pack(">f", 1.5) +
             b"\xa1d\xd9\x03abc"
             b"\xa1e\xc4\x02\x00\x01"
             b"\xa1f\xdc\x00\x02\xc0\xc2"
             b"\xa1g\xd4\x02\x00")

    def test_parse_values(self):
        value, end = mws._parse(memoryview(self.MIXED), 0, 0, "", None)
        self.assertEqual(end, len(self.MIXED))
        got = dict(value.pairs)
        self.assertEqual(got["a"], 256)
        self.assertEqual(got["b"], -1)
        self.assertEqual(got["c"], 1.5)
        self.assertEqual(got["d"], "abc")
        self.assertEqual(bytes(got["e"]), b"\x00\x01")
        self.assertEqual(got["f"], [None, False])
        self.assertEqual((got["g"].code, bytes(got["g"].data)), (2, b"\x00"))

    def test_mixed_doc_clean(self):
        self.assertEqual(mws.scan_bytes(self.MIXED), [])
        self.assertEqual(mws.scan_bytes(b"\x80"), [])
        self.assertEqual(mws.scan_bytes(b""), [])

    def test_fixext_unknown(self):
        f = mws.scan_bytes(b"\xd5\x07\x00\x00")
        self.assertEqual(rules(f), ["MPK004"])
        self.assertIn("extension type 7", f[0]["evidence"])

    def test_truncated(self):
        f = mws.scan_bytes(pack({"a": 1, "b": 2})[:-1])
        self.assertEqual(rules(f), ["MPK004"])
        self.assertIn("not well-formed", f[0]["evidence"])

    def test_reserved_byte(self):
        f = mws.scan_bytes(b"\xc1")
        self.assertEqual(rules(f), ["MPK004"])
        self.assertIn("0xc1", f[0]["evidence"])

    def test_depth_limit(self):
        self.assertEqual(mws.scan_bytes(b"\x91" * 10 + b"\x00"), [])
        f = mws.scan_bytes(b"\x91" * (mws.MAX_DEPTH + 5) + b"\x00")
        self.assertEqual(rules(f), ["MPK004"])
        self.assertIn("deeper than", f[0]["evidence"])

    def test_declared_count_beyond_data(self):
        for data in (b"\xdd\xff\xff\xff\xff\x00", b"\xdf\xff\xff\xff\xff\x00"):
            f = mws.scan_bytes(data)
            self.assertEqual(rules(f), ["MPK004"])
            self.assertIn("declared", f[0]["evidence"])

    def test_several_values(self):
        f = mws.scan_bytes(pack({"a": 1}) + pack(mn_array(P_GLOBAL)), "s")
        self.assertEqual(rules(f), ["MPK001", "MPK004"])
        self.assertIn("s:#2", f[0]["evidence"])
        self.assertIn("2 MessagePack values", f[1]["evidence"])

    def test_value_limit(self):
        f = mws.scan_bytes(b"\x00" * (mws.MAX_VALUES + 5))
        self.assertTrue(any("stopped after %d" % mws.MAX_VALUES
                            in x["evidence"] for x in f))

    def test_findings_limit(self):
        f = scan([Ext(9, b"") for _ in range(mws.MAX_FINDINGS + 5)])
        self.assertEqual(len(f), mws.MAX_FINDINGS + 1)
        self.assertIn("5 more findings", f[-1]["evidence"])


class ShapeTests(unittest.TestCase):
    def test_finding_shape_and_ascii(self):
        f = scan({"été": mn_array(P_GLOBAL)})
        self.assertEqual(len(f), 1)
        self.assertEqual(set(f[0]), {"rule", "severity", "cve", "cwe",
                                     "message", "evidence"})
        self.assertEqual(f[0]["cve"], "")
        self.assertEqual(f[0]["severity"], f[0]["severity"].lower())
        f[0]["evidence"].encode("ascii")
        f[0]["message"].encode("ascii")
        self.assertIn("\\xe9", f[0]["evidence"])

    def test_version(self):
        self.assertEqual(mws.__version__, "0.1.0")


class FileTests(unittest.TestCase):
    def test_scan_file_and_main(self):
        d = tempfile.mkdtemp()
        try:
            bad = os.path.join(d, "bad.msgpack")
            good = os.path.join(d, "good.msgpack")
            empty = os.path.join(d, "empty.msgpack")
            data = pack({"a": mn_array(P_GLOBAL)})
            with open(bad, "wb") as fh:
                fh.write(data)
            with open(good, "wb") as fh:
                fh.write(pack({"k": flax_array([1], "float32", b"\x00" * 4)}))
            open(empty, "wb").close()
            self.assertEqual(mws.scan_file(bad),
                             mws.scan_bytes(data, "bad.msgpack"))
            self.assertEqual(mws.scan_file(empty), [])
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(mws.main([bad]), 1)
                self.assertEqual(mws.main([good]), 0)
                self.assertEqual(mws.main([os.path.join(d, "none")]), 2)
                self.assertEqual(mws.main([]), 2)
            self.assertIn("HIGH MPK001", out.getvalue())
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
