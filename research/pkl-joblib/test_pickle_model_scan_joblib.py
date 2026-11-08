# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for pickle_model_scan 0.4.0: joblib.dump files are walked to the end.

joblib.dump writes each numpy array as a NumpyArrayWrapper object followed by
the array: a padding-length byte, padding and the raw bytes for a numeric
array (joblib >= 1.2; earlier versions write no padding byte), or a separate
nested pickle for an object-dtype array (joblib/numpy_pickle.py,
NumpyArrayWrapper.write_array and read_array). The streams below are built
by hand in that layout for ordinary arrays, so the tests need no numpy or
joblib. They are only ever disassembled by the scanner; nothing here is
unpickled.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import bz2
import collections
import datetime
import decimal
import gzip
import lzma
import pickle as P
import struct
import unittest
import zlib

import pickle_model_scan as pms

WRAP_MOD = "joblib.numpy_pickle"
WRAP = "NumpyArrayWrapper"


def su(s):
    b = s.encode("utf-8")
    return P.SHORT_BINUNICODE + bytes([len(b)]) + b


def sg(mod, name):
    return su(mod) + su(name) + P.STACK_GLOBAL


def gl(mod, name):
    return P.GLOBAL + mod.encode() + b"\n" + name.encode() + b"\n"


def i1(n):
    return P.BININT1 + bytes([n])


def i4(n):
    return P.BININT + struct.pack("<i", n)


def tup(items):
    if not items:
        return P.EMPTY_TUPLE
    if len(items) <= 3:
        return b"".join(items) + (P.TUPLE1, P.TUPLE2, P.TUPLE3)[len(items) - 1]
    return P.MARK + b"".join(items) + P.TUPLE


def dtype_ops(typestr, elsize=-1, flags=0, endian="<", fields=None,
              binput=None):
    """numpy's dtype.__reduce__: dtype(typestr, False, True), then BUILD with
    (3, endian, subarray, names, fields, elsize, alignment, flags)."""
    ops = sg("numpy", "dtype") + tup([su(typestr), P.NEWFALSE, P.NEWTRUE])
    ops += P.REDUCE
    if binput is not None:
        ops += P.BINPUT + bytes([binput])
    names = fd = P.NONE
    if fields:
        names = tup([su(n) for n, _sub, _off in fields])
        fd = (P.EMPTY_DICT + P.MARK
              + b"".join(su(n) + tup([sub, i1(off)]) for n, sub, off in fields)
              + P.SETITEMS)
    ops += (P.MARK + i1(3) + su(endian) + P.NONE + names + fd + i4(elsize)
            + i4(-1) + i4(flags) + P.TUPLE + P.BUILD)
    return ops


def wrapper_ops(shape, dt, align=16, head=None):
    """The wrapper object and its state dict, as joblib pickles it."""
    ops = head if head is not None else (sg(WRAP_MOD, WRAP) + P.EMPTY_TUPLE
                                         + P.NEWOBJ)
    ops += P.EMPTY_DICT + P.MARK
    ops += su("subclass") + sg("numpy", "ndarray")
    ops += su("shape") + tup([i4(n) for n in shape])
    ops += su("order") + su("C")
    ops += su("dtype") + dt
    ops += su("allow_mmap") + P.NEWTRUE
    if align == "absent":       # joblib 0.10 to 1.1 wrote no such key
        pass
    elif align is None:         # a file handle without tell()
        ops += su("numpy_array_alignment_bytes") + P.NONE
    else:
        ops += su("numpy_array_alignment_bytes") + i1(align)
    return ops + P.SETITEMS + P.BUILD


class JS(object):
    """A joblib-shaped stream: a dict whose values may be arrays."""

    def __init__(self, proto=4, head=None):
        self.b = bytearray(P.PROTO + bytes([proto]) if head is None else head)

    def add(self, ops):
        self.b += ops
        return self

    def array(self, shape, dt, payload, align=16, head=None):
        self.b += wrapper_ops(shape, dt, align, head)
        if align not in (None, "absent"):
            n = align - ((len(self.b) + 1) % align)  # as write_array does
            self.b += bytes([n]) + b"\xff" * n
        self.b += payload
        return self

    def data(self):
        return bytes(self.b)


AFTER = (su("after") + sg("collections", "OrderedDict") + P.EMPTY_TUPLE
         + P.REDUCE)


def f8(*vals):
    return struct.pack("<%dd" % len(vals), *vals)


def rules(findings):
    return {f.rule for f in findings}


def simple_stream(**kw):
    s = JS().add(P.EMPTY_DICT + P.MARK + su("w"))
    s.array((3,), dtype_ops("f8"), f8(1.0, 2.0, 3.0), **kw)
    return s.add(AFTER + P.SETITEMS + P.STOP).data()


class NumericArrays(unittest.TestCase):

    def assert_complete(self, data, arrays=1):
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["stop"], len(data) - 1, w)
        self.assertEqual(w["joblib_arrays"], arrays, w)
        self.assertFalse(w["symbolic_stack_lost"], w)
        self.assertEqual(w["unresolved"], 0, w)
        self.assertIn("collections OrderedDict", w["imports"])
        self.assertEqual(pms.scan_pickle_bytes(data, "t"), [])
        return w

    def test_version(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in pms.__version__.split(".")), (0, 4, 0))

    def test_aligned_array_then_the_rest(self):
        w = self.assert_complete(simple_stream())
        self.assertEqual(w["imports"][0], "%s %s" % (WRAP_MOD, WRAP))

    def test_no_alignment_key(self):
        self.assert_complete(simple_stream(align="absent"))

    def test_alignment_none(self):
        self.assert_complete(simple_stream(align=None))

    def test_two_arrays_sharing_a_memoized_dtype(self):
        s = JS().add(P.EMPTY_DICT + P.MARK + su("a"))
        s.array((2, 2), dtype_ops("f8", binput=200), f8(1, 2, 3, 4))
        s.add(su("b"))
        s.array((3,), P.BINGET + bytes([200]), f8(5, 6, 7))
        self.assert_complete(s.add(AFTER + P.SETITEMS + P.STOP).data(), 2)

    def test_itemsizes(self):
        cases = [
            ((5,), dtype_ops("b1"), b"\x01" * 5),
            ((2,), dtype_ops("i4", endian=">"), b"\x00" * 8),
            ((2,), dtype_ops("c16"), b"\x00" * 32),
            ((3,), dtype_ops("f2"), b"\x00" * 6),
            ((2,), dtype_ops("M8"), b"\x00" * 16),
            ((2,), dtype_ops("U5", elsize=20), b"\x00" * 40),
            ((2,), dtype_ops("S3", elsize=3, endian="|"), b"abcdef"),
            ((), dtype_ops("f8"), f8(3.0)),
            ((0, 3), dtype_ops("f8"), b""),
            ((2,), dtype_ops("V12", elsize=12, endian="|", fields=[
                ("a", dtype_ops("f8"), 0), ("b", dtype_ops("i4"), 8)]),
             b"\x00" * 24),
        ]
        for shape, dt, payload in cases:
            s = JS().add(P.EMPTY_DICT + P.MARK + su("w"))
            s.array(shape, dt, payload)
            with self.subTest(shape=shape, payload=len(payload)):
                self.assert_complete(s.add(AFTER + P.SETITEMS + P.STOP).data())

    def test_protocol_3_global_opcode(self):
        s = JS(proto=3).add(P.EMPTY_DICT + P.MARK + su("w"))
        s.array((3,), dtype_ops("f8"), f8(1, 2, 3),
                head=gl(WRAP_MOD, WRAP) + P.EMPTY_TUPLE + P.NEWOBJ)
        self.assert_complete(s.add(AFTER + P.SETITEMS + P.STOP).data())

    def test_reconstructor_form_of_protocols_0_and_1(self):
        head = (gl("copy_reg", "_reconstructor") + P.MARK + gl(WRAP_MOD, WRAP)
                + gl("__builtin__", "object") + P.NONE + P.TUPLE + P.REDUCE)
        s = JS(head=b"").add(P.EMPTY_DICT + P.MARK + su("w"))
        s.array((3,), dtype_ops("f8"), f8(1, 2, 3), head=head)
        self.assert_complete(s.add(AFTER + P.SETITEMS + P.STOP).data())

    def test_scikit_learn_bundled_joblib_module(self):
        s = JS().add(P.EMPTY_DICT + P.MARK + su("w"))
        s.array((3,), dtype_ops("f8"), f8(1, 2, 3), align="absent",
                head=sg("sklearn.externals.joblib.numpy_pickle", WRAP)
                + P.EMPTY_TUPLE + P.NEWOBJ)
        self.assert_complete(s.add(AFTER + P.SETITEMS + P.STOP).data())

    def test_import_after_the_array_is_classified(self):
        s = JS().add(P.EMPTY_DICT + P.MARK + su("w"))
        s.array((3,), dtype_ops("f8"), f8(1, 2, 3))
        s.add(su("m") + sg("mylib.models", "Tree") + P.EMPTY_TUPLE
              + P.NEWOBJ + P.SETITEMS + P.STOP)
        data = s.data()
        found = pms.scan_pickle_bytes(data, "t")
        self.assertEqual(rules(found), {"PKL003"})
        self.assertIn("mylib.models.Tree", found[0].detail)


class ObjectArrays(unittest.TestCase):

    def nested(self):
        # A complete pickle with its own memo: slot 0 is "numpy" here, while
        # slot 0 of the outer stream holds the outer dict.
        return (P.PROTO + b"\x05" + su("numpy") + P.MEMOIZE + su("ndarray")
                + P.MEMOIZE + P.STACK_GLOBAL + P.MEMOIZE + P.BINGET + b"\x00"
                + su("dtype") + P.MEMOIZE + P.STACK_GLOBAL + P.MEMOIZE
                + P.TUPLE2 + P.STOP)

    def stream(self, dt):
        s = JS().add(P.EMPTY_DICT + P.MEMOIZE + P.MARK + su("names"))
        s.add(wrapper_ops((2,), dt))  # no padding before a nested pickle
        s.add(self.nested())
        return s.add(AFTER + P.SETITEMS + P.STOP).data()

    def test_nested_pickle_has_its_own_memo(self):
        data = self.stream(dtype_ops("O8", endian="|", flags=63))
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["nested_pickles"], 1, w)
        self.assertEqual(w["stop"], len(data) - 1, w)
        self.assertEqual(w["unresolved"], 0, w)
        self.assertIn("numpy dtype", w["imports"])
        self.assertEqual(w["imports"][-1], "collections OrderedDict")
        self.assertEqual(pms.scan_pickle_bytes(data, "t"), [])

    def test_structured_dtype_with_an_object_field(self):
        dt = dtype_ops("V16", elsize=16, endian="|", flags=63, fields=[
            ("a", dtype_ops("O8", endian="|", flags=63), 0),
            ("b", dtype_ops("f8"), 8)])
        w = pms.pickle_walk(self.stream(dt), "t")
        self.assertEqual(w["nested_pickles"], 1, w)
        self.assertEqual(w["joblib_arrays"], 0, w)


class FailClosed(unittest.TestCase):

    def test_unknown_dtype_is_medium_not_silent(self):
        s = JS().add(P.EMPTY_DICT + P.MARK + su("w"))
        s.array((3,), dtype_ops("Zq"), f8(1, 2, 3))
        data = s.add(AFTER + P.SETITEMS + P.STOP).data()
        found = pms.scan_pickle_bytes(data, "t")
        hits = [f for f in found if f.rule == "PKL008"]
        self.assertTrue(hits, found)
        self.assertEqual(hits[0].severity, "MEDIUM")
        self.assertIsNone(pms.pickle_walk(data, "t")["stop"])

    def test_truncated_array_is_reported(self):
        s = JS().add(P.EMPTY_DICT + P.MARK + su("w"))
        s.array((1000,), dtype_ops("f8"), f8(1, 2))
        found = pms.scan_pickle_bytes(s.data(), "t")
        self.assertIn("PKL000", rules(found))


class Containers(unittest.TestCase):

    def probe(self):
        s = JS().add(P.EMPTY_DICT + P.MARK + su("w"))
        s.array((3,), dtype_ops("f8"), f8(1, 2, 3))
        return s.add(su("m") + sg("mylib.models", "Tree") + P.EMPTY_TUPLE
                     + P.NEWOBJ + P.SETITEMS + P.STOP).data()

    def test_every_joblib_compressor_in_the_stdlib(self):
        raw = self.probe()
        blobs = {
            "zlib": zlib.compress(raw, 3),
            "gzip": gzip.compress(raw, 3),
            "bz2": bz2.compress(raw, 3),
            "xz": lzma.compress(raw, format=lzma.FORMAT_XZ),
            "lzma": lzma.compress(raw, format=lzma.FORMAT_ALONE),
        }
        for name, blob in blobs.items():
            with self.subTest(compressor=name):
                found = pms.scan_blob(blob, "m.joblib", assume_pickle=True)
                self.assertEqual(rules(found), {"PKL003"}, found)


class PlainPicklesUnchanged(unittest.TestCase):
    """Python's own pickler output that happens to contain joblib's class
    name as data: the stack tracking must follow every opcode and change
    nothing."""

    def obj(self):
        rec = [1]
        rec.append(rec)
        loop = {"k": None}
        loop["k"] = loop
        return {
            "marker": "NumpyArrayWrapper", "module": "joblib.numpy_pickle",
            "b": b"NumpyArrayWrapper", "ba": bytearray(b"xy"),
            "f": 1.5, "c": complex(1, 2), "big": 2 ** 100, "neg": -7,
            "t": (1, (2, 3), (4, 5, 6, 7)), "s": {1, 2}, "fs": frozenset({3}),
            "od": collections.OrderedDict(a=1),
            "dt": datetime.datetime(2026, 11, 8, 12, 0),
            "dec": decimal.Decimal("1.25"), "rec": rec, "loop": loop,
            "rt": (rec,), "none": None, "yes": True,
        }

    def test_all_protocols(self):
        for proto in range(0, P.HIGHEST_PROTOCOL + 1):
            data = P.dumps(self.obj(), protocol=proto)
            with self.subTest(protocol=proto):
                w = pms.pickle_walk(data, "t")
                self.assertTrue(w["joblib_mode"])
                self.assertFalse(w["symbolic_stack_lost"], w)
                self.assertEqual(w["stop"], len(data) - 1, w)
                found = pms.scan_pickle_bytes(data, "t")
                self.assertNotIn("PKL008", rules(found))
                self.assertNotIn("PKL007", rules(found))
                self.assertNotIn("PKL000", rules(found))


if __name__ == "__main__":
    unittest.main()
