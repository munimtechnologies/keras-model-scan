# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for pickle_model_scan 0.3.0 and later: STACK_GLOBAL operands from the memo.

Python's pickler (protocols 4 and 5) memoizes the module and name strings of
each import and fetches a repeated module name from the memo. Since 0.3.0 the
scanner resolves such operands instead of reporting PKL007, and keeps PKL007
for operands it cannot resolve. Every stream here is only disassembled by the
scanner; none is ever unpickled.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import collections
import pickle
import pickletools
import struct
import unittest

import pickle_model_scan as pms

P4 = pickle.PROTO + b"\x04"
GETS = ("GET", "BINGET", "LONG_BINGET")


def su(s):
    b = s.encode("utf-8")
    return pickle.SHORT_BINUNICODE + bytes([len(b)]) + b


def binget(i):
    return pickle.BINGET + bytes([i])


def _get(f, key):
    if isinstance(f, dict):
        return f.get(key)
    return getattr(f, key, None)


def rules(findings):
    return {_get(f, "rule") for f in findings}


def of_rule(findings, rule):
    return [f for f in findings if _get(f, "rule") == rule]


def worst(findings):
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max([order.get(str(_get(f, "severity")).upper(), 0)
                for f in findings] or [0])


class Alpha:
    pass


class Beta:
    pass


def ops_between_globals(data):
    """Opcode names between the first and second STACK_GLOBAL."""
    names = [op.name for op, _a, _p in pickletools.genops(data)]
    idx = [i for i, n in enumerate(names) if n == "STACK_GLOBAL"]
    if len(idx) < 2:
        return []
    return names[idx[0] + 1:idx[1]]


class MemoResolution(unittest.TestCase):

    def test_version(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in pms.__version__.split(".")), (0, 3, 0))

    def test_python_pickler_repeated_module_resolves(self):
        for proto in (4, 5):
            data = pickle.dumps([Alpha(), Beta()], protocol=proto)
            # The case under test: the second import's module is a memo fetch.
            self.assertTrue(any(n in GETS for n in ops_between_globals(data)),
                            "protocol %d wrote no memo fetch" % proto)
            f = pms.scan_pickle_bytes(data, "t")
            self.assertNotIn("PKL007", rules(f), proto)
            # Both imports are resolved and classified (unknown module).
            details = " ".join(str(_get(x, "detail")) for x in
                               of_rule(f, "PKL003"))
            self.assertIn("Alpha", details)
            self.assertIn("Beta", details)

    def test_collections_pickle_is_clean(self):
        obj = {"c": collections.Counter(a=1),
               "m": collections.ChainMap({"x": 1})}
        for proto in (4, 5):
            data = pickle.dumps(obj, protocol=proto)
            self.assertTrue(any(n in GETS for n in ops_between_globals(data)),
                            "protocol %d wrote no memo fetch" % proto)
            f = pms.scan_pickle_bytes(data, "t")
            self.assertNotIn("PKL007", rules(f), proto)
            self.assertLessEqual(worst(f), 1, [(_get(x, "rule"),
                                                _get(x, "severity"))
                                               for x in f])

    def test_memoized_dangerous_import_is_critical(self):
        data = (P4 + su("os") + pickle.MEMOIZE + pickle.POP
                + su("system") + pickle.MEMOIZE + pickle.POP
                + binget(0) + binget(1) + pickle.STACK_GLOBAL
                + pickle.EMPTY_TUPLE + pickle.REDUCE + pickle.STOP)
        f = pms.scan_pickle_bytes(data, "t")
        hits = of_rule(f, "PKL001")
        self.assertTrue(hits)
        self.assertEqual(_get(hits[0], "severity"), "CRITICAL")
        self.assertNotIn("PKL007", rules(f))

    def test_memo_index_follows_the_unpickler(self):
        # MEMOIZE stores at the current memo size: 0 then 1. Fetching them
        # in swapped order gives module "OrderedDict", name "collections",
        # an unknown import (PKL003), which shows the indices are right.
        data = (P4 + su("collections") + pickle.MEMOIZE + su("OrderedDict")
                + pickle.MEMOIZE + pickle.POP + pickle.POP
                + binget(1) + binget(0) + pickle.STACK_GLOBAL + pickle.STOP)
        f = pms.scan_pickle_bytes(data, "t")
        self.assertIn("PKL003", rules(f))
        self.assertNotIn("PKL007", rules(f))

    def test_binput_and_long_binget(self):
        data = (P4 + su("collections") + pickle.BINPUT + b"\x03"
                + su("OrderedDict") + pickle.LONG_BINPUT
                + struct.pack("<I", 300) + pickle.POP + pickle.POP
                + binget(3) + pickle.LONG_BINGET + struct.pack("<I", 300)
                + pickle.STACK_GLOBAL + pickle.STOP)
        f = pms.scan_pickle_bytes(data, "t")
        self.assertNotIn("PKL007", rules(f))
        self.assertLessEqual(worst(f), 1)

    def test_frame_between_operands_is_ignored(self):
        frame = pickle.FRAME + struct.pack("<Q", 64)
        data = (P4 + frame + su("collections") + pickle.MEMOIZE + frame
                + su("OrderedDict") + pickle.MEMOIZE + pickle.STACK_GLOBAL
                + pickle.STOP)
        f = pms.scan_pickle_bytes(data, "t")
        self.assertEqual(f, [])


class StillUnresolved(unittest.TestCase):

    def assert_pkl007_high(self, data):
        hits = of_rule(pms.scan_pickle_bytes(data, "t"), "PKL007")
        self.assertTrue(hits)
        self.assertEqual(_get(hits[0], "severity"), "HIGH")

    def test_memo_slot_holding_a_tuple(self):
        self.assert_pkl007_high(
            P4 + pickle.EMPTY_TUPLE + pickle.MEMOIZE + binget(0) + binget(0)
            + pickle.STACK_GLOBAL + pickle.STOP)

    def test_memo_index_never_stored(self):
        self.assert_pkl007_high(
            P4 + binget(7) + binget(8) + pickle.STACK_GLOBAL + pickle.STOP)

    def test_memo_slot_overwritten_by_a_tuple(self):
        self.assert_pkl007_high(
            P4 + su("collections") + pickle.BINPUT + b"\x01" + pickle.POP
            + pickle.EMPTY_TUPLE + pickle.BINPUT + b"\x01" + pickle.POP
            + binget(1) + su("OrderedDict") + pickle.STACK_GLOBAL
            + pickle.STOP)

    def test_operands_must_be_the_last_two_pushes(self):
        # After the two POPs the stack top is "os", "system", not the last
        # two strings written. 0.2.1 read the last two strings; 0.3.0 sees
        # that the last two opcodes are not pushes and reports PKL007.
        self.assert_pkl007_high(
            P4 + su("os") + su("system") + su("collections")
            + su("OrderedDict") + pickle.POP + pickle.POP
            + pickle.STACK_GLOBAL + pickle.STOP)


if __name__ == "__main__":
    unittest.main()
