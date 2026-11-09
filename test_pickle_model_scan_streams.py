#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for pickle_model_scan 0.5.0: every pickle the loader reads is walked.

torch.save(..., _use_new_zipfile_serialization=False) writes five pickles
back to back (magic number, protocol version 1001, sys_info, the object, the
storage keys) and then raw tensor bytes; torch.load reads all five. Files
written with several pickle.dump calls hold several pickles too. These tests
build both layouts with Python's own pickler (torch is not needed) and check
that the walk reaches the last pickle the loader reads, and no further.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import collections
import contextlib
import datetime
import io
import os
import pickle as P
import tempfile
import unittest

import model_file_scan
import pickle_model_scan as pms

MAGIC = 0x1950A86A20F9469CFC6C
SYS_INFO = {"protocol_version": 1001, "little_endian": True,
            "type_sizes": {"short": 2, "int": 4, "long": 4}}
# A class outside the allowlist, as torch.save(model) of a user's own
# nn.Module writes it (e.g. __main__.Net): GLOBAL, EMPTY_TUPLE, NEWOBJ, STOP.
USER_CLASS_P2 = b"\x80\x02cmylib.models\nTree\n)\x81."


def legacy(obj=None, proto=2, streams=5, raw=b"\x00" * 16, object_stream=None):
    """The byte layout torch's _legacy_save writes, built with pickle."""
    if obj is None:
        obj = collections.OrderedDict([("weight", [1.0, 2.0])])
    parts = [P.dumps(MAGIC, protocol=proto), P.dumps(1001, protocol=proto),
             P.dumps(SYS_INFO, protocol=proto),
             object_stream if object_stream is not None
             else P.dumps(obj, protocol=proto),
             P.dumps(["0"], protocol=proto)]
    head = b"".join(parts[:streams])
    return head, head + raw


def rules(findings):
    return {f.rule for f in findings}


class LegacyTorch(unittest.TestCase):

    def test_version(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in pms.__version__.split(".")), (0, 5, 0))

    def test_magic_number_pickle_is_torchs_header(self):
        # The 15 bytes every protocol-2 legacy torch.save file starts with.
        self.assertEqual(P.dumps(MAGIC, protocol=2),
                         bytes.fromhex("80028a0a6cfc9c46f9206aa850192e"))

    def test_all_five_pickles_are_walked(self):
        head, data = legacy()
        w = pms.pickle_walk(data, "t")
        self.assertTrue(w["torch_legacy"], w)
        self.assertEqual(w["streams"], 5, w)
        self.assertEqual(w["stop"], len(head) - 1, w)
        self.assertIn("collections OrderedDict", w["imports"])
        self.assertEqual(w["unresolved"], 0, w)
        self.assertEqual(pms.scan_pickle_bytes(data, "t"), [])

    def test_protocol_4(self):
        head, data = legacy(proto=4)
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["streams"], 5, w)
        self.assertEqual(w["stop"], len(head) - 1, w)
        self.assertIn("collections OrderedDict", w["imports"])
        self.assertEqual(w["unresolved"], 0, w)

    def test_raw_storage_is_not_walked(self):
        # Tensor bytes after the fifth pickle are read raw by torch.load,
        # whatever they happen to look like.
        _head, data = legacy(raw=b"\x80\x02\xff\xff" + b"\x00" * 12)
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["streams"], 5, w)
        self.assertEqual(pms.scan_pickle_bytes(data, "t"), [])

    def test_import_in_the_object_pickle_is_classified(self):
        _head, data = legacy(object_stream=USER_CLASS_P2)
        found = pms.scan_pickle_bytes(data, "t")
        self.assertEqual(rules(found), {"PKL003"}, found)
        self.assertIn("mylib.models.Tree", found[0].detail)

    def test_truncated_legacy_file_is_low(self):
        _head, data = legacy(streams=3, raw=b"")
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["streams"], 3, w)
        found = pms.scan_pickle_bytes(data, "t")
        self.assertEqual(rules(found), {"PKL000"}, found)
        self.assertEqual(found[0].severity, "LOW")

    def test_scan_file_by_extension(self):
        _head, data = legacy(object_stream=USER_CLASS_P2)
        with tempfile.TemporaryDirectory() as d:
            for name in ("pytorch_model.bin", "model.pt", "model.pth"):
                path = os.path.join(d, name)
                with open(path, "wb") as fh:
                    fh.write(data)
                with self.subTest(name=name):
                    self.assertIn("PKL003", rules(pms.scan_file(path)))

    def test_model_file_scan_exit_codes(self):
        _h, honest = legacy()
        _h, user = legacy(object_stream=USER_CLASS_P2)
        with tempfile.TemporaryDirectory() as d:
            codes = {}
            for name, data in (("honest.bin", honest), ("user.bin", user)):
                path = os.path.join(d, name)
                with open(path, "wb") as fh:
                    fh.write(data)
                with contextlib.redirect_stdout(io.StringIO()):
                    codes[name] = model_file_scan.main(["--json", path])
        self.assertEqual(codes, {"honest.bin": 0, "user.bin": 1})


class SeveralDumps(unittest.TestCase):

    def test_three_dumps_are_walked(self):
        data = (P.dumps({"a": 1}, protocol=4)
                + P.dumps(collections.OrderedDict(b=2), protocol=4)
                + P.dumps(datetime.date(2026, 11, 9), protocol=2))
        w = pms.pickle_walk(data, "t")
        self.assertFalse(w["torch_legacy"], w)
        self.assertEqual(w["streams"], 3, w)
        self.assertEqual(w["stop"], len(data) - 1, w)
        self.assertIn("collections OrderedDict", w["imports"])
        self.assertIn("datetime date", w["imports"])
        self.assertEqual(pms.scan_pickle_bytes(data, "t"), [])

    def test_each_dump_has_its_own_memo(self):
        # Both pickles memoize "collections" in slot 0; the second must not
        # be resolved from the first one's memo, and need not be.
        od = collections.OrderedDict(x=1)
        data = P.dumps([od, od], protocol=4) + P.dumps(od, protocol=4)
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["streams"], 2, w)
        self.assertEqual(w["unresolved"], 0, w)
        self.assertEqual(w["imports"].count("collections OrderedDict"), 2, w)

    def test_import_in_a_later_dump_is_classified(self):
        data = P.dumps({"header": 1}, protocol=2) + USER_CLASS_P2
        found = pms.scan_pickle_bytes(data, "t")
        self.assertEqual(rules(found), {"PKL003"}, found)

    def test_trailing_bytes_that_are_not_a_pickle(self):
        data = P.dumps({"a": 1}, protocol=4) + b"trailing text\n"
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["streams"], 1, w)
        self.assertEqual(pms.scan_pickle_bytes(data, "t"), [])

    def test_single_pickle_unchanged(self):
        data = P.dumps(collections.OrderedDict(a=1), protocol=5)
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["streams"], 1, w)
        self.assertFalse(w["torch_legacy"], w)
        self.assertEqual(w["stop"], len(data) - 1, w)

    def test_stream_cap(self):
        one = P.dumps(1, protocol=2)
        data = one * (pms._MAX_STREAMS + 4)
        w = pms.pickle_walk(data, "t")
        self.assertEqual(w["streams"], pms._MAX_STREAMS, w)
        found = pms.scan_pickle_bytes(data, "t")
        self.assertEqual(rules(found), {"PKL000"}, found)


if __name__ == "__main__":
    unittest.main()
