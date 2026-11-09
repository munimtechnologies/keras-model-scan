#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for nemo_container_scan 0.3.0: a legacy-format torch.save checkpoint
inside a .nemo is walked the way torch.load reads it.

torch.save(..., _use_new_zipfile_serialization=False) writes five pickles
back to back (magic number, protocol version 1001, sys_info, the object, the
storage keys) and then raw tensor bytes; torch.load reads all five. Up to
0.2.0 only the first was walked, so such a model_weights.ckpt got no finding
at all. These tests build that byte layout with Python's own pickler from
benign values (torch is not needed) and put it in a NeMo-style tar.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import collections
import contextlib
import datetime
import io
import os
import pickle as P
import tarfile
import tempfile
import unittest
import zipfile

import model_file_scan
import nemo_container_scan as scan

MAGIC = 0x1950A86A20F9469CFC6C
SYS_INFO = {"protocol_version": 1001, "little_endian": True,
            "type_sizes": {"short": 2, "int": 4, "long": 4}}
# A class outside any allowlist, as torch.save(model) of a user's own module
# writes it: GLOBAL, EMPTY_TUPLE, NEWOBJ, STOP.
USER_CLASS_P2 = b"\x80\x02cmylib.models\nTree\n)\x81."
YAML = b"name: tiny-asr\nsample_rate: 16000\n"


def legacy(proto=2, streams=5, raw=b"\x00" * 16, object_stream=None):
    """The byte layout torch's _legacy_save writes, built with pickle."""
    obj = collections.OrderedDict([("weight", [1.0, 2.0])])
    parts = [P.dumps(MAGIC, protocol=proto), P.dumps(1001, protocol=proto),
             P.dumps(SYS_INFO, protocol=proto),
             object_stream if object_stream is not None
             else P.dumps(obj, protocol=proto),
             P.dumps(["0"], protocol=proto)]
    return b"".join(parts[:streams]) + raw


def nemo(ckpt, mode="w"):
    """A tar laid out like NeMo's save_to: config and weights under './'."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, content in (("./model_config.yaml", YAML),
                              ("./model_weights.ckpt", ckpt)):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def rules(findings):
    return sorted(f["rule"] for f in findings)


def walk(data, all_streams=True):
    info = {}
    dang, allg = scan._scan_pickle_ops(data, all_streams, info)
    return info, dang, ["%s.%s" % p for p in allg]


class LegacyCheckpoint(unittest.TestCase):

    def test_version(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in scan.__version__.split(".")), (0, 3, 0))

    def test_legacy_member_reports_nemo010(self):
        found = scan.scan_bytes(nemo(legacy()))
        self.assertEqual(rules(found), ["NEMO010"], found)
        ev = found[0]["evidence"]
        self.assertIn("legacy torch.save, 5 of 5 pickles", ev)
        self.assertIn("collections.OrderedDict", ev)

    def test_legacy_protocol_4(self):
        found = scan.scan_bytes(nemo(legacy(proto=4)))
        self.assertEqual(rules(found), ["NEMO010"], found)
        self.assertIn("collections.OrderedDict", found[0]["evidence"])

    def test_legacy_in_gzip_tar(self):
        found = scan.scan_bytes(nemo(legacy(), mode="w:gz"))
        self.assertEqual(rules(found), ["NEMO010"], found)

    def test_all_five_and_no_further(self):
        # Tensor bytes after the fifth pickle are read raw by torch.load,
        # whatever they happen to look like.
        info, dang, allg = walk(legacy(raw=b"\x80\x02\xff\xff" + b"\x00" * 12))
        self.assertEqual(info, {"streams": 5, "torch_legacy": True,
                                "truncated": False})
        self.assertEqual(dang, [])
        self.assertEqual(allg, ["collections.OrderedDict"])

    def test_one_stream_by_default(self):
        info, _dang, allg = walk(legacy(), all_streams=False)
        self.assertEqual(info["streams"], 1)
        self.assertTrue(info["torch_legacy"])
        self.assertEqual(allg, [])

    def test_user_class_is_named(self):
        found = scan.scan_bytes(nemo(legacy(object_stream=USER_CLASS_P2)))
        self.assertEqual(rules(found), ["NEMO010"], found)
        self.assertIn("mylib.models.Tree", found[0]["evidence"])

    def test_truncated_legacy_is_still_reported(self):
        found = scan.scan_bytes(nemo(legacy(streams=3, raw=b"")))
        self.assertEqual(rules(found), ["NEMO010"], found)
        self.assertIn("3 of 5 pickles; truncated", found[0]["evidence"])
        self.assertIn("imports=(none)", found[0]["evidence"])


class OtherMembers(unittest.TestCase):

    def test_several_dumps_are_walked(self):
        data = (P.dumps({"a": 1}, protocol=4)
                + P.dumps(collections.OrderedDict(b=2), protocol=4)
                + P.dumps(datetime.date(2026, 11, 9), protocol=2))
        found = scan.scan_bytes(nemo(data))
        self.assertEqual(rules(found), ["NEMO010"], found)
        ev = found[0]["evidence"]
        self.assertIn("(3 pickles)", ev)
        self.assertIn("datetime.date", ev)

    def test_trailing_text_is_not_walked(self):
        info, _dang, _allg = walk(P.dumps({"a": 1}, protocol=4) + b"notes\n")
        self.assertEqual(info["streams"], 1)
        self.assertFalse(info["torch_legacy"])

    def test_single_pickle_evidence_unchanged(self):
        data = P.dumps(collections.OrderedDict(a=1), protocol=2)
        found = scan.scan_bytes(nemo(data))
        self.assertEqual(rules(found), ["NEMO010"], found)
        self.assertEqual(found[0]["evidence"],
                         "tar:./model_weights.ckpt; "
                         "imports=collections.OrderedDict")

    def test_zip_data_pkl_is_read_once(self):
        # torch.load reads one pickle from a zip checkpoint's data.pkl.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl",
                        P.dumps(collections.OrderedDict(a=1), protocol=2)
                        + P.dumps(datetime.date(2026, 11, 9), protocol=2))
        found = scan.scan_bytes(nemo(buf.getvalue()))
        self.assertEqual(rules(found), ["NEMO010"], found)
        self.assertNotIn("datetime", found[0]["evidence"])

    def test_memo_module_name_is_resolved(self):
        # Protocol 4 memoizes the module name "collections" with Counter and
        # fetches it back from the memo for ChainMap (same module object).
        data = P.dumps([collections.Counter(), collections.ChainMap()],
                       protocol=4)
        self.assertEqual(data.count(b"collections"), 1)
        _info, _dang, allg = walk(data)
        self.assertIn("collections.Counter", allg)
        self.assertIn("collections.ChainMap", allg)

    def test_stream_cap(self):
        data = P.dumps(1, protocol=2) * (scan._MAX_STREAMS + 4)
        info, _dang, _allg = walk(data)
        self.assertEqual(info["streams"], scan._MAX_STREAMS)
        self.assertTrue(info["truncated"])


class FilesAndCli(unittest.TestCase):

    def _write(self, data, d):
        path = os.path.join(d, "model.nemo")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_scan_file_and_main(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(nemo(legacy()), d)
            self.assertEqual(rules(scan.scan_file(path)), ["NEMO010"])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scan.main([path]), 0)

    def test_model_file_scan_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(nemo(legacy()), d)
            with contextlib.redirect_stdout(io.StringIO()):
                medium = model_file_scan.main(["--json", path])
                high = model_file_scan.main(["--json", "--fail-on", "high",
                                             path])
        self.assertEqual((medium, high), (1, 0))


if __name__ == "__main__":
    unittest.main()
