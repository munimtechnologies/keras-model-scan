#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for pickle_model_scan 0.6.0: in a torch.save zip that holds
<prefix>/data.pkl, the raw tensor storages <prefix>/data/<key> are not
sniffed as pickles (torch.load copies them as raw bytes). Everything else in
a zip is read as before.

The storage bytes used here are struct.pack("<q", 128): the int64 that
BatchNorm's num_batches_tracked holds after 128 training batches, which
torch.save stores little-endian as 80 00 00 00 00 00 00 00 (job
zip-storage-v1, research/zip-storage/).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import contextlib
import io
import os
import pickle
import struct
import tempfile
import unittest
import zipfile

import model_file_scan
import pickle_model_scan as pms

STORAGE_128 = struct.pack("<q", 128)
STATE = pickle.dumps({"w": 1}, protocol=2)


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def at(findings, member):
    return [f for f in findings
            if f.location.split("!", 1)[-1].split(" ")[0] == member]


class ZipStorage(unittest.TestCase):

    def test_version(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in pms.__version__.split(".")), (0, 6, 0))

    def test_storage_starting_0x80_is_raw_data(self):
        data = make_zip({"archive/data.pkl": STATE,
                         "archive/data/0": STORAGE_128})
        self.assertEqual(pms.scan_zip(data, "m.pt"), [])

    def test_root_prefix(self):
        data = make_zip({"data.pkl": STATE, "data/0": STORAGE_128})
        self.assertEqual(pms.scan_zip(data, "m.pt"), [])

    def test_data_pkl_is_still_walked(self):
        data = make_zip({"archive/data.pkl": STORAGE_128,
                         "archive/data/0": STORAGE_128})
        findings = pms.scan_zip(data, "m.pt")
        self.assertEqual([f.rule for f in at(findings, "archive/data.pkl")],
                         ["PKL000"])
        self.assertEqual(at(findings, "archive/data/0"), [])

    def test_pickle_extension_under_data_is_still_walked(self):
        data = make_zip({"archive/data.pkl": STATE,
                         "archive/data/extra.pkl": STORAGE_128})
        findings = pms.scan_zip(data, "m.pt")
        self.assertEqual(
            [f.rule for f in at(findings, "archive/data/extra.pkl")],
            ["PKL000"])

    def test_zip_without_data_pkl_is_sniffed_as_before(self):
        data = make_zip({"bundle/data/0": STORAGE_128})
        findings = pms.scan_zip(data, "b.zip")
        self.assertEqual([f.rule for f in at(findings, "bundle/data/0")],
                         ["PKL000"])

    def test_other_prefix_is_sniffed_as_before(self):
        data = make_zip({"a/data.pkl": STATE, "b/data/0": STORAGE_128})
        findings = pms.scan_zip(data, "b.zip")
        self.assertEqual([f.rule for f in at(findings, "b/data/0")],
                         ["PKL000"])

    def test_deeper_path_under_data_is_sniffed_as_before(self):
        data = make_zip({"archive/data.pkl": STATE,
                         "archive/data/sub/0": STORAGE_128})
        findings = pms.scan_zip(data, "m.pt")
        self.assertEqual([f.rule for f in at(findings, "archive/data/sub/0")],
                         ["PKL000"])

    def test_storage_members_helper(self):
        names = ["archive/data.pkl", "archive/byteorder", "archive/version",
                 "archive/.data/version", "archive/data/0", "archive/data/17",
                 "archive/data/sub/0", "other/data/0", "x/data.pkl/0"]
        self.assertEqual(pms._torch_storage_members(names),
                         {"archive/data/0", "archive/data/17"})
        self.assertEqual(pms._torch_storage_members(["data.pkl", "data/3"]),
                         {"data/3"})
        self.assertEqual(pms._torch_storage_members(["data/3"]), set())

    def test_scan_file_and_cli_on_a_pt_file(self):
        data = make_zip({"bn_128/data.pkl": STATE,
                         "bn_128/byteorder": b"little",
                         "bn_128/data/6": STORAGE_128})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bn_128.pt")
            with open(path, "wb") as fh:
                fh.write(data)
            self.assertEqual(pms.scan_file(path), [])
            with contextlib.redirect_stdout(io.StringIO()):
                code = model_file_scan.main(["--json", path])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
