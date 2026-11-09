# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""model-file-scan: directory walks keep pickle-bearing names that the
extension table misses (checkpoint.pth.tar from pytorch/examples; paddle.save
.pdparams / .pdopt; joblib.dump's compressed names such as model.joblib.gz),
and nothing else changes for ordinary archives and text files.
See REALFILE_CHECK_WALK_NAMES_2026-11.md.

Every file written here is an ordinary pickle of plain data (or plain text):
the tests check which files a folder walk picks up, never a detection.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import contextlib
import gzip
import io
import json
import os
import pickle
import shutil
import tempfile
import unittest

import model_file_scan as mfs

KEPT = ("checkpoint.pth.tar", "model_best.pth.tar", "weights.pt.tar",
        "epoch3.ckpt.tar", "model.pdparams", "model.pdopt",
        "MODEL.PDPARAMS", "Checkpoint.PTH.TAR",
        "model.joblib.z", "model.joblib.gz", "model.joblib.bz2",
        "model.joblib.xz", "model.joblib.lzma", "model.joblib.lz4",
        "model.pkl.gz", "clf.pickle.xz", "Model.PKL.GZ")
NOT_KEPT = ("data.tar", "logs.tar.gz", "readme.md", "model.pdiparams",
            "pth.tar.txt", "notes.txt.gz", "model.gz", "archive.tar.xz",
            "model.joblib.gz.txt", "model.npy.gz")


def honest_pickle():
    return pickle.dumps({"w": [1.0, 2.0], "b": [0.5], "name": "tiny"},
                        protocol=4)


class WalkNames(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, name, data=b"x"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def run_cli(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = mfs.main(list(args))
        return rc, buf.getvalue()

    def test_is_pickle_name(self):
        for name in KEPT:
            self.assertTrue(mfs._is_pickle_name(name), name)
        for name in NOT_KEPT:
            self.assertFalse(mfs._is_pickle_name(name), name)

    def test_walk_keeps_names(self):
        for name in KEPT:
            self.put(name)
            self.assertTrue(mfs._walk_keeps(self.tmp, name), name)

    def test_walk_skips_other_names(self):
        for name in NOT_KEPT:
            self.put(name, b"hello\n")
            self.assertFalse(mfs._walk_keeps(self.tmp, name), name)

    def test_route_is_pickle(self):
        for name in KEPT:
            self.assertEqual(mfs.route(name), "pickle", name)

    def test_expand_paths_finds_them(self):
        for name in KEPT[:6] + KEPT[8:11] + NOT_KEPT[:2]:
            self.put(name)
        files, missing = mfs.expand_paths([self.tmp])
        self.assertEqual(missing, [])
        self.assertEqual(sorted(os.path.basename(f) for f in files),
                         sorted(KEPT[:6] + KEPT[8:11]))

    def test_folder_scan_reads_honest_pdparams(self):
        self.put("model.pdparams", honest_pickle())
        rc, out = self.run_cli(self.tmp, "--json")
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual([os.path.basename(f["path"]) for f in doc["files"]],
                         ["model.pdparams"])

    def test_folder_scan_reads_honest_gzip_pickle(self):
        self.put("model.pkl.gz", gzip.compress(honest_pickle()))
        rc, out = self.run_cli(self.tmp, "--json")
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual([os.path.basename(f["path"]) for f in doc["files"]],
                         ["model.pkl.gz"])

    def test_plain_archives_still_skipped(self):
        self.put("data.tar", b"a.txt" + b"\0" * 507)
        self.put("notes.txt.gz", gzip.compress(b"hello\n"))
        rc, out = self.run_cli(self.tmp)
        self.assertEqual(rc, 0)
        self.assertIn("no model files found", out)

    def test_version(self):
        parts = tuple(int(p) for p in mfs.__version__.split("."))
        self.assertGreaterEqual(parts, (0, 13, 0))


if __name__ == "__main__":
    unittest.main()
