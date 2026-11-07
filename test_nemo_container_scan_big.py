# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Tests for nemo_container_scan 0.2.0: big checkpoints are checked, not skipped.
#
# NeMo's SaveRestoreConnector writes model_weights.ckpt with torch.save into an
# uncompressed tar (arcname "."). Up to 0.1.0 a member larger than
# MAX_MEMBER_BYTES (256 MiB) was skipped with no finding, so the weights of
# most published .nemo models were never checked and the result was clean.
# 0.2.0 opens a nested torch-save zip from the tar member as a seekable file and
# reads only its directory and *.pkl entries, whatever the member's size. A
# bare pickle member that is too big, or a *.pkl entry that is too big, gets
# NEMO030 (medium); more members than MAX_MEMBERS gets NEMO031 (medium).
#
# Standard library only. MAX_MEMBER_BYTES / MAX_MEMBERS are lowered inside each
# test so the files stay tiny. The one "dangerous" pickle below is an inert
# marker: a GLOBAL opcode with no call, which the scanner must flag.
#
# This work was made with AI agents working in the name of MV2 of Munim, Inc.

import collections
import io
import os
import pickle
import shutil
import tarfile
import tempfile
import unittest
import zipfile

import nemo_container_scan as scan

INERT_DANGEROUS_PKL = b"\x80\x02cposix\nsystem\n."   # import only, never called


def _rules(findings):
    return {f["rule"] for f in findings}


def _torch_like_zip(pkl, tensor_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/data.pkl", pkl)
        zf.writestr("archive/byteorder", b"little")
        zf.writestr("archive/data/0", b"\x00" * tensor_bytes)
        zf.writestr("archive/version", b"3\n")
    return buf.getvalue()


class _Limits(unittest.TestCase):
    member_bytes = 1024
    members = None

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = (scan.MAX_MEMBER_BYTES, scan.MAX_MEMBERS)
        scan.MAX_MEMBER_BYTES = self.member_bytes
        if self.members is not None:
            scan.MAX_MEMBERS = self.members

    def tearDown(self):
        scan.MAX_MEMBER_BYTES, scan.MAX_MEMBERS = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def nemo(self, members, mode="w:"):
        """NeMo's layout: a folder tarred with arcname '.'."""
        folder = os.path.join(self.tmp, "folder")
        os.makedirs(folder, exist_ok=True)
        for name, data in members.items():
            with open(os.path.join(folder, name), "wb") as fh:
                fh.write(data)
        path = os.path.join(self.tmp, "model.nemo")
        with tarfile.open(path, mode) as tar:
            tar.add(folder, arcname=".")
        return path


class TestVersion(unittest.TestCase):

    def test_version_at_least_0_2_0(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in scan.__version__.split(".")), (0, 2, 0))


class TestBigCheckpoint(_Limits):

    def _benign(self):
        return pickle.dumps(collections.OrderedDict(), protocol=2)

    def test_big_zip_member_is_checked(self):
        path = self.nemo({"model_config.yaml": b"sample_rate: 16000\n",
                          "model_weights.ckpt": _torch_like_zip(
                              self._benign(), 4096)})
        self.assertEqual(_rules(scan.scan_file(path)), {"NEMO010"})
        with open(path, "rb") as fh:
            self.assertEqual(_rules(scan.scan_bytes(fh.read())), {"NEMO010"})

    def test_big_zip_member_dangerous(self):
        path = self.nemo({"model_weights.ckpt": _torch_like_zip(
            INERT_DANGEROUS_PKL, 4096)})
        self.assertIn("NEMO001", _rules(scan.scan_file(path)))

    def test_big_zip_member_gzip_tar(self):
        path = self.nemo({"model_weights.ckpt": _torch_like_zip(
            self._benign(), 4096)}, mode="w:gz")
        self.assertEqual(_rules(scan.scan_file(path)), {"NEMO010"})

    def test_small_zip_member_unchanged(self):
        path = self.nemo({"model_weights.ckpt": _torch_like_zip(
            self._benign(), 16)})
        scan.MAX_MEMBER_BYTES = 1 << 20
        self.assertEqual(_rules(scan.scan_file(path)), {"NEMO010"})

    def test_big_bare_pickle_reports_nemo030(self):
        pkl = pickle.dumps(b"\x00" * 4096, protocol=2)
        path = self.nemo({"model_weights.ckpt": pkl})
        findings = scan.scan_file(path)
        self.assertEqual(_rules(findings), {"NEMO030"})
        f = [x for x in findings if x["rule"] == "NEMO030"][0]
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(sorted(f), ["cve", "cwe", "evidence", "message",
                                     "rule", "severity"])

    def test_big_non_pickle_member_is_quiet(self):
        path = self.nemo({"tokenizer.model": b"\x0a\x0b" + b"x" * 4096})
        self.assertEqual(scan.scan_file(path), [])

    def test_big_pkl_entry_inside_zip_reports_nemo030(self):
        big_pkl = pickle.dumps(list(range(2000)), protocol=2)
        self.assertGreater(len(big_pkl), self.member_bytes)
        path = self.nemo({"model_weights.ckpt": _torch_like_zip(big_pkl, 16)})
        self.assertEqual(_rules(scan.scan_file(path)), {"NEMO030"})

    def test_main_medium_only_returns_0(self):
        path = self.nemo({"model_weights.ckpt": _torch_like_zip(
            self._benign(), 4096)})
        self.assertEqual(scan.main([path]), 0)


class TestMemberLimit(_Limits):
    member_bytes = 1 << 20
    members = 3

    def test_over_member_limit_reports_nemo031(self):
        # 1 directory entry ('.') + 4 files = 5 members > 3
        path = self.nemo({"a.txt": b"a", "b.txt": b"b", "c.txt": b"c",
                          "d.txt": b"d"})
        self.assertIn("NEMO031", _rules(scan.scan_file(path)))

    def test_at_member_limit_is_quiet(self):
        # '.' + 2 files = 3 members
        path = self.nemo({"a.txt": b"a", "b.txt": b"b"})
        self.assertEqual(scan.scan_file(path), [])


class TestScanFileStreams(unittest.TestCase):

    def test_non_tar_file_is_out_of_scope(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "x.nemo")
            with open(path, "wb") as fh:
                fh.write(b"not a tar" * 100)
            self.assertEqual(scan.scan_file(path), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError):
            scan.scan_file(os.path.join(tempfile.gettempdir(),
                                        "mv2-no-such-file.nemo"))


if __name__ == "__main__":
    unittest.main()
