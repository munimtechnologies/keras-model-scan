# test_archive_symlink_scan.py - local, no-network regression test.
# Made with AI agents working in the name of MV2, Munim, Inc. Apache-2.0.
import os
import stat
import tarfile
import tempfile
import unittest
import zipfile

import archive_symlink_scan as m


def _zip_with_symlink(path: str, name: str, target: str) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zi = zipfile.ZipInfo(name)
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zi, target)


def _tar_with_symlink(path: str, name: str, target: str) -> None:
    with tarfile.open(path, "w") as tf:
        ti = tarfile.TarInfo(name)
        ti.type = tarfile.SYMTYPE
        ti.linkname = target
        tf.addfile(ti)


class TestArchiveSymlinkScan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def _p(self, n):
        return os.path.join(self.d, n)

    def test_zip_escaping_symlink_flagged_asl001(self):
        p = self._p("evil.zip")
        _zip_with_symlink(p, "weights.bin", "../../etc/passwd")
        self.assertIn("ASL001", {f["rule"] for f in m.scan(p)})

    def test_zip_absolute_symlink_flagged(self):
        p = self._p("abs.zip")
        _zip_with_symlink(p, "w.bin", "/etc/shadow")
        self.assertIn("ASL001", {f["rule"] for f in m.scan(p)})

    def test_zip_indir_symlink_is_medium(self):
        p = self._p("ok.zip")
        _zip_with_symlink(p, "a/w.bin", "b/real.bin")
        rules = {f["rule"] for f in m.scan(p)}
        self.assertIn("ASL004", rules)
        self.assertNotIn("ASL001", rules)

    def test_tar_escaping_symlink_flagged_asl002(self):
        p = self._p("evil.tar")
        _tar_with_symlink(p, "weights.bin", "../../root/.ssh/authorized_keys")
        self.assertIn("ASL002", {f["rule"] for f in m.scan(p)})

    def test_clean_zip_no_findings(self):
        p = self._p("clean.zip")
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("weights.bin", b"\x00\x01\x02")
        self.assertEqual(m.scan(p), [])

    def test_asl001_carries_real_cve(self):
        p = self._p("cve.zip")
        _zip_with_symlink(p, "w.bin", "../out")
        hi = [f for f in m.scan(p) if f["rule"] == "ASL001"]
        self.assertTrue(hi)
        self.assertEqual(hi[0]["cve"], "CVE-2026-27489")


if __name__ == "__main__":
    unittest.main(verbosity=2)
