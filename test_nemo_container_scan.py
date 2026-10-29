"""Self-contained tests for nemo_container_scan.py (stdlib only).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

Run: python -m unittest -v test_nemo_container_scan
"""

import io
import os
import tarfile
import tempfile
import unittest
import zipfile

import nemo_container_scan as scan


# Known code-execution pickle gadgets (never unpickled here, only disassembled).
GADGET_P0 = b"cos\nsystem\n(S'id'\ntR."                       # GLOBAL os system
GADGET_P4 = b"\x80\x04\x8c\x02os\x8c\x06system\x93)R."         # STACK_GLOBAL os.system
# Benign pickles that still carry a (non-dangerous) global import.
BENIGN_P0 = b"ccollections\nOrderedDict\n)R."                  # GLOBAL collections OrderedDict
BENIGN_P4 = b"\x80\x04\x8c\x0bcollections\x8c\x0bOrderedDict\x93)R."

YAML = b"name: tiny-asr\nsample_rate: 16000\nlabels: [a, b, c]\n"


def make_tar(members, mode="w"):
    """members: list of (name, bytes). Build a tar in memory and return bytes."""
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode=mode)
    for name, content in members:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    tf.close()
    return buf.getvalue()


def make_link_tar(name, linkname, symlink=True):
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w")
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.SYMTYPE if symlink else tarfile.LNKTYPE
    info.linkname = linkname
    info.size = 0
    tf.addfile(info)
    tf.close()
    return buf.getvalue()


def make_torch_zip(entry_name, payload):
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w")
    zf.writestr(entry_name, payload)
    zf.close()
    return buf.getvalue()


def rules(findings):
    return sorted(f["rule"] for f in findings)


class TestPickleInContainer(unittest.TestCase):
    def test_dangerous_weights_p0_flags_nemo001(self):
        data = make_tar([("model_config.yaml", YAML),
                         ("model_weights.ckpt", GADGET_P0)])
        f = scan.scan_bytes(data, name="m.nemo")
        self.assertIn("NEMO001", rules(f))

    def test_dangerous_weights_p4_stack_global_flags_nemo001(self):
        data = make_tar([("model_weights.ckpt", GADGET_P4)])
        f = scan.scan_bytes(data)
        self.assertIn("NEMO001", rules(f))

    def test_benign_pickle_flags_nemo010_not_nemo001(self):
        data = make_tar([("model_config.yaml", YAML),
                         ("model_weights.ckpt", BENIGN_P0)])
        r = rules(scan.scan_bytes(data))
        self.assertIn("NEMO010", r)
        self.assertNotIn("NEMO001", r)

    def test_benign_p4_flags_nemo010(self):
        data = make_tar([("model_weights.ckpt", BENIGN_P4)])
        self.assertIn("NEMO010", rules(scan.scan_bytes(data)))

    def test_nested_torch_zip_datapkl_dangerous(self):
        zipped = make_torch_zip("archive/data.pkl", GADGET_P4)
        data = make_tar([("model_weights.ckpt", zipped)])
        f = scan.scan_bytes(data)
        self.assertIn("NEMO001", rules(f))
        self.assertTrue(any(">zip:" in x["evidence"] for x in f))

    def test_nested_torch_zip_datapkl_benign(self):
        zipped = make_torch_zip("archive/data.pkl", BENIGN_P4)
        data = make_tar([("model_weights.ckpt", zipped)])
        r = rules(scan.scan_bytes(data))
        self.assertIn("NEMO010", r)
        self.assertNotIn("NEMO001", r)

    def test_config_only_tar_is_clean(self):
        data = make_tar([("model_config.yaml", YAML),
                         ("vocab.txt", b"a\nb\nc\n")])
        self.assertEqual(scan.scan_bytes(data), [])

    def test_multiple_pickle_members(self):
        data = make_tar([("a.ckpt", GADGET_P0), ("b.ckpt", BENIGN_P0)])
        r = rules(scan.scan_bytes(data))
        self.assertIn("NEMO001", r)
        self.assertIn("NEMO010", r)


class TestCompressedTar(unittest.TestCase):
    def test_gzip_tar_gadget_flags_nemo001(self):
        data = make_tar([("model_weights.ckpt", GADGET_P0)], mode="w:gz")
        self.assertIn("NEMO001", rules(scan.scan_bytes(data)))

    def test_bz2_tar_gadget_flags_nemo001(self):
        data = make_tar([("model_weights.ckpt", GADGET_P4)], mode="w:bz2")
        self.assertIn("NEMO001", rules(scan.scan_bytes(data)))

    def test_xz_tar_gadget_flags_nemo001(self):
        data = make_tar([("model_weights.ckpt", GADGET_P0)], mode="w:xz")
        self.assertIn("NEMO001", rules(scan.scan_bytes(data)))


class TestPathTraversal(unittest.TestCase):
    def test_relative_traversal_flags_nemo020(self):
        data = make_tar([("../../../../tmp/evil", b"x"),
                         ("model_config.yaml", YAML)])
        f = scan.scan_bytes(data)
        self.assertIn("NEMO020", rules(f))
        hit = [x for x in f if x["rule"] == "NEMO020"][0]
        self.assertEqual(hit["cve"], "CVE-2024-0129")
        self.assertEqual(hit["severity"], "high")

    def test_absolute_path_flags_nemo020(self):
        data = make_tar([("/etc/cron.d/evil", b"x")])
        self.assertIn("NEMO020", rules(scan.scan_bytes(data)))

    def test_escaping_symlink_flags_nemo021(self):
        data = make_link_tar("link.ckpt", "../../../../etc/passwd", symlink=True)
        r = rules(scan.scan_bytes(data))
        self.assertIn("NEMO021", r)

    def test_escaping_hardlink_flags_nemo021(self):
        data = make_link_tar("h", "../../secret", symlink=False)
        self.assertIn("NEMO021", rules(scan.scan_bytes(data)))

    def test_innocuous_relative_name_no_nemo020(self):
        data = make_tar([("subdir/model_weights.ckpt", BENIGN_P0)])
        self.assertNotIn("NEMO020", rules(scan.scan_bytes(data)))


class TestEscapesHelper(unittest.TestCase):
    def test_escapes_cases(self):
        self.assertTrue(scan._escapes("/etc/passwd"))
        self.assertTrue(scan._escapes("../x"))
        self.assertTrue(scan._escapes("a/../../b"))
        self.assertTrue(scan._escapes("C:\\windows\\x"))
        self.assertFalse(scan._escapes("model_weights.ckpt"))
        self.assertFalse(scan._escapes("a/b/c.ckpt"))
        self.assertFalse(scan._escapes(""))


class TestOutOfScope(unittest.TestCase):
    def test_bare_pickle_is_out_of_scope(self):
        self.assertEqual(scan.scan_bytes(GADGET_P0, name="x.pkl"), [])

    def test_bare_zip_is_out_of_scope(self):
        zipped = make_torch_zip("data.pkl", GADGET_P4)
        self.assertEqual(scan.scan_bytes(zipped, name="x.pt"), [])

    def test_empty_and_garbage(self):
        self.assertEqual(scan.scan_bytes(b""), [])
        self.assertEqual(scan.scan_bytes(b"not a container at all"), [])


class TestFindingShape(unittest.TestCase):
    def test_keys_and_lowercase_severity(self):
        data = make_tar([("model_weights.ckpt", GADGET_P0)])
        for f in scan.scan_bytes(data):
            self.assertEqual(set(f), {"rule", "severity", "cve", "cwe",
                                      "message", "evidence"})
            self.assertEqual(f["severity"], f["severity"].lower())
            self.assertIn(f["severity"], {"high", "medium", "low"})
            self.assertTrue(f["cwe"])

    def test_version(self):
        self.assertEqual(scan.__version__, "0.1.0")


class TestScanFileAndMain(unittest.TestCase):
    def _write(self, data, suffix=".nemo"):
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        with open(path, "wb") as fh:
            fh.write(data)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_scan_file_roundtrip(self):
        path = self._write(make_tar([("model_weights.ckpt", GADGET_P0)]))
        self.assertIn("NEMO001", rules(scan.scan_file(path)))

    def test_main_high_returns_1(self):
        path = self._write(make_tar([("model_weights.ckpt", GADGET_P0)]))
        self.assertEqual(scan.main([path]), 1)

    def test_main_benign_returns_0(self):
        path = self._write(make_tar([("model_weights.ckpt", BENIGN_P0)]))
        self.assertEqual(scan.main([path]), 0)

    def test_main_usage_returns_2(self):
        self.assertEqual(scan.main([]), 2)

    def test_main_unreadable_returns_2(self):
        self.assertEqual(scan.main([os.path.join(tempfile.gettempdir(),
                                                 "nope-nemo-missing.nemo")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
