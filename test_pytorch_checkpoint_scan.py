"""Tests for pytorch_checkpoint_scan.py. Standard library only; imports only the
module under test. Pickle fixtures are hand-crafted bytes and are never executed
(the scanner only disassembles opcodes with pickletools)."""

import io
import os
import tarfile
import tempfile
import unittest
import zipfile

import pytorch_checkpoint_scan as pcs

# Protocol-0 gadget: GLOBAL os system; MARK; STRING 'id'; TUPLE; REDUCE; STOP.
GADGET_P0 = b"cos\nsystem\n(S'id'\ntR."
# Protocol-4 STACK_GLOBAL gadget: PROTO 4; 'os'; 'system'; STACK_GLOBAL;
# EMPTY_TUPLE; REDUCE; STOP.
GADGET_P4 = b"\x80\x04\x8c\x02os\x8c\x06system\x93)R."
# Benign empty dict: EMPTY_DICT; STOP. No globals.
BENIGN = b"}."
# Benign but with a (non-dangerous) global: GLOBAL collections OrderedDict;
# EMPTY_TUPLE; REDUCE; STOP.
BENIGN_GLOBAL = b"ccollections\nOrderedDict\n)R."


def _zip_with(member, payload):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr(member, payload)
    return bio.getvalue()


def _tar_with(member, payload):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        info = tarfile.TarInfo(name=member)
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return bio.getvalue()


def _rules(findings):
    return {f["rule"] for f in findings}


class LegacyFormat(unittest.TestCase):
    def test_legacy_pickle_stream_gadget_is_ptc001(self):
        f = pcs.scan_bytes(GADGET_P0)
        self.assertEqual(_rules(f), {"PTC001"})
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["cve"], "CVE-2025-32434")
        self.assertEqual(f[0]["cwe"], "CWE-502")
        self.assertIn("os.system", f[0]["evidence"])

    def test_legacy_tar_gadget_is_ptc001(self):
        data = _tar_with("pickle", GADGET_P0)
        f = pcs.scan_bytes(data)
        self.assertEqual(_rules(f), {"PTC001"})
        self.assertEqual(f[0]["cve"], "CVE-2025-32434")
        self.assertIn("legacy tar", f[0]["evidence"])

    def test_legacy_advisory_is_ptc010(self):
        # Real pickled object graph, no dangerous import -> advisory only.
        f = pcs.scan_bytes(BENIGN_GLOBAL)
        self.assertEqual(_rules(f), {"PTC010"})
        self.assertEqual(f[0]["severity"], "medium")
        self.assertEqual(f[0]["cve"], "CVE-2025-32434")

    def test_legacy_no_global_is_clean(self):
        # A pickle with no global is not treated as a checkpoint object graph.
        self.assertEqual(pcs.scan_bytes(BENIGN), [])


class ModernZip(unittest.TestCase):
    def test_modern_zip_gadget_is_ptc002(self):
        data = _zip_with("archive/data.pkl", GADGET_P0)
        f = pcs.scan_bytes(data)
        self.assertEqual(_rules(f), {"PTC002"})
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["cve"], "")
        self.assertEqual(f[0]["cwe"], "CWE-502")
        self.assertIn("modern zip", f[0]["evidence"])

    def test_modern_zip_stack_global_gadget(self):
        data = _zip_with("archive/data.pkl", GADGET_P4)
        f = pcs.scan_bytes(data)
        self.assertEqual(_rules(f), {"PTC002"})
        self.assertIn("os.system", f[0]["evidence"])

    def test_modern_zip_benign_is_clean(self):
        self.assertEqual(pcs.scan_bytes(_zip_with("archive/data.pkl", BENIGN)), [])

    def test_modern_zip_benign_global_is_clean(self):
        # A non-dangerous global in a modern zip is NOT advisory (weights_only
        # enforcement lives on this path); only legacy files raise PTC010.
        data = _zip_with("archive/data.pkl", BENIGN_GLOBAL)
        self.assertEqual(pcs.scan_bytes(data), [])

    def test_non_data_pkl_member_is_scanned(self):
        data = _zip_with("archive/extra/weights.pkl", GADGET_P0)
        f = pcs.scan_bytes(data)
        self.assertEqual(_rules(f), {"PTC002"})


class NotACheckpoint(unittest.TestCase):
    def test_random_bytes_clean(self):
        self.assertEqual(pcs.scan_bytes(b"\x00\x01\x02\x03 not a pickle at all"), [])

    def test_empty_clean(self):
        self.assertEqual(pcs.scan_bytes(b""), [])


class FindingShape(unittest.TestCase):
    def test_keys_and_types(self):
        f = pcs.scan_bytes(GADGET_P0)[0]
        self.assertEqual(set(f.keys()),
                         {"rule", "severity", "cve", "cwe", "message", "evidence"})
        self.assertIn(f["severity"], ("high", "medium"))
        self.assertEqual(f["severity"], f["severity"].lower())

    def test_version(self):
        self.assertEqual(pcs.__version__, "0.1.0")


class FileAndMain(unittest.TestCase):
    def _write(self, data, suffix):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(os.remove, path)
        return path

    def test_scan_file(self):
        path = self._write(GADGET_P0, ".bin")
        f = pcs.scan_file(path)
        self.assertEqual(_rules(f), {"PTC001"})

    def test_main_high_returns_1(self):
        path = self._write(_zip_with("archive/data.pkl", GADGET_P0), ".pt")
        self.assertEqual(pcs.main([path]), 1)

    def test_main_clean_returns_0(self):
        path = self._write(_zip_with("archive/data.pkl", BENIGN), ".pt")
        self.assertEqual(pcs.main([path]), 0)

    def test_main_advisory_only_returns_0(self):
        # PTC010 is advisory (medium): it prints but does not fail the exit code.
        path = self._write(BENIGN_GLOBAL, ".bin")
        self.assertEqual(pcs.main([path]), 0)

    def test_main_no_args_returns_2(self):
        self.assertEqual(pcs.main([]), 2)

    def test_main_missing_file_returns_2(self):
        self.assertEqual(pcs.main([os.path.join(tempfile.gettempdir(), "no_such_ckpt_x.pt")]), 2)


if __name__ == "__main__":
    unittest.main()
