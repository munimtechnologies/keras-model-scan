"""Tests for joblib_pickle_scan.py. Standard library only; imports the module
under test plus stdlib compressors used only to BUILD fixtures. The pickle
gadgets are hand-crafted bytes and are never executed (the scanner only
disassembles opcodes with pickletools)."""

import bz2
import gzip
import lzma
import os
import tempfile
import unittest
import zlib

import joblib_pickle_scan as jps

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


def _rules(findings):
    return {f["rule"] for f in findings}


class CompressedGadget(unittest.TestCase):
    def test_zlib_wrapped_gadget_is_jlb001(self):
        f = jps.scan_bytes(zlib.compress(GADGET_P0))
        self.assertEqual(_rules(f), {"JLB001"})
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["cve"], "")
        self.assertEqual(f[0]["cwe"], "CWE-502")
        self.assertIn("os.system", f[0]["evidence"])
        self.assertIn("codec=zlib", f[0]["evidence"])

    def test_gzip_wrapped_gadget_is_jlb001(self):
        f = jps.scan_bytes(gzip.compress(GADGET_P0))
        self.assertEqual(_rules(f), {"JLB001"})
        self.assertIn("codec=gzip", f[0]["evidence"])

    def test_bz2_wrapped_gadget_is_jlb001(self):
        f = jps.scan_bytes(bz2.compress(GADGET_P0))
        self.assertEqual(_rules(f), {"JLB001"})
        self.assertIn("codec=bz2", f[0]["evidence"])

    def test_xz_wrapped_gadget_is_jlb001(self):
        f = jps.scan_bytes(lzma.compress(GADGET_P0))  # default FORMAT_XZ
        self.assertEqual(_rules(f), {"JLB001"})
        self.assertIn("codec=xz", f[0]["evidence"])

    def test_stack_global_gadget_under_gzip(self):
        f = jps.scan_bytes(gzip.compress(GADGET_P4))
        self.assertEqual(_rules(f), {"JLB001"})
        self.assertIn("os.system", f[0]["evidence"])

    def test_nested_zlib_layers(self):
        f = jps.scan_bytes(zlib.compress(zlib.compress(GADGET_P0)))
        self.assertEqual(_rules(f), {"JLB001"})
        self.assertIn("codec=zlib+zlib", f[0]["evidence"])


class CompressedBenign(unittest.TestCase):
    def test_zlib_wrapped_benign_global_is_jlb010(self):
        f = jps.scan_bytes(zlib.compress(BENIGN_GLOBAL))
        self.assertEqual(_rules(f), {"JLB010"})
        self.assertEqual(f[0]["severity"], "medium")
        self.assertEqual(f[0]["cwe"], "CWE-502")

    def test_gzip_wrapped_empty_dict_is_clean(self):
        # A pickle with no global is not treated as an object graph worth flagging.
        self.assertEqual(jps.scan_bytes(gzip.compress(BENIGN)), [])

    def test_gzip_wrapped_non_pickle_is_clean(self):
        # A compressed NON-pickle (bytes that are not a valid pickle stream) must
        # not be flagged: 0x00 is not a pickle opcode, so genops yields nothing.
        self.assertEqual(jps.scan_bytes(gzip.compress(b"\x00" * 64)), [])


class Lz4Frame(unittest.TestCase):
    def test_lz4_frame_magic_is_jlb012(self):
        # lz4 is not stdlib-decompressible; only the frame magic is asserted.
        f = jps.scan_bytes(b"\x04\x22\x4d\x18" + b"\x00" * 16, name="model.joblib")
        self.assertEqual(_rules(f), {"JLB012"})
        self.assertEqual(f[0]["severity"], "medium")
        self.assertIn("lz4", f[0]["evidence"])


class OutOfScopeOrClean(unittest.TestCase):
    def test_bare_pickle_gadget_is_clean(self):
        # An UNCOMPRESSED pickle is out of scope for this module (pickle_model_scan
        # and pytorch_checkpoint_scan handle it); no compression wrapper -> clean.
        self.assertEqual(jps.scan_bytes(GADGET_P0), [])

    def test_bare_pickle_empty_list_not_misread_as_lzma(self):
        # 0x5d (']', EMPTY_LIST) must not be mistaken for the lzma 'alone' format.
        self.assertEqual(jps.scan_bytes(b"]."), [])

    def test_random_bytes_clean(self):
        self.assertEqual(jps.scan_bytes(b"\x00\x01\x02\x03 not compressed"), [])

    def test_empty_clean(self):
        self.assertEqual(jps.scan_bytes(b""), [])


class FindingShape(unittest.TestCase):
    def test_keys_and_types(self):
        f = jps.scan_bytes(zlib.compress(GADGET_P0))[0]
        self.assertEqual(set(f.keys()),
                         {"rule", "severity", "cve", "cwe", "message", "evidence"})
        self.assertIn(f["severity"], ("high", "medium"))
        self.assertEqual(f["severity"], f["severity"].lower())

    def test_version(self):
        self.assertEqual(jps.__version__, "0.1.0")


class FileAndMain(unittest.TestCase):
    def _write(self, data, suffix):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(os.remove, path)
        return path

    def test_scan_file(self):
        path = self._write(bz2.compress(GADGET_P0), ".joblib")
        self.assertEqual(_rules(jps.scan_file(path)), {"JLB001"})

    def test_main_high_returns_1(self):
        path = self._write(gzip.compress(GADGET_P0), ".pkl.gz")
        self.assertEqual(jps.main([path]), 1)

    def test_main_clean_returns_0(self):
        path = self._write(gzip.compress(BENIGN), ".pkl.gz")
        self.assertEqual(jps.main([path]), 0)

    def test_main_advisory_only_returns_0(self):
        # JLB010 is advisory (medium): it prints but does not fail the exit code.
        path = self._write(zlib.compress(BENIGN_GLOBAL), ".joblib")
        self.assertEqual(jps.main([path]), 0)

    def test_main_no_args_returns_2(self):
        self.assertEqual(jps.main([]), 2)

    def test_main_missing_file_returns_2(self):
        self.assertEqual(
            jps.main([os.path.join(tempfile.gettempdir(), "no_such_joblib_x.joblib")]), 2)


if __name__ == "__main__":
    unittest.main()
