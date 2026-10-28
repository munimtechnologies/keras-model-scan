#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for numpy_npy_scan.

Deliberately self-contained: imports only the standalone scanner module and
the Python standard library, so it runs in committed-file isolation without
the rest of the repo (and without numpy installed).
"""

import io
import os
import struct
import tempfile
import unittest
import zipfile

import numpy_npy_scan as nps

MAGIC = b"\x93NUMPY"

# A hand-crafted protocol-0 pickle: GLOBAL os.system + REDUCE. Built by hand so
# the opcode stream is identical on every platform/pickle protocol. Never run.
EXEC_PICKLE = b"cos\nsystem\n(S'id'\ntR."
# A minimal benign pickle (EMPTY_LIST + STOP): no code-execution opcodes.
BENIGN_PICKLE = b"]."


def _make_npy(descr, data_section=b"", major=1, minor=0):
    """Build a minimal valid .npy buffer with the given descr and data."""
    header = "{'descr': %r, 'fortran_order': False, 'shape': (0,), }" % (descr,)
    hdr = header.encode("latin-1")
    base = 10 if major == 1 else 12
    total = base + len(hdr) + 1  # +1 for the trailing newline
    pad = (64 - (total % 64)) % 64
    hdr = hdr + b" " * pad + b"\n"
    hlen = struct.pack("<H", len(hdr)) if major == 1 else struct.pack("<I", len(hdr))
    return MAGIC + bytes([major, minor]) + hlen + hdr + data_section


def _make_npz(members):
    """Build a .npz (ZIP) buffer from a dict of name -> .npy bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


class NumpyNpyScanTest(unittest.TestCase):
    def _rules(self, findings):
        return {f["rule"] for f in findings}

    def test_object_npy_flags_npy001(self):
        findings = nps.scan_bytes(_make_npy("|O", BENIGN_PICKLE), name="a.npy")
        rules = self._rules(findings)
        self.assertIn("NPY001", rules)
        self.assertNotIn("NPY002", rules)  # benign pickle: no exec opcodes
        f = next(x for x in findings if x["rule"] == "NPY001")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["cve"], "CVE-2019-6446")
        self.assertEqual(f["cwe"], "CWE-502")
        self.assertIn("descr", f["evidence"])

    def test_numeric_npy_is_clean(self):
        self.assertEqual(nps.scan_bytes(_make_npy("<f8", b"\x00" * 8)), [])

    def test_object_pickle_exec_flags_npy002(self):
        findings = nps.scan_bytes(_make_npy("|O", EXEC_PICKLE), name="evil.npy")
        rules = self._rules(findings)
        self.assertIn("NPY001", rules)
        self.assertIn("NPY002", rules)
        f = next(x for x in findings if x["rule"] == "NPY002")
        self.assertEqual(f["severity"], "high")
        self.assertIn("opcode", f["evidence"])
        self.assertIn("system", f["evidence"])

    def test_structured_object_dtype_detected(self):
        # Object dtype nested inside a structured dtype must still be caught.
        descr = [("a", "<f8"), ("b", "|O")]
        findings = nps.scan_bytes(_make_npy(descr, BENIGN_PICKLE))
        self.assertIn("NPY001", self._rules(findings))

    def test_structured_all_numeric_is_clean(self):
        descr = [("a", "<f8"), ("b", "<i4")]
        self.assertEqual(nps.scan_bytes(_make_npy(descr, b"\x00" * 12)), [])

    def test_npz_object_member_flagged_with_name(self):
        npz = _make_npz(
            {
                "weights.npy": _make_npy("<f8", b"\x00" * 8),
                "payload.npy": _make_npy("|O", EXEC_PICKLE),
            }
        )
        findings = nps.scan_bytes(npz, name="model.npz")
        rules = self._rules(findings)
        self.assertIn("NPY001", rules)
        self.assertIn("NPY002", rules)
        self.assertTrue(any("payload.npy" in f["evidence"] or "payload.npy" in f["message"] for f in findings))

    def test_npz_all_numeric_is_clean(self):
        npz = _make_npz({"a.npy": _make_npy("<f8", b"\x00" * 8)})
        self.assertEqual(nps.scan_bytes(npz), [])

    def test_version2_header_is_parsed(self):
        findings = nps.scan_bytes(_make_npy("|O", BENIGN_PICKLE, major=2, minor=0))
        self.assertIn("NPY001", self._rules(findings))

    def test_random_bytes_no_findings_no_crash(self):
        self.assertEqual(nps.scan_bytes(b"not a model file at all"), [])

    def test_empty_bytes(self):
        self.assertEqual(nps.scan_bytes(b""), [])

    def test_truncated_npy_does_not_crash(self):
        # Magic present but the buffer is too short to hold a header.
        self.assertEqual(nps.scan_bytes(MAGIC + b"\x01\x00\x10"), [])

    def test_bad_zip_does_not_crash(self):
        self.assertEqual(nps.scan_bytes(b"PK\x03\x04garbage"), [])

    def test_non_bytes_raises(self):
        with self.assertRaises(TypeError):
            nps.scan_bytes("a string")

    def test_scan_file_roundtrip(self):
        fd, path = tempfile.mkstemp(suffix=".npy")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(_make_npy("|O", EXEC_PICKLE))
            findings = nps.scan_file(path)
            self.assertIn("NPY001", self._rules(findings))
            self.assertIn("NPY002", self._rules(findings))
        finally:
            os.remove(path)

    def test_main_exit_codes(self):
        self.assertEqual(nps.main([]), 2)  # no args -> usage
        obj_fd, obj_path = tempfile.mkstemp(suffix=".npy")
        num_fd, num_path = tempfile.mkstemp(suffix=".npy")
        try:
            with os.fdopen(obj_fd, "wb") as fh:
                fh.write(_make_npy("|O", EXEC_PICKLE))
            with os.fdopen(num_fd, "wb") as fh:
                fh.write(_make_npy("<f8", b"\x00" * 8))
            self.assertEqual(nps.main([obj_path]), 1)  # high finding
            self.assertEqual(nps.main([num_path]), 0)  # clean
        finally:
            os.remove(obj_path)
            os.remove(num_path)


if __name__ == "__main__":
    unittest.main()
