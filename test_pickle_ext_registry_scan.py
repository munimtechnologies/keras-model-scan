# SPDX-License-Identifier: Apache-2.0
# Part of keras-model-scan. Made with AI by MV2 of Munim, Inc.
"""Tests for pickle_ext_registry_scan (stdlib only, no code execution)."""

import io
import os
import json
import pickle
import tarfile
import zipfile
import tempfile
import unittest
import contextlib

import pickle_ext_registry_scan as p


# A minimal protocol-2 pickle that uses the EXT1 opcode (0x82) with code 1.
# PROTO 2  |  EXT1 code=1  |  STOP.  No dangerous name appears in the bytes.
EXT1_PICKLE = b"\x80\x02\x82\x01."

# STACK_GLOBAL importing copyreg.add_extension (SHORT_BINUNICODE x2 then 0x93).
STACK_GLOBAL_COPYREG = (
    b"\x80\x04"
    b"\x8c\x07copyreg"
    b"\x8c\radd_extension"
    b"\x93."
)

# Text-protocol GLOBAL importing copyreg._inverted_registry.
GLOBAL_COPYREG = b"ccopyreg\n_inverted_registry\n."


def _write(tmpdir, name, data):
    path = os.path.join(tmpdir, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _ids(findings):
    return sorted(f["id"] for f in findings)


class ScanBytesTest(unittest.TestCase):
    def test_ext1_opcode_flagged(self):
        findings = p.scan_pickle_bytes(EXT1_PICKLE, "x")
        self.assertIn("PXR002", _ids(findings))
        hit = [f for f in findings if f["id"] == "PXR002"][0]
        self.assertEqual(hit["opcode"], "EXT1")
        self.assertEqual(hit["severity"], "HIGH")

    def test_stack_global_copyreg_flagged(self):
        findings = p.scan_pickle_bytes(STACK_GLOBAL_COPYREG, "x")
        self.assertIn("PXR001", _ids(findings))
        hit = [f for f in findings if f["id"] == "PXR001"][0]
        self.assertEqual(hit["import"], "copyreg.add_extension")
        self.assertEqual(hit["severity"], "CRITICAL")

    def test_global_text_copyreg_flagged(self):
        findings = p.scan_pickle_bytes(GLOBAL_COPYREG, "x")
        hit = [f for f in findings if f["id"] == "PXR001"]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["import"], "copyreg._inverted_registry")

    def test_benign_pickle_clean(self):
        benign = pickle.dumps({"a": 1, "b": [1, 2, 3], "c": "hello"})
        self.assertEqual(p.scan_pickle_bytes(benign, "x"), [])

    def test_benign_copyreg_name_not_flagged(self):
        # copyreg.__newobj__ is legitimate (normal object reconstruction) and
        # must not fire -- only the registry-mutating names do.
        data = b"\x80\x04\x8c\x07copyreg\x8c\n__newobj__\x93."
        self.assertEqual(p.scan_pickle_bytes(data, "x"), [])


class ScanFileTest(unittest.TestCase):
    def test_raw_ext_pickle_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, "model.pkl", EXT1_PICKLE)
            findings = p.scan_file(path)
            self.assertIn("PXR002", _ids(findings))

    def test_non_pickle_file_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, "notes.txt", b"just some plain text, not a pickle")
            self.assertEqual(p.scan_file(path), [])

    def test_benign_pickle_file_clean(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, "ok.pkl", pickle.dumps([1, 2, 3]))
            self.assertEqual(p.scan_file(path), [])

    def test_zip_member_scanned(self):
        # A torch-style zip archive carrying a pickle member.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "model.pt")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("archive/data.pkl", EXT1_PICKLE)
            findings = p.scan_file(path)
            self.assertIn("PXR002", _ids(findings))
            self.assertTrue(any("data.pkl" in f["source"] for f in findings))

    def test_tar_member_scanned(self):
        # A .nemo-style tar archive carrying a pickle member.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "model.nemo")
            with tarfile.open(path, "w") as tf:
                info = tarfile.TarInfo("model_weights.pkl")
                info.size = len(STACK_GLOBAL_COPYREG)
                tf.addfile(info, io.BytesIO(STACK_GLOBAL_COPYREG))
            findings = p.scan_file(path)
            self.assertIn("PXR001", _ids(findings))


class MainTest(unittest.TestCase):
    def _run(self, args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = p.main(args)
        return rc, buf.getvalue()

    def test_main_reports_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, "evil.pkl", STACK_GLOBAL_COPYREG)
            rc, out = self._run([path])
            self.assertEqual(rc, 1)
            payload = json.loads(out)
            self.assertEqual(payload["tool"], "pickle_ext_registry_scan")
            ids = [f["id"] for r in payload["results"] for f in r["findings"]]
            self.assertIn("PXR001", ids)

    def test_main_clean_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, "ok.pkl", pickle.dumps({"x": 1}))
            rc, out = self._run([path])
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["results"][0]["findings"], [])

    def test_help_exits_zero(self):
        rc, out = self._run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("extension-registry", out)


if __name__ == "__main__":
    unittest.main()
