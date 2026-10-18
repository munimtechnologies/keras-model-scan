# Copyright 2026 MV2, Munim, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for nested_container_scan.

All fixtures are built in memory with the standard library. The "dangerous"
payloads are byte strings that merely carry the magic prefix of a pickle /
HDF5 / NumPy file -- they are never unpickled, imported or executed.
"""
import gzip
import bz2
import io
import lzma
import os
import tarfile
import tempfile
import unittest
import zipfile

import nested_container_scan as ncs

# Magic-only payloads (never deserialized).
PICKLE = b"\x80\x04N."                    # proto-4 pickle header + None + STOP
HDF5 = b"\x89HDF\r\n\x1a\n" + b"\x00" * 24
NPY = b"\x93NUMPY\x01\x00" + b"\x00" * 24
TEXT = b"this is not a model, just some plain text bytes"
ZSTD = ncs._ZSTD_MAGIC + b"\x00" * 16
LZ4 = ncs._LZ4_MAGIC + b"\x00" * 16


def _rules(findings):
    return {f.rule for f in findings}


def _by_rule(findings, rule):
    matches = [f for f in findings if f.rule == rule]
    return matches[0] if matches else None


def _zip_with(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_with(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class TestSingleCompressorPayload(unittest.TestCase):
    def test_gzip_wrapped_pickle_is_high(self):
        findings = ncs.scan_bytes(gzip.compress(PICKLE), "model.pkl.gz")
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.value, "pickle")
        self.assertIn("arXiv:2508.19774", f.message)

    def test_bz2_wrapped_pickle_is_high(self):
        findings = ncs.scan_bytes(bz2.compress(PICKLE), "model.pkl.bz2")
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.value, "pickle")

    def test_xz_wrapped_pickle_is_high(self):
        findings = ncs.scan_bytes(lzma.compress(PICKLE), "model.pkl.xz")
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "HIGH")

    def test_tar_wrapped_pickle_is_high(self):
        data = _tar_with({"weights.pkl": PICKLE})
        findings = ncs.scan_bytes(data, "bundle.tar")
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.value, "pickle")

    def test_gzip_wrapped_numpy_is_high(self):
        findings = ncs.scan_bytes(gzip.compress(NPY), "arr.npy.gz")
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.value, "numpy-array")

    def test_name_only_payload_is_medium(self):
        findings = ncs.scan_bytes(gzip.compress(TEXT), "mystery.ckpt.gz")
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "MEDIUM")
        self.assertEqual(f.value, "ckpt")


class TestStandardSingleZipNotFlagged(unittest.TestCase):
    def test_single_zip_pickle_is_not_evasion(self):
        # The ordinary PyTorch .pt case (pickle in one zip) is handled by the
        # format scanners and must NOT be flagged as nested-container evasion.
        data = _zip_with({"archive/data.pkl": PICKLE})
        findings = ncs.scan_bytes(data, "model.pt")
        self.assertNotIn("NC001", _rules(findings))
        self.assertIn("NC000", _rules(findings))

    def test_bare_pickle_not_flagged(self):
        findings = ncs.scan_bytes(PICKLE, "model.pkl")
        self.assertNotIn("NC001", _rules(findings))
        self.assertIn("NC000", _rules(findings))


class TestNestedContainers(unittest.TestCase):
    def test_zip_in_zip_pickle(self):
        inner = _zip_with({"data.pkl": PICKLE})
        outer = _zip_with({"inner.zip": inner})
        findings = ncs.scan_bytes(outer, "outer.zip")
        self.assertIn("NC002", _rules(findings))
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.value, "pickle")

    def test_gzip_tar_pickle(self):
        tar = _tar_with({"w.pkl": PICKLE})
        data = gzip.compress(tar)
        findings = ncs.scan_bytes(data, "bundle.tar.gz")
        self.assertIn("NC002", _rules(findings))  # tar nested inside gzip
        self.assertIn("NC001", _rules(findings))

    def test_keras_npz_npy_chain(self):
        # .keras (zip) -> npz (zip) -> npy (numpy): the chained-archive bypass.
        npz = _zip_with({"arr_0.npy": NPY})
        keras = _zip_with({"model.npz": npz})
        findings = ncs.scan_bytes(keras, "model.keras")
        self.assertIn("NC002", _rules(findings))
        f = _by_rule(findings, "NC001")
        self.assertIsNotNone(f)
        self.assertEqual(f.value, "numpy-array")


class TestUnsupportedCodec(unittest.TestCase):
    def test_nested_zstd_member_flagged(self):
        data = _zip_with({"weights.zst": ZSTD})
        findings = ncs.scan_bytes(data, "bundle.zip")
        f = _by_rule(findings, "NC010")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "MEDIUM")
        self.assertEqual(f.value, "zstd")

    def test_nested_lz4_member_flagged(self):
        data = _zip_with({"weights.lz4": LZ4})
        findings = ncs.scan_bytes(data, "bundle.zip")
        f = _by_rule(findings, "NC010")
        self.assertIsNotNone(f)
        self.assertEqual(f.value, "lz4")

    def test_top_level_zstd_not_flagged(self):
        findings = ncs.scan_bytes(ZSTD, "model.zst")
        self.assertNotIn("NC010", _rules(findings))
        self.assertIn("NC000", _rules(findings))


class TestUnreadableMember(unittest.TestCase):
    def test_broken_nested_zip_flags_nc011(self):
        broken = b"PK\x03\x04" + b"\x00" * 24  # looks like a zip, cannot parse
        outer = _zip_with({"broken.zip": broken})
        findings = ncs.scan_bytes(outer, "outer.zip")
        f = _by_rule(findings, "NC011")
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "MEDIUM")
        self.assertIn("CVE-2025", f.message)


class TestLimits(unittest.TestCase):
    def test_depth_limit_emits_nc003(self):
        data = PICKLE
        for _ in range(ncs.MAX_DEPTH + 2):
            data = gzip.compress(data)
        findings = ncs.scan_bytes(data, "deep.gz")
        f = _by_rule(findings, "NC003")
        self.assertIsNotNone(f)
        self.assertEqual(f.value, "depth")


class TestCleanAndSerialization(unittest.TestCase):
    def test_clean_zip_text(self):
        data = _zip_with({"readme.txt": TEXT, "notes.md": TEXT})
        findings = ncs.scan_bytes(data, "docs.zip")
        self.assertEqual(_rules(findings), {"NC000"})

    def test_finding_as_dict_keys(self):
        findings = ncs.scan_bytes(gzip.compress(PICKLE), "model.pkl.gz")
        d = _by_rule(findings, "NC001").as_dict()
        self.assertEqual(
            set(d),
            {"rule", "severity", "key", "value", "file", "location", "message"},
        )


class TestCliAndPaths(unittest.TestCase):
    def test_scan_paths_and_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "model.pkl.gz")
            with open(bad, "wb") as fh:
                fh.write(gzip.compress(PICKLE))
            clean = os.path.join(d, "readme.txt")
            with open(clean, "wb") as fh:
                fh.write(TEXT)

            result = ncs.scan_paths([d])
            self.assertIn("NC001", _rules(result.findings))
            self.assertIn(bad, result.scanned_files)

            self.assertEqual(ncs.main([bad, "--fail-on", "HIGH"]), 1)
            self.assertEqual(ncs.main([clean, "--fail-on", "HIGH"]), 0)
            self.assertEqual(ncs.main([bad, "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
