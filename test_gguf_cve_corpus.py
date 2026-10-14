# SPDX-License-Identifier: Apache-2.0
# Part of keras-model-scan by MV2 of Munim, Inc. Made with AI.
"""Self-contained tests for gguf_cve_corpus.

Imports only the new module plus the standard library, so the publish test gate
never needs any live repo module in the files map. Re-parses each crafted file
to confirm it is a well-formed GGUF header carrying the documented extreme value.
"""
import json
import os
import re
import struct
import tempfile
import unittest

import gguf_cve_corpus as g


class _Reader:
    """Sequential little-endian reader matching the module's writer."""

    def __init__(self, blob: bytes):
        self.b = blob
        self.i = 0

    def take(self, n: int) -> bytes:
        # Clamp so a lying length (e.g. 2**64) does not explode the slice.
        avail = max(0, len(self.b) - self.i)
        n = min(n, avail)
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.b, self.i)[0]
        self.i += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from("<Q", self.b, self.i)[0]
        self.i += 8
        return v

    def gstr(self):
        n = self.u64()
        return n, self.take(n)


class CorpusBytesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.written = g.build_corpus(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _read(self, name: str) -> bytes:
        with open(self.written[name], "rb") as fh:
            return fh.read()

    def _header(self, name: str):
        """Return (reader positioned after the 24-byte header, tensor_count, kv_count)."""
        r = _Reader(self._read(name))
        self.assertEqual(r.take(4), g.GGUF_MAGIC)
        self.assertEqual(r.u32(), g.GGUF_VERSION)
        tensor_count = r.u64()
        kv_count = r.u64()
        return r, tensor_count, kv_count

    def test_all_files_written(self):
        expected = {e["file"] for e in g.CORPUS}
        self.assertEqual(set(self.written), expected)
        for path in self.written.values():
            self.assertTrue(os.path.exists(path))

    def test_kv_count_overflow(self):
        _, tc, kv = self._header("kv_count_overflow.gguf")
        self.assertEqual(tc, 0)
        self.assertEqual(kv, g.U64_MAX)

    def test_tensor_count_overflow(self):
        _, tc, kv = self._header("tensor_count_overflow.gguf")
        self.assertEqual(tc, g.U64_MAX)
        self.assertEqual(kv, 0)

    def test_array_len_overflow(self):
        r, tc, kv = self._header("array_len_overflow.gguf")
        self.assertEqual((tc, kv), (0, 1))
        klen, key = r.gstr()
        self.assertEqual((klen, key), (1, b"x"))
        self.assertEqual(r.u32(), g.GGUF_TYPE_ARRAY)
        self.assertEqual(r.u32(), g.GGUF_TYPE_UINT32)
        self.assertEqual(r.u64(), g.U64_MAX)  # array length

    def test_string_len_overrun(self):
        r, tc, kv = self._header("string_len_overrun.gguf")
        self.assertEqual((tc, kv), (0, 1))
        klen, key = r.gstr()
        self.assertEqual((klen, key), (1, b"x"))
        self.assertEqual(r.u32(), g.GGUF_TYPE_STRING)
        declared, _ = r.gstr()
        self.assertEqual(declared, g.U64_MAX)  # string length overruns the file

    def test_tensor_dims_overflow(self):
        r, tc, kv = self._header("tensor_dims_overflow.gguf")
        self.assertEqual((tc, kv), (1, 0))
        nlen, name = r.gstr()
        self.assertEqual((nlen, name), (1, b"t"))
        self.assertEqual(r.u32(), 2)          # n_dims
        self.assertEqual(r.u64(), g.U64_MAX)  # dim 0
        self.assertEqual(r.u64(), g.U64_MAX)  # dim 1

    def test_bad_alignment(self):
        r, tc, kv = self._header("bad_alignment.gguf")
        self.assertEqual((tc, kv), (0, 1))
        klen, key = r.gstr()
        self.assertEqual(key, b"general.alignment")
        self.assertEqual(klen, len(b"general.alignment"))
        self.assertEqual(r.u32(), g.GGUF_TYPE_UINT32)
        self.assertEqual(r.u32(), 0)          # alignment = 0

    def test_data_offset_oob(self):
        r, tc, kv = self._header("data_offset_oob.gguf")
        self.assertEqual((tc, kv), (1, 0))
        nlen, name = r.gstr()
        self.assertEqual((nlen, name), (1, b"t"))
        self.assertEqual(r.u32(), 1)          # n_dims
        self.assertEqual(r.u64(), 1)          # dim 0
        self.assertEqual(r.u32(), 0)          # ggml type
        self.assertEqual(r.u64(), g.U64_MAX)  # data offset past EOF


class AdvisoryMapTest(unittest.TestCase):
    CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
    RULE_RE = re.compile(r"^GG\d{3}$")

    def test_advisory_ids_well_formed(self):
        self.assertTrue(g.ADVISORIES)
        for cve, info in g.ADVISORIES.items():
            self.assertRegex(cve, self.CVE_RE)
            self.assertTrue(info.get("cwe"), f"{cve} missing cwe")
            for key in ("ref", "component", "impact", "fixed"):
                self.assertTrue(info.get(key), f"{cve} missing {key}")

    def test_corpus_entries_consistent(self):
        files = [e["file"] for e in g.CORPUS]
        self.assertEqual(len(files), len(set(files)), "duplicate corpus filenames")
        for e in g.CORPUS:
            self.assertTrue(e["file"].endswith(".gguf"))
            self.assertRegex(e["gguf_scan_rule"], self.RULE_RE)
            self.assertIn(e["coverage"], ("full", "partial"))
            for cve in e["cves"]:
                self.assertRegex(cve, self.CVE_RE)
                self.assertIn(cve, g.ADVISORIES, f"{cve} not in ADVISORIES")

    def test_every_advisory_is_covered(self):
        covered = {cve for e in g.CORPUS for cve in e["cves"]}
        self.assertEqual(covered, set(g.ADVISORIES), "advisory/corpus coverage mismatch")

    def test_dump_map_roundtrips(self):
        with tempfile.TemporaryDirectory() as d:
            path = g.dump_map(os.path.join(d, "gguf_cve_map.json"))
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertEqual(data["license"], "CC BY 4.0")
        self.assertEqual(set(data["advisories"]), set(g.ADVISORIES))
        self.assertEqual(len(data["corpus"]), len(g.CORPUS))
        for item in data["corpus"]:
            self.assertNotIn("builder", item)


if __name__ == "__main__":
    unittest.main(verbosity=2)
