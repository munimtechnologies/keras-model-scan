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
"""Tests for gguf_data_region_scan."""
import os
import struct
import tempfile
import unittest

import gguf_data_region_scan as g


def _u32(v):
    return struct.pack("<I", v)


def _u64(v):
    return struct.pack("<Q", v)


def _gstr(b):
    return _u64(len(b)) + b


def build_gguf(tensors, kvs=None, version=3, pad_to=None):
    """Assemble a GGUF image.

    tensors: list of (name:bytes, dims:list[int], ttype:int, offset:int)
    kvs:     list of (key:bytes, vtype:int, raw_value:bytes)  (value pre-encoded)
    pad_to:  if set, zero-pad the whole image up to this many bytes.
    """
    kvs = kvs or []
    out = bytearray()
    out += g.GGUF_MAGIC
    out += _u32(version)
    out += _u64(len(tensors))
    out += _u64(len(kvs))
    for key, vtype, raw in kvs:
        out += _gstr(key)
        out += _u32(vtype)
        out += raw
    for name, dims, ttype, offset in tensors:
        out += _gstr(name)
        out += _u32(len(dims))
        for d in dims:
            out += _u64(d)
        out += _u32(ttype)
        out += _u64(offset)
    if pad_to is not None and pad_to > len(out):
        out += b"\x00" * (pad_to - len(out))
    return bytes(out)


def _rules(findings):
    return [f.rule for f in findings]


class HardcodedAnchorTest(unittest.TestCase):
    """A byte-for-byte GGUF image computed by hand, independent of build_gguf."""

    def test_gdr001_hardcoded(self):
        data = (
            b"GGUF"                              # magic                     off 0
            + b"\x03\x00\x00\x00"               # version = 3               off 4
            + b"\x01\x00\x00\x00\x00\x00\x00\x00"  # tensor_count = 1       off 8
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # kv_count = 0           off 16
            + b"\x01\x00\x00\x00\x00\x00\x00\x00"  # name len = 1           off 24
            + b"a"                              # name = "a"                off 32
            + b"\x01\x00\x00\x00"               # n_dims = 1                off 33
            + b"\x04\x00\x00\x00\x00\x00\x00\x00"  # dims[0] = 4            off 37
            + b"\x00\x00\x00\x00"               # type = 0 (F32)            off 45
            + b"\xe8\x03\x00\x00\x00\x00\x00\x00"  # offset = 1000          off 49
            + b"\x00" * 43                      # pad to 100 bytes          off 57
        )
        self.assertEqual(len(data), 100)
        # after_tensor_info = 57; data_start = align_up(57, 32) = 64;
        # abs_start = 64 + 1000 = 1064 >= 100  ->  GDR001.
        findings = g.scan_bytes(data)
        self.assertIn("GDR001", _rules(findings))
        self.assertTrue(all(f.severity == "HIGH" for f in findings if f.rule == "GDR001"))


class DataRegionTest(unittest.TestCase):
    def test_offset_past_eof_is_gdr001(self):
        data = build_gguf([(b"a", [4], 0, 1000)], pad_to=100)
        findings = g.scan_bytes(data)
        self.assertIn("GDR001", _rules(findings))
        self.assertNotIn("GDR002", _rules(findings))

    def test_region_end_past_eof_is_gdr002(self):
        # dims=[100] F32 -> 400 bytes; data_start=64; 64+400 > 100.
        data = build_gguf([(b"w", [100], 0, 0)], pad_to=100)
        findings = g.scan_bytes(data)
        self.assertIn("GDR002", _rules(findings))
        self.assertNotIn("GDR001", _rules(findings))

    def test_in_bounds_tensor_is_clean(self):
        # dims=[4] F32 -> 16 bytes; data_start=64; 64+16 = 80 <= 80.
        data = build_gguf([(b"w", [4], 0, 0)], pad_to=80)
        findings = g.scan_bytes(data)
        self.assertEqual(_rules(findings), ["GDR000"])
        self.assertEqual(findings[0].severity, "INFO")

    def test_quantized_type_skips_gdr002_but_keeps_gdr001(self):
        # type 12 = Q4_K (block type): no exact size table -> no GDR002.
        # offset in-bounds, so the whole file is clean (no false positive).
        data = build_gguf([(b"w", [256], 12, 0)], pad_to=200)
        findings = g.scan_bytes(data)
        self.assertEqual(_rules(findings), ["GDR000"])
        # But a Q4_K tensor with an out-of-file offset is still caught by GDR001.
        data2 = build_gguf([(b"w", [256], 12, 5000)], pad_to=200)
        self.assertIn("GDR001", _rules(g.scan_bytes(data2)))


class AlignmentTest(unittest.TestCase):
    def test_general_alignment_kv_is_honored(self):
        # With alignment=256, data_start=align_up(90,256)=256 > file_size(200)
        #   -> GDR010. With the default 32 it would be 96 <= 200 and clean,
        # so a GDR010 here proves the general.alignment KV was parsed.
        kvs = [(b"general.alignment", g._GGUF_TYPE_UINT32, _u32(256))]
        data = build_gguf([(b"w", [1], 0, 0)], kvs=kvs, pad_to=200)
        self.assertIn("GDR010", _rules(g.scan_bytes(data)))

    def test_array_metadata_is_skipped_cleanly(self):
        # An array-of-uint32 KV must be walked past without derailing parsing.
        arr = _u32(4) + _u64(3) + _u32(1) + _u32(2) + _u32(3)  # type=UINT32, count=3
        kvs = [(b"arr", g._GGUF_TYPE_ARRAY, arr)]
        data = build_gguf([(b"w", [4], 0, 0)], kvs=kvs, pad_to=200)
        self.assertEqual(_rules(g.scan_bytes(data)), ["GDR000"])


class RobustnessTest(unittest.TestCase):
    def test_truncated_structure_is_gdr010(self):
        data = build_gguf([(b"a", [4], 0, 1000)], pad_to=100)[:40]
        self.assertIn("GDR010", _rules(g.scan_bytes(data)))

    def test_non_gguf_is_ignored(self):
        for blob in (b"\x00" * 50, b"PK\x03\x04" + b"\x00" * 40, b""):
            findings = g.scan_bytes(blob)
            self.assertEqual(_rules(findings), ["GDR000"])
            self.assertEqual(findings[0].severity, "INFO")

    def test_implausible_counts_do_not_hang(self):
        data = (
            g.GGUF_MAGIC + _u32(3)
            + _u64(2**40)  # tensor_count absurd
            + _u64(0)
        )
        self.assertIn("GDR010", _rules(g.scan_bytes(data)))

    def test_huge_array_count_does_not_hang(self):
        arr = _u32(g._GGUF_TYPE_STRING) + _u64(2**60)  # 2^60 strings
        kvs = [(b"x", g._GGUF_TYPE_ARRAY, arr)]
        data = build_gguf([(b"w", [4], 0, 0)], kvs=kvs, pad_to=200)
        # Should flag unparseable rather than loop 2^60 times.
        self.assertIn("GDR010", _rules(g.scan_bytes(data)))


class IOTest(unittest.TestCase):
    def test_scan_file_and_paths(self):
        data = build_gguf([(b"a", [4], 0, 1000)], pad_to=100)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.gguf")
            with open(p, "wb") as fh:
                fh.write(data)
            result = g.scan_paths([d])
            self.assertIn("GDR001", _rules(result.findings))
            self.assertIn(p, result.scanned_files)

    def test_main_fail_on(self):
        bad = build_gguf([(b"a", [4], 0, 1000)], pad_to=100)
        good = build_gguf([(b"w", [4], 0, 0)], pad_to=80)
        with tempfile.TemporaryDirectory() as d:
            bp = os.path.join(d, "bad.gguf")
            gp = os.path.join(d, "good.gguf")
            with open(bp, "wb") as fh:
                fh.write(bad)
            with open(gp, "wb") as fh:
                fh.write(good)
            self.assertEqual(g.main([bp, "--fail-on", "HIGH"]), 1)
            self.assertEqual(g.main([gp, "--fail-on", "HIGH"]), 0)


class ApiTest(unittest.TestCase):
    def test_finding_as_dict_keys(self):
        f = g.scan_bytes(build_gguf([(b"a", [4], 0, 1000)], pad_to=100))[0]
        self.assertEqual(
            set(f.as_dict()),
            {"rule", "severity", "key", "value", "file", "location", "message"},
        )

    def test_version_string(self):
        self.assertEqual(g.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
