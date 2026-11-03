# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tensor type ids in gguf_scan 0.2.0.

llama.cpp's ggml defines tensor types up to GGML_TYPE_F8_E4M3 = 43
(GGML_TYPE_COUNT = 44, tag b12034). Types 39-43 (MXFP4, NVFP4, Q1_0, Q2_0,
F8_E4M3) must not be reported as out of range; 44 and above must be.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import struct
import unittest

import gguf_scan

LOUD = ("MEDIUM", "HIGH", "CRITICAL")


def one_tensor_gguf(ttype, ne0=256, data_len=256):
    """A GGUF v3 file with no metadata and one 1-D tensor at offset 0."""
    name = b"t"
    out = b"GGUF" + struct.pack("<IQQ", 3, 1, 0)
    out += struct.pack("<Q", len(name)) + name
    out += struct.pack("<I", 1) + struct.pack("<Q", ne0)
    out += struct.pack("<IQ", ttype, 0)
    out += b"\x00" * ((-len(out)) % 32)
    out += b"\x00" * data_len
    return out


def rules(findings):
    return sorted(set(f.rule for f in findings))


def loud(findings):
    return [f for f in findings if str(f.severity).upper() in LOUD]


class TypeIdTests(unittest.TestCase):
    def scan(self, ttype):
        raw = one_tensor_gguf(ttype)
        return gguf_scan.scan_bytes(raw, len(raw), "t.gguf")

    def test_version(self):
        self.assertEqual(gguf_scan.__version__, "0.2.0")

    def test_f32_control_is_clean(self):
        findings = self.scan(0)
        self.assertNotIn("GG010", rules(findings))
        self.assertEqual(loud(findings), [])

    def test_current_types_not_out_of_range(self):
        for ttype in (39, 40, 41, 42, 43):
            with self.subTest(ttype=ttype):
                findings = self.scan(ttype)
                self.assertNotIn("GG010", rules(findings))
                self.assertEqual(loud(findings), [])

    def test_type_count_and_above_out_of_range(self):
        for ttype in (44, 45, 1000, 0xFFFFFFFF):
            with self.subTest(ttype=ttype):
                self.assertIn("GG010", rules(self.scan(ttype)))


if __name__ == "__main__":
    unittest.main()
