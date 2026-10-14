# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Tests for safetensors_scan.py. Made with AI by MV2 of Munim, Inc.
# Standard library only; crafts safetensors bytes in-memory, never loads a model.

import json
import os
import struct
import tempfile
import unittest

import safetensors_scan as s


def make_st(header_obj, data_len=0):
    """Build a well-formed-prefix safetensors blob from a header object."""
    hdr = json.dumps(header_obj).encode("utf-8")
    return struct.pack("<Q", len(hdr)) + hdr + (b"\x00" * data_len)


def write_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".safetensors")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def rules(findings):
    return {f.rule for f in findings}


class ValidFile(unittest.TestCase):
    def test_valid_single_tensor_is_clean(self):
        blob = make_st({"w": {"dtype": "F32", "shape": [2, 2],
                              "data_offsets": [0, 16]}}, data_len=16)
        path = write_tmp(blob)
        try:
            findings = s.scan_file(path)
            self.assertEqual(rules(findings), {"SFT000"})
            self.assertEqual(findings[0].severity, "INFO")
        finally:
            os.remove(path)

    def test_metadata_key_is_ignored(self):
        blob = make_st({"__metadata__": {"framework": "pt"},
                        "w": {"dtype": "F16", "shape": [4],
                              "data_offsets": [0, 8]}}, data_len=8)
        path = write_tmp(blob)
        try:
            self.assertEqual(rules(s.scan_file(path)), {"SFT000"})
        finally:
            os.remove(path)

    def test_two_contiguous_tensors_clean(self):
        blob = make_st({
            "a": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
            "b": {"dtype": "F32", "shape": [2, 2], "data_offsets": [16, 32]},
        }, data_len=32)
        path = write_tmp(blob)
        try:
            self.assertEqual(rules(s.scan_file(path)), {"SFT000"})
        finally:
            os.remove(path)


class HeaderLength(unittest.TestCase):
    def test_declared_header_exceeds_file(self):
        blob = struct.pack("<Q", 1000) + b"{}"
        path = write_tmp(blob)
        try:
            self.assertIn("SFT001", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_header_over_cap(self):
        blob = struct.pack("<Q", 200_000_000) + b"{}"
        path = write_tmp(blob)
        try:
            r = rules(s.scan_file(path))
            self.assertIn("SFT002", r)
        finally:
            os.remove(path)

    def test_too_small_file(self):
        path = write_tmp(b"\x00\x00")
        try:
            self.assertIn("SFT007", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_zero_length_header(self):
        path = write_tmp(struct.pack("<Q", 0) + b"abcd")
        try:
            self.assertIn("SFT007", rules(s.scan_file(path)))
        finally:
            os.remove(path)


class OffsetValidation(unittest.TestCase):
    def test_offsets_past_data_section(self):
        blob = make_st({"w": {"dtype": "F32", "shape": [2, 2],
                              "data_offsets": [0, 32]}}, data_len=16)
        path = write_tmp(blob)
        try:
            self.assertIn("SFT003", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_size_mismatch(self):
        # F32 [2,2] needs 16 bytes, but offsets span only 8.
        blob = make_st({"w": {"dtype": "F32", "shape": [2, 2],
                              "data_offsets": [0, 8]}}, data_len=8)
        path = write_tmp(blob)
        try:
            self.assertIn("SFT005", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_overlapping_tensors(self):
        blob = make_st({
            "a": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
            "b": {"dtype": "F32", "shape": [2, 2], "data_offsets": [8, 24]},
        }, data_len=24)
        path = write_tmp(blob)
        try:
            self.assertIn("SFT004", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_reversed_offsets(self):
        blob = make_st({"w": {"dtype": "U8", "shape": [4],
                              "data_offsets": [16, 4]}}, data_len=16)
        path = write_tmp(blob)
        try:
            self.assertIn("SFT003", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_unknown_dtype(self):
        blob = make_st({"w": {"dtype": "FLOAT9000", "shape": [1],
                              "data_offsets": [0, 0]}}, data_len=0)
        path = write_tmp(blob)
        try:
            self.assertIn("SFT008", rules(s.scan_file(path)))
        finally:
            os.remove(path)


class Coverage(unittest.TestCase):
    def test_trailing_bytes_flagged(self):
        blob = make_st({"w": {"dtype": "F32", "shape": [2, 2],
                              "data_offsets": [0, 16]}}, data_len=16)
        path = write_tmp(blob + b"extra bytes not in the header")
        try:
            findings = s.scan_file(path)
            self.assertIn("SFT009", rules(findings))
            self.assertNotIn("SFT000", rules(findings))
            self.assertEqual(s.main([path]), 1)
        finally:
            os.remove(path)

    def test_metadata_only_with_trailing_bytes_flagged(self):
        blob = make_st({"__metadata__": {"framework": "pt"}}, data_len=4)
        path = write_tmp(blob)
        try:
            self.assertIn("SFT009", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_first_tensor_not_at_zero_flagged(self):
        blob = make_st({"w": {"dtype": "F32", "shape": [2, 2],
                              "data_offsets": [4, 20]}}, data_len=20)
        path = write_tmp(blob)
        try:
            findings = s.scan_file(path)
            self.assertIn("SFT004", rules(findings))
            self.assertNotIn("SFT009", rules(findings))
        finally:
            os.remove(path)

    def test_zero_length_tensor_is_clean(self):
        blob = make_st({
            "a": {"dtype": "F32", "shape": [0], "data_offsets": [0, 0]},
            "b": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]},
        }, data_len=4)
        path = write_tmp(blob)
        try:
            self.assertEqual(rules(s.scan_file(path)), {"SFT000"})
        finally:
            os.remove(path)


class MalformedHeader(unittest.TestCase):
    def test_deeply_nested_header(self):
        inner = b"[" * 150 + b"0" + b"]" * 150
        blob = struct.pack("<Q", len(inner)) + inner
        path = write_tmp(blob)
        try:
            r = rules(s.scan_file(path))
            self.assertIn("SFT006", r)
        finally:
            os.remove(path)

    def test_not_json(self):
        body = b"this is not json!!"
        blob = struct.pack("<Q", len(body)) + body
        path = write_tmp(blob)
        try:
            self.assertIn("SFT007", rules(s.scan_file(path)))
        finally:
            os.remove(path)

    def test_json_not_object(self):
        body = b"[1, 2, 3]"
        blob = struct.pack("<Q", len(body)) + body
        path = write_tmp(blob)
        try:
            self.assertIn("SFT007", rules(s.scan_file(path)))
        finally:
            os.remove(path)


class Depth(unittest.TestCase):
    def test_bracket_depth_ignores_strings(self):
        self.assertEqual(s._max_bracket_depth(b'{"a": "[[[["}'), 1)

    def test_bracket_depth_counts_nesting(self):
        self.assertEqual(s._max_bracket_depth(b"[[[]]]"), 3)


class Numel(unittest.TestCase):
    def test_scalar_shape(self):
        self.assertEqual(s._numel([]), 1)

    def test_negative_dim_rejected(self):
        self.assertIsNone(s._numel([-1, 2]))

    def test_bool_dim_rejected(self):
        self.assertIsNone(s._numel([True]))


class CliAndApi(unittest.TestCase):
    def test_main_flags_bad_file(self):
        blob = make_st({"w": {"dtype": "F32", "shape": [2, 2],
                              "data_offsets": [0, 32]}}, data_len=16)
        path = write_tmp(blob)
        try:
            self.assertEqual(s.main([path]), 1)
        finally:
            os.remove(path)

    def test_main_passes_clean_file(self):
        blob = make_st({"w": {"dtype": "F32", "shape": [2, 2],
                              "data_offsets": [0, 16]}}, data_len=16)
        path = write_tmp(blob)
        try:
            self.assertEqual(s.main([path]), 0)
        finally:
            os.remove(path)

    def test_as_dict_shape(self):
        f = s.Finding("SFT000", "INFO", "t", "d", "loc", "")
        self.assertEqual(set(f.as_dict()), {"rule", "severity", "title",
                                            "detail", "location", "cve"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
