# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Tests for gguf_scan.py: a crafted-corpus check that every integrity rule fires
# on the header condition it targets, that a well-formed header is clean, and that
# model_file_scan routes .gguf to this scanner. The fixtures are built byte by
# byte in memory from the GGUF v3 layout; no real model or network is used, and
# nothing is ever executed. Made with AI by MV2 of Munim, Inc.

import os
import struct
import tempfile
import unittest

import gguf_scan
import model_file_scan

# GGUF value type ids used by the fixtures.
T_UINT32 = 4
T_STRING = 8
T_ARRAY = 9


def _s(b: bytes) -> bytes:
    """gguf_string: uint64 length prefix + bytes."""
    return struct.pack("<Q", len(b)) + b


def _u32(n: int) -> bytes:
    return struct.pack("<I", n)


def _u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def build(tensor_count, kv_count, kv_blob=b"", ti_blob=b"", version=3,
          magic=b"GGUF"):
    """Assemble a GGUF header from parts, so each test can corrupt one field."""
    return (magic + _u32(version) + _u64(tensor_count) + _u64(kv_count)
            + kv_blob + ti_blob)


def kv(key: bytes, vtype: int, value: bytes) -> bytes:
    return _s(key) + _u32(vtype) + value


def tensor(name: bytes, dims, ttype: int, offset: int) -> bytes:
    blob = _s(name) + _u32(len(dims))
    for d in dims:
        blob += _u64(d)
    blob += _u32(ttype) + _u64(offset)
    return blob


def rules(findings):
    return sorted(f.rule for f in findings)


def scan(data: bytes):
    return gguf_scan.scan_bytes(data, len(data), "fixture.gguf")


class CleanHeader(unittest.TestCase):
    def test_well_formed_is_info_only(self):
        data = build(
            tensor_count=1, kv_count=1,
            kv_blob=kv(b"general.alignment", T_UINT32, _u32(32)),
            ti_blob=tensor(b"w", [4], 0, 0))
        findings = scan(data)
        self.assertEqual(rules(findings), ["GG000"])
        self.assertEqual(findings[0].severity, "INFO")

    def test_clean_file_through_scan_file(self):
        data = build(
            tensor_count=1, kv_count=1,
            kv_blob=kv(b"general.alignment", T_UINT32, _u32(32)),
            ti_blob=tensor(b"w", [4], 0, 0))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.gguf")
            with open(p, "wb") as fh:
                fh.write(data)
            findings = gguf_scan.scan_file(p)
        self.assertEqual(rules(findings), ["GG000"])


class MagicAndVersion(unittest.TestCase):
    def test_bad_magic(self):
        data = build(0, 0, magic=b"XXXX")
        self.assertEqual(rules(scan(data)), ["GG001"])

    def test_unsupported_version(self):
        data = build(0, 0, version=99)
        self.assertEqual(rules(scan(data)), ["GG002"])

    def test_legacy_v1_flagged(self):
        data = build(0, 0, version=1)
        self.assertEqual(rules(scan(data)), ["GG002"])
        self.assertEqual(scan(data)[0].severity, "LOW")


class CountsExceedFile(unittest.TestCase):
    def test_tensor_count_too_large(self):
        data = build(tensor_count=10 ** 9, kv_count=0)
        self.assertIn("GG003", rules(scan(data)))

    def test_kv_count_too_large(self):
        data = build(tensor_count=0, kv_count=10 ** 9)
        self.assertIn("GG003", rules(scan(data)))


class MetadataLengths(unittest.TestCase):
    def test_string_value_overruns_file(self):
        data = build(0, 1, kv_blob=kv(b"x", T_STRING, _u64(10 ** 9)))
        self.assertEqual(rules(scan(data)), ["GG004"])

    def test_array_length_overflows(self):
        blob = kv(b"a", T_ARRAY, _u32(T_UINT32) + _u64(10 ** 18))
        data = build(0, 1, kv_blob=blob)
        self.assertEqual(rules(scan(data)), ["GG006"])

    def test_unknown_value_type(self):
        data = build(0, 1, kv_blob=kv(b"u", 99, b""))
        self.assertEqual(rules(scan(data)), ["GG005"])


class TensorInfo(unittest.TestCase):
    def test_dimension_product_overflow(self):
        data = build(1, 0, ti_blob=tensor(b"w", [2 ** 32, 2 ** 32], 0, 0))
        self.assertEqual(rules(scan(data)), ["GG009"])

    def test_out_of_range_type_id(self):
        data = build(1, 0, ti_blob=tensor(b"w", [4], 999, 0))
        self.assertEqual(rules(scan(data)), ["GG010"])

    def test_too_many_dimensions(self):
        data = build(1, 0, ti_blob=tensor(b"w", [1, 1, 1, 1, 1], 0, 0))
        self.assertEqual(rules(scan(data)), ["GG008"])

    def test_unaligned_offset(self):
        data = build(1, 0, ti_blob=tensor(b"w", [4], 0, 8))
        self.assertEqual(rules(scan(data)), ["GG011"])

    def test_oversized_name(self):
        data = build(1, 0, ti_blob=tensor(b"n" * 65, [4], 0, 0))
        self.assertIn("GG007", rules(scan(data)))


class Truncation(unittest.TestCase):
    def test_truncated_tensor_info(self):
        # Declares one tensor but provides none of its bytes.
        data = build(tensor_count=1, kv_count=0)
        self.assertEqual(rules(scan(data)), ["GG012"])

    def test_truncated_header(self):
        data = b"GGUF" + _u32(3) + _u64(1)  # stops inside the counts
        self.assertEqual(rules(scan(data)), ["GG012"])


class Routing(unittest.TestCase):
    def test_gguf_routes_to_gguf(self):
        self.assertEqual(model_file_scan.route("model.gguf"), "gguf")
        self.assertEqual(model_file_scan.route("/tmp/Q4_K_M.GGUF"), "gguf")

    def test_dispatch_runs_gguf_scanner(self):
        data = build(
            tensor_count=1, kv_count=1,
            kv_blob=kv(b"general.alignment", T_UINT32, _u32(32)),
            ti_blob=tensor(b"w", [4], 0, 0))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.gguf")
            with open(p, "wb") as fh:
                fh.write(data)
            findings = model_file_scan.scan_path(p)
        self.assertEqual(rules(findings), ["GG000"])


if __name__ == "__main__":
    unittest.main()
