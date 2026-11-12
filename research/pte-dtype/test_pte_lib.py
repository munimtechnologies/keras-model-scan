#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pte_lib (jobs pte-census-v1 and pte-dtype-v1). Test data is
honest bytes: an ET12 identifier and an eh00 header with ordinary sizes.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import os
import struct
import tempfile
import unittest

import pte_lib as L


def head(program_size=1464, base=1536, data_size=60, length=32):
    body = struct.pack("<I", 28) + b"ET12" + b"eh00" + struct.pack("<I", length)
    body += struct.pack("<QQ", program_size, base)
    if length >= 32:
        body += struct.pack("<Q", data_size)
    return body + b"\0" * (64 - len(body))


class Names(unittest.TestCase):
    def test_ext_of(self):
        self.assertEqual(L.ext_of("a/b/model.PTE"), ".pte")
        self.assertEqual(L.ext_of("weights.ptd"), ".ptd")
        self.assertEqual(L.ext_of("README"), "")
        self.assertEqual(L.ext_of(".gitattributes"), "")

    def test_next_link(self):
        h = '<https://huggingface.co/api/models?cursor=x>; rel="next"'
        self.assertEqual(L.next_link(h), "https://huggingface.co/api/models?cursor=x")
        self.assertIsNone(L.next_link(None))
        self.assertIsNone(L.next_link('<u>; rel="prev"'))


class Head(unittest.TestCase):
    def test_full_header(self):
        info = L.parse_head(head())
        self.assertEqual(info["identifier"], "ET12")
        self.assertTrue(info["has_header"])
        self.assertEqual(info["program_size"], 1464)
        self.assertEqual(info["segment_base_offset"], 1536)
        self.assertEqual(info["segment_data_size"], 60)
        self.assertNotIn("error", info)

    def test_short_header_has_no_data_size(self):
        info = L.parse_head(head(length=24))
        self.assertEqual(info["segment_data_size"], 0)

    def test_header_length_too_small(self):
        self.assertIn("error", L.parse_head(head(length=16)))

    def test_no_header(self):
        data = struct.pack("<I", 20) + b"ET12" + b"\0" * 56
        info = L.parse_head(data)
        self.assertFalse(info["has_header"])
        self.assertEqual(info["identifier"], "ET12")

    def test_other_identifier(self):
        data = struct.pack("<I", 20) + b"TFL3" + b"\0" * 56
        self.assertEqual(L.parse_head(data)["identifier"], "TFL3")


class Plan(unittest.TestCase):
    def test_program_only(self):
        self.assertEqual(L.fetch_plan(L.parse_head(head()), 10_000_000, 100),
                         (None, "program over cap"))
        self.assertEqual(L.fetch_plan(L.parse_head(head()), 10_000_000, 2000),
                         (1464, "program"))

    def test_no_header_needs_whole_file(self):
        info = L.parse_head(struct.pack("<I", 20) + b"ET12" + b"\0" * 56)
        self.assertEqual(L.fetch_plan(info, 900, 1000), (900, "whole (no header)"))
        self.assertEqual(L.fetch_plan(info, 2000, 1000)[0], None)

    def test_unknown_size(self):
        self.assertEqual(L.fetch_plan(L.parse_head(head()), None, 10)[0], None)

    def test_program_larger_than_file(self):
        self.assertEqual(L.fetch_plan(L.parse_head(head(program_size=5000)),
                                      3000, 10_000), (3000, "program"))


class Sparse(unittest.TestCase):
    def test_sparse_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.pte")
            self.assertEqual(L.make_sparse(p, b"abc", 10), 10)
            with open(p, "rb") as fh:
                self.assertEqual(fh.read(), b"abc" + b"\0" * 7)

    def test_head_longer_than_size(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                L.make_sparse(os.path.join(d, "x"), b"abcd", 2)


class Findings(unittest.TestCase):
    F = [{"rule": "PTE003", "severity": "medium",
          "message": "backend delegate XnnpackBackend: that backend's native "
                     "code parses an ahead-of-time compiled blob at load; this "
                     "scanner cannot read inside it", "evidence": "e"},
         {"rule": "PTE004", "severity": "medium", "message": "m", "evidence": "x"}]

    def test_delegates(self):
        self.assertEqual(L.delegates(self.F), ["XnnpackBackend"])

    def test_gate(self):
        self.assertTrue(L.gate_fails(self.F))
        self.assertFalse(L.gate_fails([{"severity": "low"}]))
        self.assertFalse(L.gate_fails([]))
        self.assertTrue(L.gate_fails([{"severity": "HIGH"}]))

    def test_normalise_order_free(self):
        self.assertEqual(L.normalise(self.F), L.normalise(list(reversed(self.F))))

    def test_share(self):
        self.assertEqual(L.share(1, 4), 0.25)
        self.assertIsNone(L.share(1, 0))


if __name__ == "__main__":
    unittest.main()
