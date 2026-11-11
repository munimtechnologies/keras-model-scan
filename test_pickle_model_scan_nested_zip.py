#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for pickle_model_scan 0.8.0: a zip member that is itself a zip
(such as the torch.save archive torch.export.save stores at
<prefix>/data/sample_inputs/model.pt inside a .pt2 file) is scanned as a zip,
up to two levels deep, instead of being read as one pickle stream.

The pickles here only NAME a harmless made-up class (mypkg.config.Settings)
with a GLOBAL opcode; nothing in them runs, and the scanner never unpickles.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import pickle
import unittest
import zipfile

import pickle_model_scan as pms

NAMES_CLASS = b"\x80\x02cmypkg.config\nSettings\nq\x00."
STATE = pickle.dumps({"w": 1}, protocol=2)


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def mentions(findings, text):
    return [f for f in findings if text in f.detail or text in f.location]


class NestedZip(unittest.TestCase):

    def test_version(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in pms.__version__.split(".")), (0, 8, 0))

    def test_pt2_sample_inputs_member_is_opened(self):
        inner = make_zip({"archive/data.pkl": NAMES_CLASS})
        outer = make_zip({"archive/models/model.json": b"{}",
                          "archive/data/sample_inputs/model.pt": inner})
        findings = pms.scan_zip(outer, "outer.pt2")
        head = "outer.pt2!archive/data/sample_inputs/model.pt!archive/data.pkl"
        hits = [f for f in findings if f.rule == "PKL003"
                and f.location.startswith(head)
                and "mypkg.config" in f.detail]
        self.assertEqual(len(hits), 1, [f.as_dict() for f in findings])
        self.assertEqual([f for f in findings if f.rule == "PKL000"], [])

    def test_honest_nested_torch_zip_is_quiet(self):
        inner = make_zip({"archive/data.pkl": STATE,
                          "archive/data/0": b"\x80" + b"\x00" * 7})
        outer = make_zip({"archive/data/sample_inputs/model.pt": inner})
        self.assertEqual(pms.scan_zip(outer, "outer.pt2"), [])

    def test_member_with_zip_magic_that_is_not_a_zip_keeps_old_path(self):
        member = b"PK\x03\x04" + b"\x00" * 26
        outer = make_zip({"x.bin": member})
        got = [f.rule for f in pms.scan_zip(outer, "b.zip")]
        want = [f.rule for f in pms.scan_pickle_bytes(member, "b.zip!x.bin")]
        self.assertEqual(got, want)
        self.assertNotIn("PKL098", got)

    def test_raw_storage_is_never_opened(self):
        storage = make_zip({"data.pkl": NAMES_CLASS})
        outer = make_zip({"m/data.pkl": STATE, "m/data/0": storage})
        self.assertEqual(pms.scan_zip(outer, "m.pt"), [])

    def test_two_levels_are_opened(self):
        b = make_zip({"data.pkl": NAMES_CLASS})
        a = make_zip({"b.blob": b})
        outer = make_zip({"a.blob": a})
        self.assertEqual(len(mentions(pms.scan_zip(outer, "o.zip"),
                                      "mypkg.config")), 1)

    def test_third_level_is_not_opened(self):
        c = make_zip({"data.pkl": NAMES_CLASS})
        b = make_zip({"c.blob": c})
        a = make_zip({"b.blob": b})
        outer = make_zip({"a.blob": a})
        self.assertEqual(mentions(pms.scan_zip(outer, "o.zip"),
                                  "mypkg.config"), [])

    def test_scan_blob_reaches_nested_member(self):
        inner = make_zip({"archive/data.pkl": NAMES_CLASS})
        outer = make_zip({"archive/data/sample_inputs/model.pt": inner})
        findings = pms.scan_blob(outer, "outer.pt2")
        self.assertEqual(len(mentions(findings, "mypkg.config")), 1)


if __name__ == "__main__":
    unittest.main()
