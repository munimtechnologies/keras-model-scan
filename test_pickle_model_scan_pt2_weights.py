#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tests for pickle_model_scan 0.9.0: in a torch.export (.pt2) archive, the
raw tensor payloads that the archive's own weights or constants config
declares with use_pickle false are treated as data, as torch.export.load
reads them, instead of being walked as a pickle when their first byte is
0x80.

RAW is ordinary float32 tensor bytes (1.0000153, then other floats), the
same first bytes torch wrote for the fixture model_b.pt2 in job pt2-nest-v1.
The one pickle here only NAMES a harmless made-up class
(mypkg.config.Settings) with a GLOBAL opcode; nothing in it runs, and the
scanner never unpickles.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import unittest
import zipfile

import pickle_model_scan as pms

RAW = b"\x80\x00\x80\x3f\x14\x2c\x9b\x3e" * 2
NAMES_CLASS = b"\x80\x02cmypkg.config\nSettings\nq\x00."


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def config(entries):
    return json.dumps({"config": {
        fqn: {"path_name": path, "is_param": True, "use_pickle": pickled,
              "tensor_meta": None}
        for fqn, (path, pickled) in entries.items()}}).encode()


def pt2(extra=None, weights=None, use_pickle=False, fmt=b"pt2",
        prefix="model/"):
    members = {
        prefix + "archive_format": fmt,
        prefix + "archive_version": b"0",
        prefix + "models/model.json": b"{}",
        prefix + "data/weights/weight_0": RAW,
        prefix + "data/weights/model_weights_config.json": config(
            weights if weights is not None
            else {"fc.weight": ("weight_0", use_pickle)}),
    }
    if fmt is None:
        del members[prefix + "archive_format"]
    members.update(extra or {})
    return make_zip(members)


def at(findings, member):
    return [f for f in findings if f.location.endswith("!" + member)]


class Pt2RawWeights(unittest.TestCase):

    def old_path(self, data, member):
        """What 0.8.0 reports for MEMBER: the pickle walk of its bytes."""
        return [f.rule for f in pms.scan_pickle_bytes(RAW, "s!" + member)]

    def test_version(self):
        self.assertGreaterEqual(
            tuple(int(p) for p in pms.__version__.split(".")), (0, 9, 0))

    def test_raw_bytes_alone_read_as_damaged_pickle(self):
        # The premise: these honest tensor bytes look like a broken pickle.
        self.assertIn("PKL000", self.old_path(RAW, "w"))

    def test_declared_raw_weight_is_data(self):
        self.assertEqual(pms.scan_zip(pt2(), "m.pt2"), [])

    def test_raw_constant_is_data(self):
        extra = {
            "model/data/constants/tensor_0": RAW,
            "model/data/constants/model_constants_config.json": config(
                {"lifted_tensor_0": ("tensor_0", False)}),
        }
        self.assertEqual(pms.scan_zip(pt2(extra), "m.pt2"), [])

    def test_use_pickle_true_keeps_old_path(self):
        found = at(pms.scan_zip(pt2(use_pickle=True), "m.pt2"),
                   "model/data/weights/weight_0")
        self.assertEqual([f.rule for f in found],
                         self.old_path(RAW, "model/data/weights/weight_0"))
        self.assertTrue(found)

    def test_use_pickle_missing_keeps_old_path(self):
        cfg = json.dumps({"config": {"fc.weight": {
            "path_name": "weight_0", "is_param": True}}}).encode()
        data = pt2({"model/data/weights/model_weights_config.json": cfg})
        self.assertTrue(at(pms.scan_zip(data, "m.pt2"),
                           "model/data/weights/weight_0"))

    def test_member_no_config_names_keeps_old_path(self):
        data = pt2({"model/data/weights/weight_1": RAW})
        found = pms.scan_zip(data, "m.pt2")
        self.assertEqual(at(found, "model/data/weights/weight_0"), [])
        self.assertTrue(at(found, "model/data/weights/weight_1"))

    def test_no_archive_format_keeps_old_path(self):
        self.assertTrue(at(pms.scan_zip(pt2(fmt=None), "m.zip"),
                           "model/data/weights/weight_0"))

    def test_other_archive_format_keeps_old_path(self):
        self.assertTrue(at(pms.scan_zip(pt2(fmt=b"zip"), "m.zip"),
                           "model/data/weights/weight_0"))

    def test_aotinductor_archive_keeps_old_path(self):
        data = pt2({"model/data/aotinductor/model/model.wrapper.cpp": b"//"})
        self.assertTrue(at(pms.scan_zip(data, "m.pt2"),
                           "model/data/weights/weight_0"))

    def test_path_name_with_folder_is_not_trusted(self):
        data = pt2({"model/data/weights/sub/weight_0": RAW},
                   weights={"fc.weight": ("sub/weight_0", False)})
        found = pms.scan_zip(data, "m.pt2")
        self.assertTrue(at(found, "model/data/weights/sub/weight_0"))
        self.assertTrue(at(found, "model/data/weights/weight_0"))

    def test_config_in_other_folder_does_not_count(self):
        data = make_zip({
            "model/archive_format": b"pt2",
            "model/data/weights/weight_0": RAW,
            "model/extra/model_weights_config.json": config(
                {"fc.weight": ("weight_0", False)}),
        })
        self.assertTrue(at(pms.scan_zip(data, "m.pt2"),
                           "model/data/weights/weight_0"))

    def test_malformed_config_keeps_old_path(self):
        data = pt2({"model/data/weights/model_weights_config.json": b"{oops"})
        self.assertTrue(at(pms.scan_zip(data, "m.pt2"),
                           "model/data/weights/weight_0"))

    def test_prefix_from_archive_name(self):
        self.assertEqual(pms.scan_zip(pt2(prefix="model_b/"), "b.pt2"), [])

    def test_nested_sample_inputs_still_scanned(self):
        inner = make_zip({"archive/data.pkl": NAMES_CLASS})
        data = pt2({"model/data/sample_inputs/model.pt": inner})
        found = pms.scan_zip(data, "m.pt2")
        hits = [f for f in found if f.rule == "PKL003"
                and "mypkg.config" in f.detail]
        self.assertEqual(len(hits), 1, [f.as_dict() for f in found])
        self.assertEqual(at(found, "model/data/weights/weight_0"), [])

    def test_scan_blob_reaches_rule(self):
        self.assertEqual(pms.scan_blob(pt2(), "m.pt2"), [])


if __name__ == "__main__":
    unittest.main()
