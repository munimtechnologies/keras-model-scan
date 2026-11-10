# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for census_lib (job pt2-census-v1). Standard library only.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import unittest

import census_lib as cl


class ExtOf(unittest.TestCase):
    def test_suffixes(self):
        self.assertEqual(cl.ext_of("model.pt2"), ".pt2")
        self.assertEqual(cl.ext_of("sub/dir/Model.TorchScript"), ".torchscript")
        self.assertEqual(cl.ext_of("a.tar.gz"), ".gz")

    def test_no_suffix(self):
        self.assertEqual(cl.ext_of("README"), "")
        self.assertEqual(cl.ext_of(".gitattributes"), "")
        self.assertEqual(cl.ext_of("dir.v1/LICENSE"), "")


class NextLink(unittest.TestCase):
    def test_next(self):
        h = '<https://huggingface.co/api/models?cursor=abc&limit=1000>; rel="next"'
        self.assertEqual(cl.next_link(h),
                         "https://huggingface.co/api/models?cursor=abc&limit=1000")

    def test_none(self):
        self.assertIsNone(cl.next_link(None))
        self.assertIsNone(cl.next_link('<https://x.org/a>; rel="prev"'))


class ClassifyHead(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(cl.classify_head(b"PK\x03\x04rest"), "zip")
        self.assertEqual(cl.classify_head(b"\x80\x02}q\x00"), "pickle")
        self.assertEqual(cl.classify_head(b"\x80\x09"), "other")
        self.assertEqual(cl.classify_head(b"GGUF"), "other")
        self.assertEqual(cl.classify_head(b""), "other")


class MemberOf(unittest.TestCase):
    def test_member(self):
        loc = "/work/hub/files/01/model.pt2!model/data/sample_inputs/model.pt @ byte 12"
        self.assertEqual(cl.member_of(loc), "model/data/sample_inputs/model.pt")

    def test_member_without_offset(self):
        self.assertEqual(cl.member_of("x.pt!archive/data.pkl"), "archive/data.pkl")

    def test_no_member(self):
        self.assertIsNone(cl.member_of("/work/hub/files/01/model.pt @ byte 3"))
        self.assertIsNone(cl.member_of(""))
        self.assertIsNone(cl.member_of(None))


class MemberRole(unittest.TestCase):
    def test_roles(self):
        r = cl.member_role
        self.assertEqual(r("model/data/sample_inputs/model.pt"), "sample_inputs")
        self.assertEqual(r("data/weights/weight_0"), "weights")
        self.assertEqual(r("m/data/constants/c0"), "constants")
        self.assertEqual(r("archive/data.pkl"), "pickle:data.pkl")
        self.assertEqual(r("archive/bytecode.pkl"), "pickle:bytecode.pkl")
        self.assertEqual(r("archive/code/__torch__/m.py"), "torchscript-code")
        self.assertEqual(r("archive/data/0"), "tensor-storage")
        self.assertEqual(r("x/serialized_state_dict.pt"),
                         "legacy-export:serialized_state_dict.pt")
        self.assertEqual(r("m/data/aotinductor/model/abc.so"), "native-library")
        self.assertEqual(r("m/archive_format"), "marker:archive_format")
        self.assertEqual(r("m/models/model.json"), "export-json")
        self.assertEqual(r("m/extra/notes.txt"), "other")


class Severity(unittest.TestCase):
    def test_max(self):
        self.assertEqual(cl.max_severity([]), -1)
        self.assertEqual(cl.max_severity([{"severity": "low"},
                                          {"severity": "MEDIUM"}]), 2)
        self.assertEqual(cl.max_severity([{"severity": "CRITICAL"}]), 4)

    def test_share(self):
        self.assertIsNone(cl.share(1, 0))
        self.assertEqual(cl.share(1, 4), 0.25)


if __name__ == "__main__":
    unittest.main()
