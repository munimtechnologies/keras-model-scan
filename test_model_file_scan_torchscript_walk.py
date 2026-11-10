# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""model-file-scan 0.14.0: a folder walk keeps TorchScript (.torchscript),
PyTorch mobile (.ptl) and torch.export (.pt2) files. Up to 0.13.2 the walk
skipped them silently (job torchscript-v1, row W2).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import os
import tempfile
import unittest

import model_file_scan as mfs

NEW = ("model.ptl", "model.torchscript", "model.pt2")


class TorchScriptWalkTest(unittest.TestCase):
    def test_version(self):
        ver = tuple(int(x) for x in mfs.__version__.split("."))
        self.assertGreaterEqual(ver, (0, 14, 0))

    def test_walk_keeps_each_extension(self):
        with tempfile.TemporaryDirectory() as d:
            for name in NEW + ("Yolo.TorchScript", "MOBILE.PTL", "EXPORT.PT2"):
                self.assertTrue(mfs._walk_keeps(d, name), name)

    def test_walk_still_skips_unrelated(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("notes.txt", "README.md"):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write("hello\n")
                self.assertFalse(mfs._walk_keeps(d, name), name)

    def test_expand_paths_lists_them(self):
        with tempfile.TemporaryDirectory() as d:
            for name in NEW + ("notes.txt",):
                with open(os.path.join(d, name), "wb") as fh:
                    fh.write(b"x")
            kept, _missing = mfs.expand_paths([d])
            names = sorted(os.path.basename(p) for p in kept)
            for name in NEW:
                self.assertIn(name, names)
            self.assertNotIn("notes.txt", names)


if __name__ == "__main__":
    unittest.main()
