# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Variant-named shard indexes, such as model.safetensors.index.fp16.json.

transformers and diffusers write save_pretrained(..., variant="fp16") as
model.safetensors.index.fp16.json. Since model-file-scan 0.12.0 and
safetensors_index_scan 0.2.0, such files are routed to the shard-index
scanner and kept in directory walks, like *.index.json. See
REALFILE_CHECK_STI_2026-11.md.

Stdlib only. Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import model_file_scan
import safetensors_index_scan as sti

VARIANT_NAMES = (
    "model.safetensors.index.fp16.json",
    "pytorch_model.bin.index.fp32.json",
    "diffusion_pytorch_model.safetensors.index.bf16.json",
    "model.safetensors.index.non_ema.json",
)
STANDARD_NAMES = (
    "model.safetensors.index.json",
    "pytorch_model.bin.index.json",
)
NOT_INDEX_NAMES = (
    "config.json",
    "generation_config.json",
    "index.json",
    "model.safetensors.index.fp16.json.bak",
    "model.fp16-00001-of-00002.safetensors",
)


def _field(finding, key):
    if isinstance(finding, dict):
        return finding.get(key)
    return getattr(finding, key, None)


def _rules(findings):
    return {str(_field(f, "rule")) for f in findings}


def _index(first_shard="model.fp16-00001-of-00002.safetensors"):
    return {"metadata": {"total_size": 16},
            "weight_map": {"a.weight": first_shard,
                           "b.weight": "model.fp16-00002-of-00002.safetensors"}}


def _version(text):
    return tuple(int(part) for part in text.split("."))


class VariantIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, doc):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path

    def _main(self, argv):
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), \
                contextlib.redirect_stderr(sink):
            return model_file_scan.main(argv)

    def test_versions(self):
        self.assertGreaterEqual(_version(sti.__version__), (0, 2, 0))
        self.assertGreaterEqual(_version(model_file_scan.__version__),
                                (0, 12, 0))

    def test_looks_like_index(self):
        for name in VARIANT_NAMES + STANDARD_NAMES + (
                "MODEL.SAFETENSORS.INDEX.FP16.JSON",):
            self.assertTrue(sti._looks_like_index(name), name)
        for name in NOT_INDEX_NAMES:
            self.assertFalse(sti._looks_like_index(name), name)

    def test_route_variant_and_standard_names(self):
        for name in VARIANT_NAMES + STANDARD_NAMES:
            self.assertEqual(model_file_scan.route(name), "sti", name)

    def test_route_other_names_unchanged(self):
        for name in ("config.json", "generation_config.json", "index.json",
                     "model.fp16-00001-of-00002.safetensors"):
            self.assertNotEqual(model_file_scan.route(name), "sti", name)
        self.assertEqual(model_file_scan.route("config.json"), "keras")

    def test_walk_keeps_variant_index(self):
        path = self._write("model.safetensors.index.fp16.json", _index())
        files, missing = model_file_scan.expand_paths([self.tmp])
        self.assertFalse(missing)
        self.assertIn(os.path.basename(path),
                      [os.path.basename(f) for f in files])

    def test_sti_scan_path_walks_variant_index(self):
        self._write("model.safetensors.index.fp16.json", _index())
        rules = _rules(sti.scan_path(self.tmp))
        self.assertIn("STI000", rules)

    def test_clean_variant_index_passes_folder_gate(self):
        self._write("model.safetensors.index.fp16.json", _index())
        self.assertEqual(self._main([self.tmp]), 0)

    def test_traversal_in_variant_index_found_by_folder_walk(self):
        path = self._write("model.safetensors.index.fp16.json",
                           _index("../outside.safetensors"))
        self.assertIn("STI002", _rules(sti.scan_path(self.tmp)))
        self.assertIn("STI002", _rules(model_file_scan.scan_path(path)))
        self.assertEqual(self._main([self.tmp]), 1)

    def test_traversal_in_bin_variant_index_found_by_folder_walk(self):
        self._write("pytorch_model.bin.index.fp32.json",
                    _index("../outside.bin"))
        self.assertIn("STI002", _rules(sti.scan_path(self.tmp)))
        self.assertEqual(self._main([self.tmp]), 1)


if __name__ == "__main__":
    unittest.main()
