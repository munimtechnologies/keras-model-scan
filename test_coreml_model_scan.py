#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Self-contained tests for coreml_model_scan. Standard library only."""

import json
import os
import shutil
import tempfile
import unittest

import coreml_model_scan as cm


def _vint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _ld(field, payload):
    return _vint((field << 3) | 2) + _vint(len(payload)) + payload


def _vf(field, n):
    return _vint(field << 3) + _vint(n)


def _s(field, text):
    return _ld(field, text.encode("utf-8"))


def _model(*parts):
    # specificationVersion = 1, description = 2 (empty), then the model type.
    return _vf(1, 7) + _ld(2, b"") + b"".join(parts)


def _layer(name, *parts):
    return _s(1, name) + b"".join(parts)


def _network(*layers):
    return b"".join(_ld(1, layer) for layer in layers)


def _custom_layer(name, cls):
    return _layer(name, _ld(500, _s(10, cls)))


def _linked(file_name, search_path):
    link_file = _ld(1, _s(1, file_name)) + _ld(2, _s(1, search_path))
    return _model(_ld(556, _ld(1, link_file)))


def _program(file_name):
    blob = _s(1, file_name) + _vf(2, 64)   # BlobFileValue fileName, offset
    value = _ld(5, blob)                   # Value.blobFileValue = 5
    return _model(_ld(502, _ld(1, _ld(2, value))))


_MANIFEST = {
    "fileFormatVersion": "1.0.0",
    "itemInfoEntries": {
        "A": {"author": "com.apple.CoreML", "name": "model.mlmodel",
              "path": "com.apple.CoreML/model.mlmodel"},
        "B": {"author": "com.apple.CoreML", "name": "weights",
              "path": "com.apple.CoreML/weights"},
    },
    "rootModelIdentifier": "A",
}


def _manifest(**changes):
    manifest = json.loads(json.dumps(_MANIFEST))
    manifest.update(changes)
    return manifest


def _rules(findings):
    return [f["rule"] for f in findings]


def _package(root, model_bytes, manifest=None):
    pkg = os.path.join(root, "M.mlpackage")
    os.makedirs(os.path.join(pkg, "Data", "com.apple.CoreML", "weights"))
    with open(os.path.join(pkg, "Data", "com.apple.CoreML", "model.mlmodel"),
              "wb") as handle:
        handle.write(model_bytes)
    with open(os.path.join(pkg, "Manifest.json"), "w") as handle:
        json.dump(manifest or _MANIFEST, handle)
    return pkg


class CoreMlModelScanTests(unittest.TestCase):

    def test_version(self):
        self.assertEqual(cm.__version__, "0.1.0")

    def test_clean_network_no_findings(self):
        model = _model(_ld(500, _network(_layer("dense"), _layer("relu"))))
        self.assertEqual(cm.scan_bytes(model), [])

    def test_bare_spec_no_findings(self):
        self.assertEqual(cm.scan_bytes(_model()), [])

    def test_custom_layer_is_cml001(self):
        model = _model(_ld(500, _network(_custom_layer("c", "MyLayer"))))
        findings = cm.scan_bytes(model)
        self.assertEqual(_rules(findings), ["CML001"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("MyLayer", findings[0]["evidence"])

    def test_custom_layer_in_classifier_and_regressor(self):
        for field in (303, 403):
            model = _model(_ld(field, _network(_custom_layer("c", "K"))))
            self.assertIn("CML001", _rules(cm.scan_bytes(model)))

    def test_custom_layer_inside_branch_is_cml001(self):
        inner = _network(_custom_layer("deep", "BranchLayer"))
        branch = _layer("b", _ld(605, _ld(2, inner)))   # elseBranch
        findings = cm.scan_bytes(_model(_ld(500, _network(branch))))
        self.assertIn("CML001", _rules(findings))
        self.assertIn("BranchLayer", findings[0]["evidence"])
        self.assertIn("(else)", findings[0]["evidence"])

    def test_custom_layer_inside_loop_body_is_cml001(self):
        body = _network(_custom_layer("deep", "LoopLayer"))
        loop = _layer("l", _ld(615, _vf(1, 3) + _ld(4, body)))
        findings = cm.scan_bytes(_model(_ld(500, _network(loop))))
        self.assertIn("CML001", _rules(findings))
        self.assertIn("(body)", findings[0]["evidence"])

    def test_custom_model_is_cml001(self):
        findings = cm.scan_bytes(_model(_ld(555, _s(10, "EvilModel"))))
        self.assertEqual(_rules(findings), ["CML001"])
        self.assertIn("EvilModel", findings[0]["evidence"])

    def test_custom_model_inside_pipelines(self):
        inner = _model(_ld(555, _s(10, "Inner")))
        pipeline = _ld(1, _model()) + _ld(1, inner)
        for model in (_model(_ld(202, pipeline)),
                      _model(_ld(200, _ld(1, pipeline))),
                      _model(_ld(201, _ld(1, pipeline)))):
            findings = cm.scan_bytes(model)
            self.assertIn("CML001", _rules(findings))
            self.assertIn("pipeline model 1", findings[0]["evidence"])

    def test_same_class_reported_once_with_count(self):
        net = _network(_custom_layer("a", "Same"), _custom_layer("b", "Same"))
        findings = cm.scan_bytes(_model(_ld(500, net)))
        self.assertEqual(_rules(findings), ["CML001"])
        self.assertIn("2 in total", findings[0]["evidence"])

    def test_linked_model_relative_and_bundle_paths_are_clean(self):
        for search in ("", ".", "models", "$BUNDLE_MAIN:.",
                       "$BUNDLE_IDENTIFIER(com.example.app)/models"):
            self.assertEqual(cm.scan_bytes(_linked("Feat.mlmodelc", search)),
                             [], search)

    def test_linked_model_absolute_search_path_is_cml002(self):
        findings = cm.scan_bytes(_linked("Feat.mlmodelc", ".:/var/tmp"))
        self.assertEqual(_rules(findings), ["CML002"])
        self.assertIn("/var/tmp", findings[0]["evidence"])

    def test_linked_model_parent_and_home_are_cml002(self):
        for search in ("models:../../x", "~/Library",
                       "$BUNDLE_MAIN/../..",
                       "$BUNDLE_IDENTIFIER(com.x)/../../y"):
            self.assertIn("CML002", _rules(cm.scan_bytes(
                _linked("Feat.mlmodelc", search))), search)

    def test_linked_model_unknown_variable_is_cml002(self):
        for search in ("$HOME/models", "$BUNDLE_IDENTIFIER(unclosed"):
            self.assertIn("CML002", _rules(cm.scan_bytes(
                _linked("Feat.mlmodelc", search))), search)

    def test_linked_model_file_name_traversal_is_cml002(self):
        findings = cm.scan_bytes(_linked("../x.mlmodelc", ""))
        self.assertEqual(_rules(findings), ["CML002"])

    def test_ml_program_default_weight_path_is_clean(self):
        self.assertEqual(
            cm.scan_bytes(_program("@model_path/weights/weight.bin")), [])

    def test_ml_program_weight_escape_is_cml003(self):
        for name in ("@model_path/../../../etc/x.bin", "/etc/weights.bin",
                     "~/w.bin", "file:///tmp/w.bin", "C:\\w\\weight.bin"):
            findings = cm.scan_bytes(_program(name))
            self.assertEqual(_rules(findings), ["CML003"], name)

    def test_ml_program_other_strings_ignored(self):
        self.assertEqual(cm.scan_bytes(_program("../not/a/weight/file")), [])

    def test_not_protobuf_is_cml005(self):
        self.assertEqual(_rules(cm.scan_bytes(b"hello world")), ["CML005"])

    def test_protobuf_without_spec_version_is_cml005(self):
        self.assertEqual(_rules(cm.scan_bytes(_ld(2, b""))), ["CML005"])

    def test_empty_and_truncated_never_crash(self):
        full = _model(_ld(500, _network(_custom_layer("c", "MyLayer"))))
        for raw in (b"", full[:-3], full[:5], b"\xff" * 12, b"\x08"):
            findings = cm.scan_bytes(raw)
            self.assertIsInstance(findings, list)
            self.assertIn("CML005", _rules(findings))

    def test_parse_errors_are_not_guard_crashes(self):
        # Regression (0.1.0 was first refused by CI): a clean or malformed
        # input must reach the parser, never the guard's crash finding.
        for raw in (_model(), b"hello world", b"{not json",
                    json.dumps(_MANIFEST).encode("utf-8")):
            for f in cm.scan_bytes(raw):
                self.assertNotIn("could not be parsed", f["message"])

    def test_deep_nesting_stops_with_cml005(self):
        net = _network(_layer("leaf"))
        for _ in range(40):
            net = _network(_layer("b", _ld(605, _ld(1, net))))
        findings = cm.scan_bytes(_model(_ld(500, net)))
        self.assertIn("CML005", _rules(findings))

    def test_manifest_bytes_clean(self):
        raw = json.dumps(_MANIFEST).encode("utf-8")
        self.assertEqual(cm.scan_bytes(raw), [])

    def test_manifest_item_path_escape_is_cml004(self):
        for path in ("../../outside", "/etc/passwd", "C:\\x\\y",
                     "com.apple.CoreML/../../../z", "~/x"):
            manifest = _manifest()
            manifest["itemInfoEntries"]["B"]["path"] = path
            findings = cm.scan_bytes(json.dumps(manifest).encode("utf-8"))
            self.assertEqual(_rules(findings), ["CML004"], path)

    def test_manifest_missing_root_is_cml005(self):
        raw = json.dumps(_manifest(rootModelIdentifier="Z")).encode("utf-8")
        self.assertEqual(_rules(cm.scan_bytes(raw)), ["CML005"])

    def test_manifest_invalid_json_is_cml005(self):
        self.assertEqual(_rules(cm.scan_bytes(b"{not json")), ["CML005"])

    def test_output_is_ascii_with_fixed_keys(self):
        model = _model(_ld(500, _network(_custom_layer("c\u00e9",
                                                       "Lay\u00e9r"))))
        findings = cm.scan_bytes(model)
        self.assertTrue(findings)
        for f in findings:
            self.assertEqual(set(f), {"rule", "severity", "cve", "cwe",
                                      "message", "evidence"})
            self.assertTrue(all(ord(c) < 128 for c in f["message"]))
            self.assertTrue(all(ord(c) < 128 for c in f["evidence"]))

    def test_package_clean_and_main_zero(self):
        root = tempfile.mkdtemp()
        try:
            pkg = _package(root, _program("@model_path/weights/weight.bin"))
            self.assertEqual(cm.scan_file(pkg), [])
            self.assertEqual(cm.scan_file(os.path.join(pkg, "Manifest.json")),
                             [])
            self.assertEqual(cm.main([pkg]), 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_package_custom_layer_and_main_one(self):
        root = tempfile.mkdtemp()
        try:
            model = _model(_ld(500, _network(_custom_layer("c", "PkgLayer"))))
            pkg = _package(root, model)
            findings = cm.scan_file(pkg)
            self.assertEqual(_rules(findings), ["CML001"])
            self.assertIn("com.apple.CoreML/model.mlmodel",
                          findings[0]["evidence"])
            self.assertEqual(cm.main([pkg]), 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_package_root_missing_and_no_manifest(self):
        root = tempfile.mkdtemp()
        try:
            pkg = _package(root, _model())
            os.remove(os.path.join(pkg, "Data", "com.apple.CoreML",
                                   "model.mlmodel"))
            self.assertEqual(_rules(cm.scan_file(pkg)), ["CML005"])
            empty = os.path.join(root, "Empty.mlpackage")
            os.makedirs(empty)
            self.assertEqual(_rules(cm.scan_file(empty)), ["CML005"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_package_symlink_out_of_data_is_cml004(self):
        if os.name == "nt":
            self.skipTest("directory symbolic links need extra rights on "
                          "Windows")
        root = tempfile.mkdtemp()
        try:
            pkg = _package(root, _model())
            outside = os.path.join(root, "outside")
            os.makedirs(outside)
            link = os.path.join(pkg, "Data", "com.apple.CoreML", "extra")
            try:
                os.symlink(outside, link, target_is_directory=True)
            except (OSError, NotImplementedError, AttributeError):
                self.skipTest("symbolic links are not available here")
            try:
                self.assertIn("CML004", _rules(cm.scan_file(pkg)))
            finally:
                os.unlink(link)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_scan_file_mlmodel(self):
        root = tempfile.mkdtemp()
        try:
            path = os.path.join(root, "m.mlmodel")
            with open(path, "wb") as handle:
                handle.write(_model(_ld(555, _s(10, "FileModel"))))
            self.assertEqual(_rules(cm.scan_file(path)), ["CML001"])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_main_usage_and_missing_file(self):
        self.assertEqual(cm.main([]), 2)
        root = tempfile.mkdtemp()
        try:
            self.assertEqual(cm.main([os.path.join(root, "nope.mlmodel")]), 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
