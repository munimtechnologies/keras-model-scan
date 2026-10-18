"""Tests for keras_lookup_vocab_scan - the Keras lookup-layer vocabulary
file/URL sink detector (CVE-2025-12058). Pure stdlib; no keras, no network,
no model execution. Made with AI by MV2 of Munim, Inc. Apache-2.0."""
import contextlib
import io
import json
import os
import tempfile
import unittest
import zipfile

import keras_lookup_vocab_scan as kv


def _layer(class_name, vocab, module="keras.layers", name="lookup",
           registered_name=None):
    cfg = {"name": name}
    if vocab is not _OMIT:
        cfg["vocabulary"] = vocab
    node = {"module": module, "class_name": class_name, "config": cfg}
    if registered_name is not None:
        node["registered_name"] = registered_name
    return node


_OMIT = object()


def _model(layers):
    return {"module": "keras", "class_name": "Sequential",
            "config": {"name": "model", "layers": layers}}


def _rules(findings):
    return [f.rule for f in findings]


class ScanConfigTest(unittest.TestCase):
    def test_string_lookup_local_path_is_klv001(self):
        text = json.dumps(_model([_layer("StringLookup", "/etc/passwd")]))
        findings = kv.scan_config(text)
        self.assertEqual(_rules(findings), ["KLV001"])
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].cve, "CVE-2025-12058")
        self.assertTrue(findings[0].location.endswith("/config/vocabulary"))

    def test_http_url_is_klv002_ssrf(self):
        url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        text = json.dumps(_model([_layer("StringLookup", url)]))
        findings = kv.scan_config(text)
        self.assertEqual(_rules(findings), ["KLV002"])
        self.assertEqual(findings[0].severity, "high")

    def test_https_url_is_klv002(self):
        text = json.dumps(_model([_layer("StringLookup", "https://evil.test/x")]))
        self.assertEqual(_rules(kv.scan_config(text)), ["KLV002"])

    def test_file_url_is_klv002(self):
        text = json.dumps(_model([_layer("StringLookup", "file:///home/u/.netrc")]))
        self.assertEqual(_rules(kv.scan_config(text)), ["KLV002"])

    def test_gcs_scheme_is_klv002(self):
        text = json.dumps(_model([_layer("StringLookup", "gs://bucket/key")]))
        self.assertEqual(_rules(kv.scan_config(text)), ["KLV002"])

    def test_list_vocabulary_is_safe(self):
        text = json.dumps(_model([_layer("StringLookup", ["a", "b", "c"])]))
        self.assertEqual(kv.scan_config(text), [])

    def test_null_vocabulary_is_safe(self):
        text = json.dumps(_model([_layer("StringLookup", None)]))
        self.assertEqual(kv.scan_config(text), [])

    def test_missing_vocabulary_is_safe(self):
        text = json.dumps(_model([_layer("StringLookup", _OMIT)]))
        self.assertEqual(kv.scan_config(text), [])

    def test_empty_string_vocabulary_is_safe(self):
        text = json.dumps(_model([_layer("StringLookup", "")]))
        self.assertEqual(kv.scan_config(text), [])

    def test_whitespace_vocabulary_is_safe(self):
        text = json.dumps(_model([_layer("StringLookup", "   ")]))
        self.assertEqual(kv.scan_config(text), [])

    def test_integer_lookup_string_path(self):
        text = json.dumps(_model([_layer("IntegerLookup", "/tmp/v.txt")]))
        self.assertEqual(_rules(kv.scan_config(text)), ["KLV001"])

    def test_index_lookup_string_path(self):
        text = json.dumps(_model([_layer("IndexLookup", "/tmp/v.txt")]))
        self.assertEqual(_rules(kv.scan_config(text)), ["KLV001"])

    def test_registered_name_prefix_is_matched(self):
        node = _layer("SomethingElse", "/x",
                      registered_name="MyPkg>StringLookup")
        self.assertEqual(_rules(kv.scan_config(json.dumps(_model([node])))),
                         ["KLV001"])

    def test_dotted_class_name_is_matched(self):
        node = _layer(
            "keras.src.layers.preprocessing.string_lookup.StringLookup", "/x")
        self.assertEqual(_rules(kv.scan_config(json.dumps(_model([node])))),
                         ["KLV001"])

    def test_non_lookup_layer_with_vocabulary_key_is_ignored(self):
        node = {"module": "keras.layers", "class_name": "Dense",
                "config": {"name": "d", "vocabulary": "/etc/passwd"}}
        self.assertEqual(kv.scan_config(json.dumps(_model([node]))), [])

    def test_nested_model_location(self):
        inner = _model([_layer("StringLookup", "/secret")])
        outer = {"module": "keras", "class_name": "Functional",
                 "config": {"name": "outer", "layers": [inner]}}
        findings = kv.scan_config(json.dumps(outer))
        self.assertEqual(_rules(findings), ["KLV001"])
        self.assertIn("layers[0]", findings[0].location)

    def test_two_layers_two_findings(self):
        text = json.dumps(_model([
            _layer("StringLookup", "/a"),
            _layer("IntegerLookup", "http://b.test/c", name="il"),
        ]))
        findings = kv.scan_config(text)
        # Sorted by severity: KLV002 (high) before KLV001 (medium) only in
        # scan_file; scan_config preserves traversal order here.
        self.assertEqual(sorted(_rules(findings)), ["KLV001", "KLV002"])

    def test_invalid_json_is_klv000(self):
        findings = kv.scan_config("{ not json")
        self.assertEqual(_rules(findings), ["KLV000"])
        self.assertEqual(findings[0].severity, "info")


class ScanFileTest(unittest.TestCase):
    def _write_keras(self, config_obj):
        fd, path = tempfile.mkstemp(suffix=".keras")
        os.close(fd)
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("config.json", json.dumps(config_obj))
            zf.writestr("metadata.json", json.dumps({"keras_version": "3.11.0"}))
        self.addCleanup(os.remove, path)
        return path

    def test_keras_archive_flags_url(self):
        path = self._write_keras(
            _model([_layer("StringLookup", "https://evil.test/x")]))
        findings = kv.scan_file(path)
        self.assertEqual(_rules(findings), ["KLV002"])
        self.assertIn("!config.json", findings[0].location)

    def test_archive_sorts_high_before_medium(self):
        path = self._write_keras(_model([
            _layer("StringLookup", "/a"),
            _layer("StringLookup", "http://b.test/", name="b"),
        ]))
        self.assertEqual(_rules(kv.scan_file(path)), ["KLV002", "KLV001"])

    def test_archive_without_config_is_empty(self):
        fd, path = tempfile.mkstemp(suffix=".keras")
        os.close(fd)
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("metadata.json", "{}")
        self.addCleanup(os.remove, path)
        self.assertEqual(kv.scan_file(path), [])

    def test_oversized_config_is_klv003(self):
        path = self._write_keras(_model([_layer("StringLookup", "/a")]))
        findings = kv.scan_file(path, max_config_bytes=10)
        self.assertEqual(_rules(findings), ["KLV003"])
        self.assertEqual(findings[0].severity, "info")

    def test_raw_json_file(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(_model([_layer("StringLookup", "/etc/shadow")]), fh)
        self.addCleanup(os.remove, path)
        self.assertEqual(_rules(kv.scan_file(path)), ["KLV001"])

    def test_clean_model_is_empty(self):
        path = self._write_keras(_model([
            _layer("StringLookup", ["token0", "token1"]),
            {"module": "keras.layers", "class_name": "Dense",
             "config": {"name": "d", "units": 10}},
        ]))
        self.assertEqual(kv.scan_file(path), [])


class MainTest(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = kv.main(argv)
        return code, buf.getvalue()

    def _write(self, obj, suffix=".json"):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w") as fh:
            json.dump(obj, fh)
        self.addCleanup(os.remove, path)
        return path

    def test_exit_1_on_finding(self):
        path = self._write(_model([_layer("StringLookup", "/x")]))
        code, _ = self._run([path])
        self.assertEqual(code, 1)

    def test_exit_0_on_clean(self):
        path = self._write(_model([_layer("StringLookup", ["a"])]))
        code, _ = self._run([path])
        self.assertEqual(code, 0)

    def test_info_only_is_exit_0(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write("{ not json")
        self.addCleanup(os.remove, path)
        code, _ = self._run([path])
        self.assertEqual(code, 0)

    def test_json_output_parses(self):
        path = self._write(_model([_layer("StringLookup", "/x")]))
        code, out = self._run(["--json", path])
        self.assertEqual(code, 1)
        parsed = json.loads(out)
        self.assertEqual(parsed[0]["findings"][0]["rule"], "KLV001")

    def test_missing_file_returns_2(self):
        code, _ = self._run(["definitely-not-a-real-file-9271.keras"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
