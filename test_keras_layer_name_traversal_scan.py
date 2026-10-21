"""Tests for keras_layer_name_traversal_scan (CVE-2026-12479).

No keras or network needed: configs are built as plain dicts and .keras archives
as in-memory ZIPs, matching the real .keras layout (config.json inside a ZIP).
The traversal shapes mirror the published CVE-2026-12479 mechanism: a Keras layer
name such as '..' that DiskIOStore joins onto its temporary working directory.

Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import os
import tempfile
import unittest
import zipfile

import keras_layer_name_traversal_scan as s


def layer(class_name="Dense", name="dense", extra=None):
    cfg = {"name": name}
    if extra:
        cfg.update(extra)
    return {"module": "keras.layers", "class_name": class_name,
            "config": cfg, "registered_name": None}


def sequential(layers, name="sequential"):
    return {"module": "keras", "class_name": "Sequential",
            "config": {"name": name, "layers": layers},
            "registered_name": None}


def make_keras(config: dict, extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.14.0"}))
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


class DetectsTraversal(unittest.TestCase):
    def test_parent_dir_name_is_high(self):
        fs = s.scan_config(sequential([layer(name="..")]))
        self.assertEqual([f.rule for f in fs], ["DLT001"])
        self.assertEqual(fs[0].severity, "high")
        self.assertEqual(fs[0].cve, "CVE-2026-12479")
        self.assertIn("Dense name '..'", fs[0].location)

    def test_dotdot_as_path_component_is_high(self):
        fs = s.scan_config(sequential([layer(name="conv/../../etc")]))
        self.assertEqual([f.rule for f in fs], ["DLT001"])
        self.assertEqual(fs[0].severity, "high")

    def test_absolute_posix_is_high(self):
        fs = s.scan_config(sequential([layer(name="/etc/cron.d/x")]))
        self.assertEqual([f.rule for f in fs], ["DLT002"])
        self.assertEqual(fs[0].severity, "high")
        self.assertEqual(fs[0].cve, "CVE-2026-12479")

    def test_windows_drive_is_high(self):
        fs = s.scan_config(sequential([layer(name="C:\\Windows\\Temp\\x")]))
        self.assertEqual([f.rule for f in fs], ["DLT002"])

    def test_leading_backslash_is_absolute(self):
        fs = s.scan_config(sequential([layer(name="\\evil")]))
        self.assertEqual([f.rule for f in fs], ["DLT002"])


class SeparatorAndControl(unittest.TestCase):
    def test_forward_slash_is_medium(self):
        fs = s.scan_config(sequential([layer(name="a/b")]))
        self.assertEqual([f.rule for f in fs], ["DLT003"])
        self.assertEqual(fs[0].severity, "medium")
        self.assertEqual(fs[0].cve, "CWE-22")

    def test_backslash_is_medium(self):
        fs = s.scan_config(sequential([layer(name="a\\b")]))
        self.assertEqual([f.rule for f in fs], ["DLT003"])
        self.assertEqual(fs[0].severity, "medium")

    def test_nul_byte_is_medium(self):
        fs = s.scan_config(sequential([layer(name="a\x00b")]))
        self.assertEqual([f.rule for f in fs], ["DLT004"])
        self.assertEqual(fs[0].severity, "medium")
        self.assertEqual(fs[0].cve, "CWE-22")

    def test_newline_is_control(self):
        fs = s.scan_config(sequential([layer(name="a\nb")]))
        self.assertEqual([f.rule for f in fs], ["DLT004"])


class NotFlagged(unittest.TestCase):
    def test_benign_names_clean(self):
        fs = s.scan_config(sequential([layer(name="dense_1"),
                                       layer("Conv2D", "conv2d")]))
        self.assertEqual(fs, [])

    def test_single_dot_is_clean(self):
        # '.' resolves to the current directory, no escape.
        fs = s.scan_config(sequential([layer(name=".")]))
        self.assertEqual(fs, [])

    def test_embedded_dots_not_a_component_clean(self):
        # '..' as a substring (not a path component) does not escape.
        fs = s.scan_config(sequential([layer(name="block..v2")]))
        self.assertEqual(fs, [])

    def test_leading_dotdot_name_not_a_component_clean(self):
        # "..foo" is a literal directory name, not a parent reference.
        fs = s.scan_config(sequential([layer(name="..foo")]))
        self.assertEqual(fs, [])

    def test_empty_name_clean(self):
        fs = s.scan_config(sequential([layer(name="")]))
        self.assertEqual(fs, [])


class Dedup(unittest.TestCase):
    def test_duplicate_dangerous_name_reported_once(self):
        fs = s.scan_config(sequential([layer(name=".."),
                                       layer("Conv2D", "..")]))
        self.assertEqual([f.rule for f in fs], ["DLT001"])


class NestedAndLabels(unittest.TestCase):
    def test_deeply_nested_name_found(self):
        config = {"class_name": "Functional", "config": {"name": "m",
                  "layers": [
                      layer(name="a"),
                      {"class_name": "Model", "config": {"name": "inner",
                       "layers": [layer(name="..")]}},
                  ]}}
        fs = s.scan_config(config)
        self.assertEqual([f.rule for f in fs], ["DLT001"])
        self.assertIn("..", fs[0].location)

    def test_node_level_name_checked(self):
        # Functional nodes carry a top-level "name" too; it must be checked.
        node = {"class_name": "Dense", "name": "..",
                "config": {"name": "safe"}}
        fs = s.scan_config(node)
        self.assertEqual([f.rule for f in fs], ["DLT001"])
        self.assertIn("Dense name '..'", fs[0].location)

    def test_member_prefix_in_location(self):
        fs = s.scan_config(layer(name=".."), member="config.json")
        self.assertTrue(fs[0].location.startswith("config.json:"))


class Archives(unittest.TestCase):
    def test_keras_zip_flags_traversal(self):
        data = make_keras(sequential([layer(name="..")]))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.keras")
            with open(p, "wb") as fh:
                fh.write(data)
            fs = s.scan_file(p)
        self.assertEqual([f.rule for f in fs], ["DLT001"])
        self.assertTrue(fs[0].location.startswith("config.json"))

    def test_bare_config_json_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "config.json")
            with open(p, "w") as fh:
                json.dump(layer(name=".."), fh)
            fs = s.scan_file(p)
        self.assertEqual([f.rule for f in fs], ["DLT001"])

    def test_benign_keras_is_ok(self):
        data = make_keras(sequential([layer(name="d1"), layer("Conv2D", "c1")]))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.keras")
            with open(p, "wb") as fh:
                fh.write(data)
            fs = s.scan_file(p)
        self.assertEqual(fs, [])

    def test_large_member_skipped(self):
        old = s.MAX_MEMBER_BYTES
        s.MAX_MEMBER_BYTES = 1
        try:
            data = make_keras(sequential([layer(name="..")]))
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "model.keras")
                with open(p, "wb") as fh:
                    fh.write(data)
                fs = s.scan_file(p)
        finally:
            s.MAX_MEMBER_BYTES = old
        self.assertTrue(all(f.rule == "DLT005" for f in fs))
        self.assertTrue(all(f.severity == "info" for f in fs))


class BadInput(unittest.TestCase):
    def test_invalid_json_bytes(self):
        fs = s.scan_bytes(b"{ not json ]")
        self.assertEqual(fs[0].rule, "DLT000")
        self.assertEqual(fs[0].severity, "info")

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "empty.json")
            open(p, "wb").close()
            fs = s.scan_file(p)
        self.assertEqual(fs[0].rule, "DLT000")

    def test_non_dict_json_is_clean(self):
        self.assertEqual(s.scan_bytes(b"[1, 2, 3]"), [])

    def test_string_json_is_clean(self):
        self.assertEqual(s.scan_bytes(b'"hello"'), [])


class Cli(unittest.TestCase):
    def _write(self, d, name, data):
        p = os.path.join(d, name)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(p, mode) as fh:
            fh.write(data)
        return p

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            bad = self._write(d, "bad.keras",
                              make_keras(sequential([layer(name="..")])))
            good = self._write(d, "good.keras",
                               make_keras(sequential([layer(name="ok")])))
            self.assertEqual(s.main([bad]), 1)
            self.assertEqual(s.main([good]), 0)
            self.assertEqual(s.main(["nope.keras"]), 2)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "config.json", json.dumps(layer(name="..")))
            self.assertEqual(s.main(["--json", p]), 1)


if __name__ == "__main__":
    unittest.main()
