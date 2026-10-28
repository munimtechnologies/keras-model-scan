"""Tests for torch_module_wrapper_scan.

Self-contained: imports only the standalone scanner module and the standard library,
so it runs under the publish lane's test_first isolation without the rest of the repo.
"""

import base64
import io
import json
import os
import pickle
import tempfile
import unittest
import zipfile

import torch_module_wrapper_scan as tmw


def _config_with_wrapper(payload_b64):
    """A Sequential model whose second layer is a TorchModuleWrapper."""
    return {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {"class_name": "Dense", "config": {"units": 4}},
                {
                    "module": "keras.layers",
                    "class_name": "TorchModuleWrapper",
                    "config": {
                        "name": "torch_module_wrapper",
                        "module": payload_b64,
                        "output_shape": [None, 4],
                    },
                    "registered_name": "TorchModuleWrapper",
                },
            ],
        },
    }


class TorchModuleWrapperScanTest(unittest.TestCase):
    def test_flags_wrapper_class_tmw001(self):
        payload = base64.b64encode(pickle.dumps({"w": 1})).decode("ascii")
        data = json.dumps(_config_with_wrapper(payload)).encode("utf-8")
        findings = tmw.scan_bytes(data)
        rules = {f["rule"] for f in findings}
        self.assertIn("TMW001", rules)
        tmw001 = next(f for f in findings if f["rule"] == "TMW001")
        self.assertEqual(tmw001["severity"], "high")
        self.assertEqual(tmw001["cve"], "CVE-2026-12484")
        self.assertEqual(tmw001["cwe"], "CWE-502")

    def test_flags_pickle_payload_tmw002(self):
        payload = base64.b64encode(pickle.dumps({"w": 1})).decode("ascii")
        data = json.dumps(_config_with_wrapper(payload)).encode("utf-8")
        rules = {f["rule"] for f in tmw.scan_bytes(data)}
        self.assertIn("TMW002", rules)

    def test_flags_zip_payload_tmw002(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("data.pkl", pickle.dumps({"w": 1}))
        payload = base64.b64encode(buf.getvalue()).decode("ascii")
        data = json.dumps(_config_with_wrapper(payload)).encode("utf-8")
        f2 = [f for f in tmw.scan_bytes(data) if f["rule"] == "TMW002"]
        self.assertEqual(len(f2), 1)
        self.assertIn("zip", f2[0]["evidence"])

    def test_clean_model_no_findings(self):
        cfg = {
            "class_name": "Sequential",
            "config": {"layers": [
                {"class_name": "Dense", "config": {"units": 8}},
                {"class_name": "Lambda", "config": {"function": "x"}},
            ]},
        }
        data = json.dumps(cfg).encode("utf-8")
        self.assertEqual(tmw.scan_bytes(data), [])

    def test_layer_module_path_not_mistaken_for_payload(self):
        # A node-level "module": "keras.layers" must not be read as a payload.
        cfg = {"module": "keras.layers", "class_name": "Dense",
               "config": {"units": 4}}
        data = json.dumps(cfg).encode("utf-8")
        self.assertEqual(tmw.scan_bytes(data), [])

    def test_registered_name_match(self):
        cfg = {"class_name": "SomethingElse",
               "registered_name": "my_pkg>TorchModuleWrapper",
               "config": {}}
        data = json.dumps(cfg).encode("utf-8")
        rules = {f["rule"] for f in tmw.scan_bytes(data)}
        self.assertIn("TMW001", rules)

    def test_keras_zip_archive(self):
        payload = base64.b64encode(pickle.dumps({"w": 1})).decode("ascii")
        inner = json.dumps(_config_with_wrapper(payload)).encode("utf-8")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("config.json", inner)
            zf.writestr("metadata.json", b'{"keras_version": "3.15.0"}')
        rules = {f["rule"] for f in tmw.scan_bytes(buf.getvalue())}
        self.assertIn("TMW001", rules)
        self.assertIn("TMW002", rules)

    def test_invalid_input_no_crash(self):
        self.assertEqual(tmw.scan_bytes(b"\x00\x01not json"), [])
        self.assertEqual(tmw.scan_bytes(b""), [])

    def test_exec_opcode_payload_reported(self):
        # Pickling a type emits a STACK_GLOBAL opcode (a code-exec opcode class).
        payload_bytes = pickle.dumps(int)
        payload = base64.b64encode(payload_bytes).decode("ascii")
        data = json.dumps(_config_with_wrapper(payload)).encode("utf-8")
        f2 = [f for f in tmw.scan_bytes(data) if f["rule"] == "TMW002"]
        self.assertEqual(len(f2), 1)
        self.assertIn("opcode", f2[0]["evidence"].lower())

    def test_scan_file_wrapper(self):
        payload = base64.b64encode(pickle.dumps({"w": 1})).decode("ascii")
        data = json.dumps(_config_with_wrapper(payload)).encode("utf-8")
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            os.write(fd, data)
            os.close(fd)
            rules = {f["rule"] for f in tmw.scan_file(path)}
            self.assertIn("TMW001", rules)
        finally:
            os.unlink(path)

    def test_main_exit_code(self):
        payload = base64.b64encode(pickle.dumps({"w": 1})).decode("ascii")
        data = json.dumps(_config_with_wrapper(payload)).encode("utf-8")
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            os.write(fd, data)
            os.close(fd)
            self.assertEqual(tmw.main([path]), 1)
        finally:
            os.unlink(path)

    def test_main_usage_no_args(self):
        self.assertEqual(tmw.main([]), 2)


if __name__ == "__main__":
    unittest.main()
