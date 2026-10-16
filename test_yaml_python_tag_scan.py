# Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""Tests for yaml_python_tag_scan. Every fixture is inert text that is only read,
never parsed by a YAML library or executed."""

import contextlib
import io
import json
import os
import tempfile
import unittest

import yaml_python_tag_scan as ypt


def rules(findings):
    return [(f.rule, f.severity) for f in findings]


class TestPyYAMLTags(unittest.TestCase):

    def test_apply_with_dangerous_target_is_critical(self):
        text = 'payload: !!python/object/apply:os.system ["id"]\n'
        self.assertEqual(rules(ypt.scan_text(text, "meta.yaml")), [("YPT001", "CRITICAL")])

    def test_object_new_with_subprocess_is_critical(self):
        text = "x: !!python/object/new:subprocess.Popen [[\"id\"]]\n"
        found = ypt.scan_text(text, "meta.yaml")
        self.assertEqual(rules(found), [("YPT001", "CRITICAL")])
        self.assertEqual(found[0].target, "subprocess.Popen")

    def test_object_with_ordinary_class_is_high(self):
        text = "opt: !!python/object:collections.OrderedDict {}\n"
        self.assertEqual(rules(ypt.scan_text(text, "meta.yaml")), [("YPT001", "HIGH")])

    def test_name_reference_is_high_not_critical(self):
        text = "fn: !!python/name:os.system\n"
        self.assertEqual(rules(ypt.scan_text(text, "meta.yaml")), [("YPT001", "HIGH")])

    def test_bare_builtin_is_dangerous(self):
        text = "x: !!python/object/apply:eval [\"1\"]\n"
        self.assertEqual(rules(ypt.scan_text(text, "meta.yaml")), [("YPT001", "CRITICAL")])

    def test_verbatim_tag_form(self):
        text = "x: !<tag:yaml.org,2002:python/object/apply:os.system> [\"id\"]\n"
        found = ypt.scan_text(text, "meta.yaml")
        self.assertEqual(rules(found), [("YPT001", "CRITICAL")])
        self.assertEqual(found[0].target, "os.system")

    def test_primitive_python_tags_are_ignored(self):
        text = "shape: !!python/tuple [1, 2]\nraw: !!python/bytes AAAA\n"
        self.assertEqual(ypt.scan_text(text, "meta.yaml"), [])

    def test_sequence_item(self):
        text = "steps:\n  - !!python/object/apply:os.system [\"id\"]\n"
        self.assertEqual(rules(ypt.scan_text(text, "meta.yaml")), [("YPT001", "CRITICAL")])


class TestHyperPyYAMLTags(unittest.TestCase):

    def test_benign_speechbrain_new_is_low(self):
        text = "model: !new:speechbrain.nnet.linear.Linear\n  input_size: 4\n"
        self.assertEqual(rules(ypt.scan_text(text, "hyperparams.yaml")), [("YPT002", "LOW")])

    def test_apply_torch_seed_is_low(self):
        text = "__set_seed: !apply:torch.manual_seed [1234]\n"
        self.assertEqual(rules(ypt.scan_text(text, "hyperparams.yaml")), [("YPT002", "LOW")])

    def test_apply_os_system_is_critical(self):
        text = "__boot: !apply:os.system [\"id\"]\n"
        self.assertEqual(rules(ypt.scan_text(text, "hyperparams.yaml")), [("YPT002", "CRITICAL")])

    def test_name_dangerous_is_high(self):
        text = "hook: !name:subprocess.run\n"
        self.assertEqual(rules(ypt.scan_text(text, "hyperparams.yaml")), [("YPT002", "HIGH")])

    def test_unknown_namespace_is_medium(self):
        text = "enc: !new:somepkg.models.Encoder\n"
        self.assertEqual(rules(ypt.scan_text(text, "hyperparams.yaml")), [("YPT002", "MEDIUM")])

    def test_module_tag(self):
        text = "m: !module:importlib\n"
        self.assertEqual(rules(ypt.scan_text(text, "hyperparams.yaml")), [("YPT002", "HIGH")])

    def test_ref_tag_is_ignored(self):
        text = "lr: 0.1\nopt_lr: !ref <lr>\n"
        self.assertEqual(ypt.scan_text(text, "hyperparams.yaml"), [])


class TestCkptAndDirectives(unittest.TestCase):

    def test_ckpt_yaml_any_code_tag_is_ypt004(self):
        text = "end-of-epoch: true\nunixtime: 1760000000.0\nx: !!python/object:collections.OrderedDict {}\n"
        self.assertEqual(rules(ypt.scan_text(text, "/ckpts/CKPT+2026/CKPT.yaml")),
                         [("YPT004", "CRITICAL")])

    def test_ckpt_yaml_hyper_tag_is_ypt004(self):
        text = "x: !new:speechbrain.nnet.linear.Linear\n"
        self.assertEqual(rules(ypt.scan_text(text, "CKPT.yaml")), [("YPT004", "CRITICAL")])

    def test_clean_ckpt_yaml(self):
        text = "# yamllint disable\nend-of-epoch: true\nunixtime: 1760000000.0\nvalid_loss: 0.42\n"
        self.assertEqual(ypt.scan_text(text, "CKPT.yaml"), [])

    def test_tag_directive_alias_is_reported(self):
        text = "%TAG !p! tag:yaml.org,2002:python/\n---\nx: !p!object/apply:os.system [\"id\"]\n"
        self.assertEqual(rules(ypt.scan_text(text, "meta.yaml")), [("YPT003", "HIGH")])


class TestFalsePositiveGuards(unittest.TestCase):

    def test_tag_in_quoted_string_is_ignored(self):
        text = "note: \"never use !!python/object/apply:os.system here\"\n"
        self.assertEqual(ypt.scan_text(text, "meta.yaml"), [])

    def test_tag_in_single_quoted_string_is_ignored(self):
        text = "note: '!apply:os.system is dangerous'\n"
        self.assertEqual(ypt.scan_text(text, "hyperparams.yaml"), [])

    def test_tag_in_comment_is_ignored(self):
        text = "# !!python/object/apply:os.system\nlr: 0.1  # !apply:os.system\n"
        self.assertEqual(ypt.scan_text(text, "meta.yaml"), [])

    def test_mid_word_bang_is_ignored(self):
        text = "title: wow!apply:os.system\n"
        self.assertEqual(ypt.scan_text(text, "meta.yaml"), [])

    def test_plain_config(self):
        text = "sample_rate: 16000\nmodel:\n  layers: 4\n"
        self.assertEqual(ypt.scan_text(text, "hyperparams.yaml"), [])


class TestCli(unittest.TestCase):

    def _write(self, folder, name, text):
        path = os.path.join(folder, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_directory_scan_and_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "hyperparams.yaml", "m: !new:speechbrain.nnet.linear.Linear\n")
            sub = os.path.join(tmp, "save", "CKPT+1")
            os.makedirs(sub)
            self._write(sub, "CKPT.yaml", "x: !!python/object/apply:os.system [\"id\"]\n")
            self._write(tmp, "notes.txt", "!!python/object/apply:os.system\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = ypt.main([tmp, "--json", "--fail-on", "CRITICAL"])
            self.assertEqual(code, 1)
            report = json.loads(buf.getvalue())
            self.assertEqual(len(report["scanned_files"]), 2)
            self.assertEqual(sorted(f["rule"] for f in report["findings"]), ["YPT002", "YPT004"])

    def test_clean_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "config.yaml", "lr: 0.1\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = ypt.main([tmp, "--fail-on", "LOW"])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
