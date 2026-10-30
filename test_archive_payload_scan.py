"""Self-contained tests for archive_payload_scan.py (stdlib only).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

Fixtures are tiny in-memory zip/tar archives whose members start with the
header bytes of each format (ELF, PE, Mach-O, ...). They are headers only, not
working programs, and nothing is ever extracted or run.

Run: python -m unittest -v test_archive_payload_scan
"""

import contextlib
import gzip
import io
import os
import tarfile
import tempfile
import unittest
import zipfile

import archive_payload_scan as scan


# --- header-only fixtures ----------------------------------------------------

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 28
FAT = b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 24
JAVA = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 24
HDF5 = b"\x89HDF\r\n\x1a\n" + b"\x00" * 56
PICKLE = b"\x80\x02]q\x00."


def pe():
    head = bytearray(b"MZ" + b"\x00" * 0x7E)
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    return bytes(head) + b"PE\x00\x00" + b"\x00" * 20


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_tar(members, mode="w"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def rules(findings):
    return [f["rule"] for f in findings]


class NativeCode(unittest.TestCase):
    def test_elf_disguised_as_weights(self):
        findings = scan.scan_bytes(make_zip({"model.bin": ELF}), "m.zip")
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("m.zip!model.bin: ELF", findings[0]["evidence"])
        self.assertIn("does not say so", findings[0]["evidence"])

    def test_shared_library_name_is_not_called_disguised(self):
        for name in ("libop.so", "libop.so.1", "op.dll", "op.dylib", "x.pyd"):
            findings = scan.scan_bytes(make_zip({name: ELF}))
            self.assertEqual(rules(findings), ["ARC001"], name)
            self.assertNotIn("does not say so", findings[0]["evidence"])

    def test_pe_in_tar(self):
        findings = scan.scan_bytes(make_tar({"weights/extra.dat": pe()}))
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertIn("extra.dat: PE", findings[0]["evidence"])

    def test_mz_without_pe_signature_is_clean(self):
        data = make_zip({"archive/data/0": b"MZ" + b"\x00" * 100})
        self.assertEqual(scan.scan_bytes(data), [])

    def test_macho_in_gzip_tar(self):
        findings = scan.scan_bytes(make_tar({"a/b": MACHO}, mode="w:gz"))
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertIn("Mach-O", findings[0]["evidence"])

    def test_fat_macho_is_native_java_class_is_code(self):
        findings = scan.scan_bytes(make_zip({"blob": FAT}))
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertIn("Mach-O universal", findings[0]["evidence"])
        findings = scan.scan_bytes(make_zip({"blob": JAVA}))
        self.assertEqual(rules(findings), ["ARC002"])
        self.assertIn("Java class", findings[0]["evidence"])

    def test_whole_file_is_a_program(self):
        findings = scan.scan_bytes(ELF, "model.pt")
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertIn("model.pt: ELF", findings[0]["evidence"])

    def test_gzip_stream_of_executable(self):
        findings = scan.scan_bytes(gzip.compress(ELF), "model.gz")
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertIn("model.gz!<decompressed>", findings[0]["evidence"])


class Scripts(unittest.TestCase):
    def test_shebang_without_extension(self):
        findings = scan.scan_bytes(make_zip({"run": b"#!/bin/sh\necho hi\n"}))
        self.assertEqual(rules(findings), ["ARC002"])
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("shebang script '#!/bin/sh'", findings[0]["evidence"])

    def test_hash_bang_in_tensor_bytes_is_not_a_script(self):
        data = make_zip({"archive/data/0": b"#!\x00\x01\x02\x03"})
        self.assertEqual(scan.scan_bytes(data), [])

    def test_python_file_in_keras_zip(self):
        data = make_zip({"config.json": b"{}", "helper.py": b"x = 1\n"})
        findings = scan.scan_bytes(data)
        self.assertEqual(rules(findings), ["ARC002"])
        self.assertIn("helper.py: .py file", findings[0]["evidence"])

    def test_script_extensions(self):
        for name in ("setup.sh", "a.bat", "b.ps1", "c.pyc", "d.jar"):
            findings = scan.scan_bytes(make_zip({name: b"plain text"}))
            self.assertEqual(rules(findings), ["ARC002"], name)

    def test_native_name_without_header(self):
        findings = scan.scan_bytes(make_zip({"libfoo.so": b"not really"}))
        self.assertEqual(rules(findings), ["ARC002"])
        self.assertIn("named like a native", findings[0]["evidence"])

    def test_torchscript_code_is_exempt(self):
        data = make_zip({
            "archive/data.pkl": PICKLE,
            "archive/constants.pkl": PICKLE,
            "archive/version": b"3\n",
            "archive/code/__torch__/m.py": b"def forward(self):\n  pass\n",
            "archive/code/__torch__/m.py.debug_pkl": PICKLE,
        })
        self.assertEqual(scan.scan_bytes(data), [])

    def test_python_outside_torchscript_code_is_flagged(self):
        data = make_zip({
            "archive/constants.pkl": PICKLE,
            "archive/code/__torch__/m.py": b"pass\n",
            "archive/extra/run.py": b"pass\n",
        })
        findings = scan.scan_bytes(data)
        self.assertEqual(rules(findings), ["ARC002"])
        self.assertIn("extra/run.py", findings[0]["evidence"])

    def test_py_under_code_without_torchscript_is_flagged(self):
        findings = scan.scan_bytes(make_zip({"code/m.py": b"pass\n"}))
        self.assertEqual(rules(findings), ["ARC002"])


class Nesting(unittest.TestCase):
    def test_zip_inside_nemo_style_tar(self):
        inner = make_zip({"payload.bin": ELF})
        outer = make_tar({"model_config.yaml": b"a: 1\n",
                          "model_weights.ckpt": inner})
        findings = scan.scan_bytes(outer, "m.nemo")
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertIn("m.nemo!model_weights.ckpt!payload.bin",
                      findings[0]["evidence"])

    def test_tar_inside_zip(self):
        inner = make_tar({"x": pe()}, mode="w:gz")
        findings = scan.scan_bytes(make_zip({"bundle.tgz": inner}))
        self.assertEqual(rules(findings), ["ARC001"])

    def test_depth_at_limit_is_opened(self):
        data = make_zip({"x": ELF})
        for i in range(scan.MAX_DEPTH):
            data = make_zip({"n%d.zip" % i: data})
        self.assertEqual(rules(scan.scan_bytes(data)), ["ARC001"])

    def test_depth_over_limit_is_reported(self):
        data = make_zip({"x": ELF})
        for i in range(scan.MAX_DEPTH + 1):
            data = make_zip({"n%d.zip" % i: data})
        findings = scan.scan_bytes(data)
        self.assertEqual(rules(findings), ["ARC003"])
        self.assertIn("deeper than", findings[0]["evidence"])

    def test_oversized_nested_archive_is_reported(self):
        saved = scan.MAX_NESTED_BYTES
        scan.MAX_NESTED_BYTES = 10
        try:
            findings = scan.scan_bytes(make_zip({"in.zip": make_zip({"x": ELF})}))
        finally:
            scan.MAX_NESTED_BYTES = saved
        self.assertEqual(rules(findings), ["ARC003"])
        self.assertIn("not opened", findings[0]["evidence"])


class Uninspectable(unittest.TestCase):
    def test_7z_member(self):
        data = make_zip({"model.7z": b"7z\xbc\xaf\x27\x1c" + b"\x00" * 26})
        findings = scan.scan_bytes(data)
        self.assertEqual(rules(findings), ["ARC003"])
        self.assertIn("7z or RAR", findings[0]["evidence"])

    def test_encrypted_member(self):
        data = bytearray(make_zip({"model.bin": ELF}))
        data[6] |= 0x1                       # local header flag bits
        central = data.find(b"PK\x01\x02")
        data[central + 8] |= 0x1             # central directory flag bits
        findings = scan.scan_bytes(bytes(data))
        self.assertEqual(rules(findings), ["ARC003"])
        self.assertIn("encrypted", findings[0]["evidence"])

    def test_corrupt_zip(self):
        findings = scan.scan_bytes(b"PK\x03\x04" + b"\x00" * 40)
        self.assertEqual(rules(findings), ["ARC003"])
        self.assertIn("zip could not be opened", findings[0]["evidence"])


class Clean(unittest.TestCase):
    def test_keras_like_zip(self):
        data = make_zip({"config.json": b'{"a": 1}', "metadata.json": b"{}",
                         "model.weights.h5": HDF5})
        self.assertEqual(scan.scan_bytes(data), [])

    def test_torch_like_zip(self):
        data = make_zip({"archive/data.pkl": PICKLE, "archive/byteorder":
                         b"little", "archive/data/0": b"\x00" * 64,
                         "archive/version": b"3\n"})
        self.assertEqual(scan.scan_bytes(data), [])

    def test_plain_bytes_and_empty(self):
        self.assertEqual(scan.scan_bytes(b"hello world"), [])
        self.assertEqual(scan.scan_bytes(b""), [])

    def test_tar_symlink_is_skipped(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/bin/sh"
            tf.addfile(info)
        self.assertEqual(scan.scan_bytes(buf.getvalue()), [])


class Shape(unittest.TestCase):
    def test_finding_shape_and_ascii(self):
        findings = scan.scan_bytes(make_zip({"modèle.bin": ELF}))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(set(f), {"rule", "severity", "cve", "cwe",
                                  "message", "evidence"})
        self.assertEqual(f["cve"], "")
        self.assertEqual(f["cwe"], "CWE-829")
        self.assertTrue(f["message"].isascii())
        self.assertTrue(f["evidence"].isascii())
        self.assertIn("mod\\xe8le.bin", f["evidence"])

    def test_version(self):
        self.assertEqual(scan.__version__, "0.1.0")


class Cli(unittest.TestCase):
    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.zip")
            good = os.path.join(tmp, "good.zip")
            medium = os.path.join(tmp, "medium.zip")
            with open(bad, "wb") as fh:
                fh.write(make_zip({"model.bin": ELF}))
            with open(good, "wb") as fh:
                fh.write(make_zip({"config.json": b"{}"}))
            with open(medium, "wb") as fh:
                fh.write(make_zip({"helper.py": b"pass\n"}))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(scan.main([bad]), 1)
                self.assertEqual(scan.main([good]), 0)
                self.assertEqual(scan.main([medium]), 0)
                self.assertEqual(scan.main([]), 2)
                self.assertEqual(
                    scan.main([os.path.join(tmp, "missing.zip")]), 2)
            self.assertIn("HIGH ARC001 [CWE-829]", out.getvalue())
            self.assertIn("MEDIUM ARC002", out.getvalue())

    def test_scan_file_tar_gz_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bundle.tar.gz")
            with open(path, "wb") as fh:
                fh.write(make_tar({"ok.txt": b"hi", "tool": ELF}, mode="w:gz"))
            findings = scan.scan_file(path)
        self.assertEqual(rules(findings), ["ARC001"])
        self.assertIn("bundle.tar.gz!tool: ELF", findings[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
