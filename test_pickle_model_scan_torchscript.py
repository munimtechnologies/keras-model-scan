# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""pickle_model_scan 0.7.0: a TorchScript archive gets one PKL040 MEDIUM
instead of one PKL003 per __torch__ class; nothing else changes.

The archives here are tiny in-memory zips laid out like torch.jit.save output
(<prefix>/data.pkl next to <prefix>/code/), with short protocol-2 pickles
that only name classes (GLOBAL opcodes); nothing is unpickled.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import unittest
import zipfile

import pickle_model_scan as pms

# GLOBAL __torch__ Net, GLOBAL __torch__.torch.nn.modules.linear Linear,
# TUPLE2, STOP
TS_DATA = (b"\x80\x02c__torch__\nNet\n"
           b"c__torch__.torch.nn.modules.linear\nLinear\n\x86.")
# the same plus GLOBAL mylib.models Thing, TUPLE3
TS_DATA_OTHER = (b"\x80\x02c__torch__\nNet\n"
                 b"c__torch__.torch.nn.modules.linear\nLinear\n"
                 b"cmylib.models\nThing\n\x87.")
EMPTY = b"\x80\x02)."
CODE = b"def forward(self, x):\n    return x\n"


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def rules(findings, rule):
    return [f for f in findings if f.rule == rule]


def torch_pkl003(findings):
    return [f for f in rules(findings, "PKL003") if "__torch__." in f.detail]


class TorchScriptArchiveTest(unittest.TestCase):
    def test_version(self):
        ver = tuple(int(x) for x in pms.__version__.split("."))
        self.assertGreaterEqual(ver, (0, 7, 0))

    def test_jit_save_layout_gets_one_pkl040(self):
        data = make_zip({"model/data.pkl": TS_DATA,
                         "model/constants.pkl": EMPTY,
                         "model/code/__torch__.py": CODE,
                         "model/version": b"3\n"})
        found = pms.scan_zip(data, "m.pt")
        ts = rules(found, "PKL040")
        self.assertEqual(len(ts), 1)
        self.assertEqual(ts[0].severity, "MEDIUM")
        self.assertIn("SECURITY.md", ts[0].detail)
        self.assertIn("__torch__.Net", ts[0].detail)
        self.assertEqual(ts[0].location, "m.pt!model/data.pkl")
        self.assertEqual(torch_pkl003(found), [])

    def test_lite_layout_with_bytecode_pkl(self):
        data = make_zip({"model/data.pkl": TS_DATA,
                         "model/bytecode.pkl": EMPTY})
        found = pms.scan_zip(data, "m.ptl")
        self.assertEqual(len(rules(found, "PKL040")), 1)
        self.assertEqual(torch_pkl003(found), [])

    def test_top_level_prefix(self):
        data = make_zip({"data.pkl": TS_DATA, "code/__torch__.py": CODE})
        found = pms.scan_zip(data, "m.pt")
        self.assertEqual(len(rules(found, "PKL040")), 1)
        self.assertEqual(torch_pkl003(found), [])

    def test_without_code_folder_nothing_changes(self):
        data = make_zip({"model/data.pkl": TS_DATA})
        found = pms.scan_zip(data, "m.pt")
        self.assertEqual(rules(found, "PKL040"), [])
        self.assertGreaterEqual(len(torch_pkl003(found)), 1)

    def test_other_imports_keep_their_rule(self):
        data = make_zip({"model/data.pkl": TS_DATA_OTHER,
                         "model/code/__torch__.py": CODE})
        found = pms.scan_zip(data, "m.pt")
        self.assertEqual(len(rules(found, "PKL040")), 1)
        self.assertEqual(torch_pkl003(found), [])
        other = [f for f in rules(found, "PKL003") if "mylib" in f.detail]
        self.assertEqual(len(other), 1)
        self.assertEqual(other[0].severity, "MEDIUM")

    def test_other_members_are_not_folded(self):
        data = make_zip({"model/data.pkl": EMPTY,
                         "model/code/__torch__.py": CODE,
                         "model/extra/notes.pkl": TS_DATA})
        found = pms.scan_zip(data, "m.pt")
        self.assertEqual(len(rules(found, "PKL040")), 1)
        kept = torch_pkl003(found)
        self.assertGreaterEqual(len(kept), 1)
        self.assertTrue(all("extra/notes.pkl" in f.location for f in kept))

    def test_plain_torch_save_zip_unchanged(self):
        data = make_zip({"archive/data.pkl": EMPTY,
                         "archive/version": b"3\n"})
        found = pms.scan_zip(data, "w.pth")
        self.assertEqual(rules(found, "PKL040"), [])

    def test_highest_severity_never_drops(self):
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for members in ({"model/data.pkl": TS_DATA,
                         "model/code/__torch__.py": CODE},
                        {"model/data.pkl": TS_DATA_OTHER,
                         "model/code/__torch__.py": CODE}):
            data = make_zip(members)
            found = pms.scan_zip(data, "m.pt")
            top = max(order[f.severity] for f in found)
            self.assertGreaterEqual(top, order["MEDIUM"])


if __name__ == "__main__":
    unittest.main()
