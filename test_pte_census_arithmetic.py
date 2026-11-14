# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
"""Tests for research/pte-census/gate_arithmetic.py (counting only; no scanning).

Made with AI agents working in the name of MV2 of Munim, Inc. Licence: Apache-2.0.
The second class pins every number quoted in research/pte-census/GATE_ARITHMETIC.md
to the published per-file data, so the note cannot drift from the data.
"""

import importlib.util
import json
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_DIR = os.path.join(_HERE, "research", "pte-census")
_spec = importlib.util.spec_from_file_location("gate_arithmetic", os.path.join(_DIR, "gate_arithmetic.py"))
ga = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ga)


def _p3(backend, severity="medium"):
    return {"rule": "PTE003", "severity": severity, "cve": "", "cwe": "CWE-829",
            "message": "backend delegate %s: that backend's native code parses an ahead-of-time "
                       "compiled blob at load; this scanner cannot read inside it" % backend,
            "evidence": "plan 0 delegate 0: segment 1, 10 bytes, 0 compile specs"}


def _p4(evidence):
    return {"rule": "PTE004", "severity": "medium", "cve": "", "cwe": "CWE-129",
            "message": "indexes that are out of range: 1", "evidence": evidence}


def _p5(evidence="1 segments"):
    return {"rule": "PTE005", "severity": "medium", "cve": "", "cwe": "CWE-693",
            "message": "the program lists data segments but no extended header gives a "
                       "segment base offset", "evidence": evidence}


def _rec(model, name, findings):
    return {"model": model, "rfilename": name, "findings": findings}


class HandBuilt(unittest.TestCase):
    def test_backend_names(self):
        self.assertEqual(ga.backend_of(_p3("XnnpackBackend")), "XnnpackBackend")
        self.assertEqual(ga.backend_of({"message": "something else"}), "?")
        rec = _rec("m", "a.pte", [_p3("A"), _p3("B"), _p4("x")])
        self.assertEqual(ga.backends(rec), frozenset({"A", "B"}))
        self.assertEqual(ga.backends(_rec("m", "b.pte", None)), frozenset())

    def test_scalar9_only(self):
        one = "plan 0 value 32: scalar_type 9 is not an ExecuTorch dtype"
        two = one + "; plan 3 value 92: scalar_type 9 is not an ExecuTorch dtype"
        self.assertTrue(ga.is_scalar9_only(one))
        self.assertTrue(ga.is_scalar9_only(two))
        self.assertFalse(ga.is_scalar9_only(""))
        self.assertFalse(ga.is_scalar9_only(one + "; plan 0 value 1: scalar_type 99 is not an ExecuTorch dtype"))
        self.assertFalse(ga.is_scalar9_only("plan 0 value 1: index 7 out of range"))

    def test_targeted(self):
        self.assertTrue(ga.targeted(_p4("plan 0 value 1: scalar_type 9 is not an ExecuTorch dtype")))
        self.assertFalse(ga.targeted(_p4("plan 0 value 1: index 7 out of range")))
        self.assertTrue(ga.targeted(_p5("1 segments")))
        self.assertFalse(ga.targeted(_p5("2 segments")))
        self.assertFalse(ga.targeted(_p3("A")))

    def test_gate(self):
        self.assertFalse(ga.fails([]))
        self.assertTrue(ga.fails([_p3("A")]))
        self.assertFalse(ga.fails([_p3("A")], frozenset({"A"})))
        self.assertTrue(ga.fails([_p3("A"), _p3("B")], frozenset({"A"})))
        self.assertTrue(ga.fails([_p3("A"), _p5()], frozenset({"A"})))
        self.assertFalse(ga.fails([_p3("A", "low")]))
        self.assertTrue(ga.fails([_p3("A", "HIGH")]))

    def test_summarize_small(self):
        s9 = "plan 0 value 1: scalar_type 9 is not an ExecuTorch dtype"
        recs = [
            _rec("m1", "a.pte", [_p3("A")]),
            _rec("m1", "b.pte", [_p3("A"), _p3("B")]),
            _rec("m2", "c.pte", [_p3("B"), _p4(s9)]),
            _rec("m2", "d.pte", [_p5()]),
            _rec("m3", "e.pte", []),
            _rec("m3", "f.pte", [_p4("plan 0 value 1: index 7 out of range")]),
        ]
        s = ga.summarize(recs)
        self.assertEqual(s["files"], 6)
        self.assertEqual(s["models"], 3)
        self.assertEqual(s["files_with_pte003"], 3)
        self.assertEqual(s["backends_per_file"], {"0": 3, "1": 2, "2": 1})
        self.assertEqual(s["files_by_backend"], {"A": 2, "B": 2})
        self.assertEqual(s["multi_backend_combos"], {"A+B": 1})
        self.assertEqual(s["targeted_findings"], 2)
        self.assertEqual(s["untargeted_non_pte003"], 1)
        self.assertEqual(s["gate_fail_now"], 5)
        self.assertEqual(s["gate_fail_without_targeted"], 4)
        self.assertEqual([x["added"] for x in s["what_if_low"]], [None, "A", "B"])
        self.assertEqual([x["gate_fail"] for x in s["what_if_low"]], [4, 3, 1])
        s2 = ga.summarize(recs, ["B"])
        self.assertEqual([x["gate_fail"] for x in s2["what_if_low"]], [4, 3])


class PublishedCensus(unittest.TestCase):
    """Every number quoted in GATE_ARITHMETIC.md, recomputed from the data."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_DIR, "pte_census_files.json"), encoding="utf-8") as fh:
            cls.s = ga.summarize(json.load(fh))

    def test_totals(self):
        s = self.s
        self.assertEqual(s["files"], 450)
        self.assertEqual(s["models"], 171)
        self.assertEqual(s["files_with_pte003"], 433)
        self.assertEqual(s["backends_per_file"], {"0": 17, "1": 426, "2": 7})

    def test_backends(self):
        self.assertEqual(self.s["files_by_backend"], {
            "XnnpackBackend": 188, "CoreMLBackend": 75, "VulkanBackend": 58, "MLXBackend": 45,
            "NeuropilotBackend": 36, "QnnBackend": 24, "CudaBackend": 10, "EthosUBackend": 3,
            "MetalBackend": 1})
        self.assertEqual(self.s["multi_backend_combos"], {
            "VulkanBackend+XnnpackBackend": 4, "QnnBackend+XnnpackBackend": 2,
            "MLXBackend+XnnpackBackend": 1})

    def test_gate_now_and_without_targeted(self):
        s = self.s
        self.assertEqual(s["targeted_findings"], 23)
        self.assertEqual(s["untargeted_non_pte003"], 0)
        self.assertEqual((s["gate_fail_now"], s["gate_fail_now_pct"]), (438, 97.3))
        self.assertEqual((s["gate_fail_without_targeted"], s["gate_fail_without_targeted_pct"]), (433, 96.2))

    def test_what_if_ladder(self):
        steps = self.s["what_if_low"]
        self.assertEqual([x["added"] for x in steps], [
            None, "XnnpackBackend", "CoreMLBackend", "VulkanBackend", "MLXBackend",
            "NeuropilotBackend", "QnnBackend", "CudaBackend", "EthosUBackend", "MetalBackend"])
        self.assertEqual([x["gate_fail"] for x in steps], [433, 252, 177, 119, 74, 38, 14, 4, 1, 0])
        self.assertEqual([x["pct"] for x in steps], [96.2, 56.0, 39.3, 26.4, 16.4, 8.4, 3.1, 0.9, 0.2, 0.0])


if __name__ == "__main__":
    unittest.main()
