# test_infection_semantics_diff.py
#
# Copyright 2026 Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Made with AI agents working in the name of MV2 of Munim, Inc.
#
# Self-contained: imports only infection_semantics_diff (no repo modules), so it runs
# under the publish lane's isolated test_first with just the committed files.

import unittest

from infection_semantics_diff import (
    picklescan_classify,
    picklescan_outcome,
    keras_classify,
    keras_outcome,
    build_matrix,
)


class TestInfectionSemantics(unittest.TestCase):
    def test_known_dangerous_both_flag(self):
        # os is a wildcard-unsafe module in picklescan and in keras DANGEROUS_MODULES.
        self.assertEqual(picklescan_classify("os", "system"), "dangerous")
        self.assertTrue(picklescan_outcome("os", "system")["infected"])
        self.assertEqual(keras_classify("os", "system"), "dangerous")
        self.assertTrue(keras_outcome("os", "system")["surfaced"])

    def test_legit_allowlist_both_clear(self):
        # collections.OrderedDict: picklescan _safe_globals; keras BENIGN_TOP.
        self.assertEqual(picklescan_classify("collections", "OrderedDict"), "innocuous")
        self.assertFalse(picklescan_outcome("collections", "OrderedDict")["infected"])
        self.assertEqual(keras_classify("collections", "OrderedDict"), "benign")
        self.assertFalse(keras_outcome("collections", "OrderedDict")["surfaced"])

    def test_numpy_f2py_both_flag(self):
        # numpy top package is benign in both, but the f2py submodule is a carve-out.
        self.assertEqual(picklescan_classify("numpy.f2py", "compile"), "dangerous")
        self.assertEqual(keras_classify("numpy.f2py", "compile"), "rce_gadget")

    def test_synthetic_unknown_is_the_divergence(self):
        # The structural heart of the finding, independent of exact list membership:
        # a global outside BOTH of each tool's lists. picklescan (default non-strict)
        # -> Suspicious, which does NOT infect; keras -> unknown -> PKL003 MEDIUM,
        # a surfaced finding.
        m, n = "zz_never_listed_mod", "run"
        self.assertEqual(picklescan_classify(m, n), "suspicious")
        self.assertFalse(picklescan_outcome(m, n)["infected"])
        self.assertEqual(keras_classify(m, n), "unknown")
        km = keras_outcome(m, n)
        self.assertTrue(km["surfaced"])
        self.assertEqual(km["finding"], "PKL003/MEDIUM")

    def test_unknown_check_wins_first(self):
        # STACK_GLOBAL evasion guard: "unknown" anywhere -> Dangerous in picklescan.
        self.assertEqual(picklescan_classify("unknown", "x"), "dangerous")
        self.assertEqual(picklescan_classify("m", "unknown"), "dangerous")

    def test_keras_lists_verified_modules(self):
        # keras side is source-verified (0.2.1); picklescan side for these is left to
        # the compute job, so only the keras classification is asserted here.
        for mod in ("importlib", "multiprocessing", "platform", "signal", "dill"):
            self.assertEqual(keras_classify(mod, "x"), "dangerous", mod)

    def test_matrix_invariant_unknown_diverges(self):
        # For every row keras marks surfaced-but-picklescan-not-infected, the
        # divergence flag must be set, and it must be set for the synthetic unknown.
        matrix = build_matrix()
        synthetic = [r for r in matrix if r["module"] == "zz_never_listed_mod"]
        self.assertEqual(len(synthetic), 1)
        self.assertTrue(synthetic[0]["divergence_on_infection"])
        for r in matrix:
            expected = r["keras_surfaced"] and not r["picklescan_infected"]
            self.assertEqual(r["divergence_on_infection"], expected, r["module"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
