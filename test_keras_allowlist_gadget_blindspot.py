# Copyright 2026 Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working in the name of MV2 of Munim, Inc.
"""Invariants for the Keras namespace-allowlist blind-spot model.

Standalone: imports only the module under test and the standard library, so it
runs in isolation (publish lane test_first) without any repository module.
"""

import unittest

from keras_allowlist_gadget_blindspot import (
    KERAS_GADGET_CALLABLES,
    KERAS_IMPORT_ALLOWLIST,
    classify_current,
    classify_proposed,
    matrix,
    top_package,
)


class TestAllowlistBlindSpot(unittest.TestCase):
    def test_allowlist_matches_source(self):
        # The four namespaces Keras 3.9+ and KMS001 both trust.
        self.assertEqual(
            KERAS_IMPORT_ALLOWLIST,
            frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"}),
        )

    def test_top_package(self):
        self.assertEqual(top_package("keras.utils"), "keras")
        self.assertEqual(top_package("subprocess"), "subprocess")
        self.assertEqual(top_package(""), "")

    def test_current_rule_has_the_blind_spot(self):
        # The crux: the in-namespace JFrog gadget is marked benign today.
        self.assertEqual(classify_current("keras.utils", "get_file"), "benign")

    def test_proposed_rule_closes_it(self):
        self.assertEqual(classify_proposed("keras.utils", "get_file"), "flag")

    def test_proposed_does_not_overflag_benign_keras(self):
        # A genuinely benign keras callable stays benign under both rules.
        self.assertEqual(classify_current("keras.layers", "Dense"), "benign")
        self.assertEqual(classify_proposed("keras.layers", "Dense"), "benign")

    def test_outside_allowlist_still_flags_under_both(self):
        for rule in (classify_current, classify_proposed):
            self.assertEqual(rule("subprocess", "Popen"), "flag")
            self.assertEqual(rule("os", "system"), "flag")

    def test_every_gadget_flips_from_benign_to_flag(self):
        # Each denylisted gadget lives in an allowlisted namespace (so the
        # current rule passes it) and is caught by the proposed rule.
        for dotted in KERAS_GADGET_CALLABLES:
            module, _, name = dotted.rpartition(".")
            self.assertIn(top_package(module), KERAS_IMPORT_ALLOWLIST, dotted)
            self.assertEqual(classify_current(module, name), "benign", dotted)
            self.assertEqual(classify_proposed(module, name), "flag", dotted)

    def test_matrix_shape(self):
        rows = matrix()
        self.assertTrue(all({"current", "proposed"} <= set(r) for r in rows))
        # At least one row must demonstrate the divergence.
        self.assertTrue(
            any(r["current"] == "benign" and r["proposed"] == "flag" for r in rows)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
