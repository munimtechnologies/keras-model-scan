# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# Made with AI agents working in the name of MV2 of Munim, Inc.
#
# Standalone tests for benign_top_blindspot_census.py. Pure-stdlib; imports only
# the census module, so it runs in isolation under the publish test gate.

import unittest

import benign_top_blindspot_census as census


class BenignTopBlindSpotCensusTest(unittest.TestCase):
    def test_selfcheck_passes(self):
        # Raises AssertionError if any invariant is violated.
        census._selfcheck()

    def test_every_listed_path_sits_under_benign_top(self):
        for entry in census.PICKLESCAN_PATHS_UNDER_BENIGN_TOP:
            self.assertIn(
                census.top_package(entry["module"]),
                census.KERAS_BENIGN_TOP,
                entry["module"],
            )

    def test_numpy_f2py_is_carved_not_blind(self):
        # numpy.f2py (and anything under it) is caught by GADGET_MODULE_PREFIXES.
        self.assertEqual(census.keras_classification("numpy.f2py"), "gadget")
        self.assertEqual(census.keras_classification("numpy.f2py.crackfortran"), "gadget")
        self.assertIn("numpy.f2py", census.carved_modules())
        self.assertNotIn("numpy.f2py", census.blind_spot_modules())

    def test_numpy_testing_private_utils_is_the_new_blind_spot(self):
        # Shadowed by BENIGN_TOP ("numpy") with no carve-out -> benign.
        self.assertEqual(
            census.keras_classification("numpy.testing._private.utils"),
            "benign",
        )
        self.assertIn(
            "numpy.testing._private.utils", census.blind_spot_modules()
        )

    def test_all_nine_torch_paths_remain_blind(self):
        torch_blind = [m for m in census.blind_spot_modules() if m.startswith("torch.")]
        self.assertEqual(len(torch_blind), 9)

    def test_completeness_counts(self):
        self.assertEqual(len(census.PICKLESCAN_PATHS_UNDER_BENIGN_TOP), 11)
        self.assertEqual(len(census.blind_spot_modules()), 10)
        self.assertEqual(census.carved_modules(), ["numpy.f2py"])

    def test_ordinary_arrays_stay_benign(self):
        # A plain numpy / torch global is correctly benign, not a false positive.
        self.assertEqual(census.keras_classification("numpy"), "benign")
        self.assertEqual(census.keras_classification("torch"), "benign")


if __name__ == "__main__":
    unittest.main()
