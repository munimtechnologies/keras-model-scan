# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
# Made with AI agents working in the name of MV2 of Munim, Inc.
#
# Standalone test for torch_gadget_blindspot.py. Imports only that module and
# the stdlib, so it passes under publish-lane test_first isolation (the commit
# contains only these files).

import unittest

import torch_gadget_blindspot as tg


class TorchGadgetBlindSpotTest(unittest.TestCase):
    def test_exactly_nine_paths(self):
        self.assertEqual(len(tg.TORCH_GADGET_PATHS), 9)

    def test_every_path_is_under_torch_with_named_callables(self):
        for entry in tg.TORCH_GADGET_PATHS:
            self.assertTrue(entry["module"].startswith("torch."), entry["module"])
            self.assertTrue(entry["names"], entry)
            self.assertTrue(all(n for n in entry["names"]), entry)
            self.assertTrue(entry["mechanism"].strip(), entry)

    def test_modules_are_unique(self):
        modules = [e["module"] for e in tg.TORCH_GADGET_PATHS]
        self.assertEqual(len(modules), len(set(modules)))

    def test_mirrors_picklescan_torch_denylist(self):
        # The nine exact dotted paths picklescan's _unsafe_globals denies under
        # the torch namespace, as fetched live 2026-10-23.
        expected = {
            "torch.serialization",
            "torch._inductor.codecache",
            "torch.jit.unsupported_tensor_ops",
            "torch._dynamo.guards",
            "torch.fx.experimental.symbolic_shapes",
            "torch.utils._config_module",
            "torch.utils.bottleneck.__main__",
            "torch.utils.collect_env",
            "torch.utils.data.datapipes.utils.decoder",
        }
        self.assertEqual({e["module"] for e in tg.TORCH_GADGET_PATHS}, expected)

    def test_all_nine_are_a_blind_spot_under_current_classifier(self):
        # The finding: with torch on BENIGN_TOP and no exact-match gadget layer,
        # every one of these recognised gadgets resolves to benign.
        self.assertEqual(
            tg.blind_spot_modules(),
            [e["module"] for e in tg.TORCH_GADGET_PATHS],
        )
        for entry in tg.TORCH_GADGET_PATHS:
            self.assertEqual(tg.keras_classification(entry["module"]), "benign")

    def test_snapshot_matches_the_live_scanner_cause(self):
        self.assertTrue(tg.KERAS_TORCH_IN_BENIGN_TOP)
        self.assertFalse(tg.KERAS_TORCH_IN_DANGEROUS_MODULES)
        self.assertFalse(tg.KERAS_HAS_GADGET_MODULE_PATHS)

    def test_fix_would_be_exact_match_not_whole_package(self):
        # An ordinary torch global that is NOT one of the gadget paths must stay
        # benign, so the planned carve-out has to be exact-path, not top-package.
        self.assertFalse(tg._is_ledger_path("torch.nn"))
        self.assertFalse(tg._is_ledger_path("torch"))
        self.assertEqual(tg.keras_classification("torch.nn"), "benign")

    def test_top_package_helper(self):
        self.assertEqual(tg.top_package("torch.utils.collect_env"), "torch")
        self.assertEqual(tg.top_package("torch"), "torch")


if __name__ == "__main__":
    unittest.main()
