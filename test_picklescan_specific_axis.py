# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made with AI agents working in MV2's name.
"""Tests for picklescan_specific_axis: pin the specific-name-axis buckets.

Expected buckets below are written independently of the module's logic (derived by hand
from the two source files, both fetched 2026-10-23). If the classifier reproduction
drifts -- e.g. torch stops resolving to BENIGN_TOP, or the builtins/gadget-name branch
changes -- these assertions fail and the published finding cannot silently rot.
"""
import unittest

import picklescan_specific_axis as psa


# Hand-derived partition of picklescan's 31 specific-name module keys through
# keras-model-scan v0.2.1's classifier.
EXPECTED_STRONG = {
    "__builtin__", "builtins", "cloudpickle.cloudpickle", "code", "functools",
    "operator", "idlelib.autocomplete", "idlelib.calltip", "idlelib.debugobj",
    "idlelib.pyshell", "idlelib.run",
}
EXPECTED_WEAK = {
    "types", "logging", "_io", "_operator", "doctest", "ensurepip", "imaplib",
    "lib2to3.pgen2.grammar", "lib2to3.pgen2.pgen", "pkgutil", "trace",
}
EXPECTED_BLIND = {
    "torch._dynamo.guards", "torch._inductor.codecache",
    "torch.fx.experimental.symbolic_shapes", "torch.jit.unsupported_tensor_ops",
    "torch.serialization", "torch.utils._config_module",
    "torch.utils.bottleneck.__main__", "torch.utils.collect_env",
    "torch.utils.data.datapipes.utils.decoder",
}


class AxisCounts(unittest.TestCase):
    def test_total_is_31(self):
        self.assertEqual(len(psa.PICKLESCAN_SPECIFIC_MODULES), 31)
        # No duplicate keys in the snapshot.
        self.assertEqual(len(set(psa.PICKLESCAN_SPECIFIC_MODULES)), 31)

    def test_partition_matches_hand_derived(self):
        d = psa.classify_specific_axis()
        self.assertEqual(set(d["strong"]), EXPECTED_STRONG)
        self.assertEqual(set(d["weak"]), EXPECTED_WEAK)
        self.assertEqual(set(d["blind"]), EXPECTED_BLIND)
        self.assertEqual(d["strong_count"], 11)
        self.assertEqual(d["weak_count"], 11)
        self.assertEqual(d["blind_count"], 9)

    def test_buckets_partition_the_whole_axis(self):
        d = psa.classify_specific_axis()
        union = set(d["strong"]) | set(d["weak"]) | set(d["blind"])
        self.assertEqual(union, set(psa.PICKLESCAN_SPECIFIC_MODULES))
        self.assertEqual(set(d["strong"]) & set(d["weak"]), set())
        self.assertEqual(set(d["strong"]) & set(d["blind"]), set())
        self.assertEqual(set(d["weak"]) & set(d["blind"]), set())


class TorchBlindSpot(unittest.TestCase):
    def test_torch_is_allowlisted_benign(self):
        # The headline: torch is on BENIGN_TOP and NOT in DANGEROUS_MODULES, so every
        # torch.* path picklescan denies is classified benign (no finding).
        self.assertIn("torch", psa.KMS_BENIGN_TOP)
        self.assertNotIn("torch", psa.KMS_DANGEROUS_MODULES)
        for module in EXPECTED_BLIND:
            self.assertEqual(psa.kms_classify(module), "benign", module)

    def test_blind_spot_is_exactly_the_nine_torch_paths(self):
        d = psa.classify_specific_axis()
        self.assertTrue(all(m.split(".", 1)[0] == "torch" for m in d["blind"]))
        self.assertEqual(len(d["blind"]), 9)


class ClassifierBehaviour(unittest.TestCase):
    def test_idlelib_whole_package_covers_submodules(self):
        # keras-model-scan is STRONGER than picklescan here: idlelib is a whole-package
        # dangerous module, so every idlelib.* submodule is caught, not just the 5
        # picklescan enumerates.
        for module in ("idlelib.run", "idlelib.pyshell", "idlelib.some_future_submodule"):
            self.assertEqual(psa.kms_classify(module), "dangerous", module)

    def test_builtins_routes_on_name(self):
        self.assertEqual(psa.kms_classify("builtins", "eval"), "dangerous")
        self.assertEqual(psa.kms_classify("builtins", "print"), "benign")

    def test_functools_operator_gadget_names(self):
        self.assertEqual(psa.kms_classify("functools", "partial"), "gadget")
        self.assertEqual(psa.kms_classify("operator", "attrgetter"), "gadget")
        # _operator (the C alias picklescan also denies) is NOT handled by name.
        self.assertEqual(psa.kms_classify("_operator", "attrgetter"), "unknown")

    def test_numpy_f2py_prefix_still_critical(self):
        self.assertEqual(psa.kms_classify("numpy.f2py.crackfortran"), "rce_gadget")

    def test_unknown_is_still_surfaced_not_benign(self):
        for module in ("types", "logging", "trace", "pkgutil"):
            self.assertEqual(psa.kms_classify(module), "unknown", module)


class MarkdownRendering(unittest.TestCase):
    def test_table_mentions_blind_spot_and_counts(self):
        table = psa.markdown_table()
        self.assertIn("BENIGN -- not flagged", table)
        self.assertIn("`torch.serialization`", table)
        self.assertIn("11 recognised, 11 unknown-only, 9 BENIGN (blind spot)", table)


if __name__ == "__main__":
    unittest.main()
