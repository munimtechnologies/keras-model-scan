#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Self-contained tests for lightgbm_model_scan. Standard library only."""

import os
import shutil
import tempfile
import unittest

import lightgbm_model_scan as ls


def _j(values):
    return " ".join(str(v) for v in values)


def _tree(idx, lefts, rights, **over):
    """One tree block as LightGBM's writer lays it out: 'Tree=N', the
    key=value lines of Tree::ToString, a blank line, then one more."""
    nodes = len(lefts)
    leaves = nodes + 1
    lines = [("num_leaves", str(leaves)), ("num_cat", "0"),
             ("split_feature", _j([0] * nodes)),
             ("split_gain", _j([1.5] * nodes)),
             ("threshold", _j([0.5] * nodes)),
             ("decision_type", _j([2] * nodes)),
             ("left_child", _j(lefts)), ("right_child", _j(rights)),
             ("leaf_value", _j([0.25] * leaves)),
             ("leaf_weight", _j([1.0] * leaves)),
             ("leaf_count", _j([5] * leaves)),
             ("internal_value", _j([0.0] * nodes)),
             ("internal_weight", _j([1.0] * nodes)),
             ("internal_count", _j([10] * nodes)),
             ("is_linear", "0"), ("shrinkage", "0.1")]
    keys = [k for k, _ in lines]
    values = dict(lines)
    for key, value in over.items():
        if key not in values:
            keys.insert(len(keys) - 2, key)
        values[key] = _j(value) if isinstance(value, list) else value
    body = "".join("%s=%s\n" % (k, values[k]) for k in keys
                   if values[k] is not None)
    return "Tree=%d\n%s\n\n" % (idx, body)


def _clean(idx=0):
    # node 0 -> node 1 and leaf 1; node 1 -> leaf 0 and leaf 2
    return _tree(idx, [1, -1], [-2, -3])


def _head(max_feature_idx=3, num_class=1, sizes=None):
    count = max_feature_idx + 1
    text = ("tree\nversion=v4\nnum_class=%d\nnum_tree_per_iteration=%d\n"
            "label_index=0\nmax_feature_idx=%d\nobjective=binary sigmoid:1\n"
            "feature_names=%s\nfeature_infos=%s\n"
            % (num_class, num_class, max_feature_idx,
               _j("Column_%d" % i for i in range(count)),
               _j("[0:1]" for _ in range(count))))
    if sizes is not None:
        text += "tree_sizes=%s\n" % sizes
    return text + "\n"


_TAIL = ("end of trees\n\nfeature_importances:\nColumn_0=3\n\nparameters:\n"
         "[boosting: gbdt]\n[objective: binary]\nend of parameters\n\n"
         "pandas_categorical:null\n")


def _model(trees, sizes=True, **head):
    if sizes is True:
        sizes = _j(len(t) for t in trees)
    return (_head(sizes=sizes, **head) + "".join(trees) + _TAIL).encode("ascii")


def _rules(findings):
    return sorted(set(f["rule"] for f in findings))


def _scan(data):
    return ls.scan_bytes(data, "model.txt")


class LightGBMModelScanTests(unittest.TestCase):

    def test_version(self):
        self.assertEqual(ls.__version__, "0.1.0")

    def test_clean_model_has_no_findings(self):
        self.assertEqual(_scan(_model([_clean(0), _clean(1)])), [])

    def test_clean_model_without_tree_sizes_has_no_findings(self):
        self.assertEqual(_scan(_model([_clean(0), _clean(1)], sizes=None)), [])

    def test_crlf_model_without_tree_sizes_has_no_findings(self):
        data = _model([_clean(0)], sizes=None).replace(b"\n", b"\r\n")
        self.assertEqual(_scan(data), [])

    def test_single_leaf_tree_has_no_findings(self):
        self.assertEqual(_scan(_model([_tree(0, [], [])])), [])

    def test_clean_multiclass_model_has_no_findings(self):
        trees = [_clean(i) for i in range(6)]
        self.assertEqual(_scan(_model(trees, num_class=3)), [])

    def test_clean_categorical_tree_has_no_findings(self):
        tree = _tree(0, [1, -1], [-2, -3], num_cat="1",
                     decision_type=[1, 2], threshold=[0, 0.5],
                     cat_boundaries=[0, 1], cat_threshold=[10])
        self.assertEqual(_scan(_model([tree])), [])

    def test_clean_linear_tree_has_no_findings(self):
        tree = _tree(0, [1, -1], [-2, -3], is_linear="1",
                     leaf_const=[0.1, 0.2, 0.3], num_features=[1, 0, 2],
                     leaf_features="0  1 3 ", leaf_coeff="0.5  0.2 0.1 ")
        self.assertEqual(_scan(_model([tree])), [])

    def test_child_node_outside_tree_is_lgb001(self):
        found = _scan(_model([_tree(0, [5, -1], [-2, -3])]))
        self.assertEqual(_rules(found), ["LGB001"])
        self.assertIn("node 0: left child 5, tree has 2 split nodes",
                      found[0]["evidence"])
        self.assertEqual(found[0]["severity"], "high")

    def test_child_leaf_outside_tree_is_lgb001(self):
        found = _scan(_model([_tree(0, [1, -1], [-2, -9])]))
        self.assertEqual(_rules(found), ["LGB001"])
        self.assertIn("node 1: right child -9 is leaf 8, tree has 3 leaves",
                      found[0]["evidence"])

    def test_feature_past_max_feature_idx_is_lgb002(self):
        found = _scan(_model([_tree(0, [1, -1], [-2, -3],
                                    split_feature=[7, 0])]))
        self.assertEqual(_rules(found), ["LGB002"])
        self.assertIn("node 0: feature 7, max_feature_idx is 3",
                      found[0]["evidence"])

    def test_negative_feature_is_lgb002(self):
        found = _scan(_model([_tree(0, [1, -1], [-2, -3],
                                    split_feature=[0, -1])]))
        self.assertEqual(_rules(found), ["LGB002"])

    def test_child_pointing_at_root_is_lgb003(self):
        found = _scan(_model([_tree(0, [1, 0], [-2, -1])]))
        self.assertEqual(_rules(found), ["LGB003"])
        self.assertIn("node 1 leads back to node 0", found[0]["evidence"])

    def test_self_loop_is_lgb003(self):
        found = _scan(_model([_tree(0, [1, 1], [-2, -1])]))
        self.assertEqual(_rules(found), ["LGB003"])
        self.assertIn("node 1 leads back to node 1", found[0]["evidence"])

    def test_node_used_twice_is_lgb006(self):
        found = _scan(_model([_tree(0, [1, -1, -3], [1, -2, -4])]))
        self.assertEqual(_rules(found), ["LGB006"])
        self.assertIn("node 1 is a child 2 times", found[0]["evidence"])
        self.assertEqual(found[0]["severity"], "medium")

    def test_short_child_array_is_padded_with_zero_like_the_loader(self):
        # StringToArrayFast fills the missing value with 0: the root.
        found = _scan(_model([_tree(0, [1, -1], [-2, -3], left_child="1")]))
        self.assertEqual(_rules(found), ["LGB003", "LGB006"])
        count = [f for f in found if f["rule"] == "LGB006"][0]
        self.assertIn("left_child has 1 values, LightGBM reads 2",
                      count["evidence"])

    def test_category_set_outside_num_cat_is_lgb001(self):
        tree = _tree(0, [1, -1], [-2, -3], num_cat="1",
                     decision_type=[1, 2], threshold=[4, 0.5],
                     cat_boundaries=[0, 1], cat_threshold=[10])
        found = _scan(_model([tree]))
        self.assertEqual(_rules(found), ["LGB001"])
        self.assertIn("node 0: set 4, num_cat is 1", found[0]["evidence"])

    def test_cat_boundaries_past_cat_threshold_is_lgb001(self):
        tree = _tree(0, [1, -1], [-2, -3], num_cat="2",
                     decision_type=[1, 2], threshold=[0, 0.5],
                     cat_boundaries=[0, 5, 1], cat_threshold=[10])
        found = _scan(_model([tree]))
        self.assertEqual(_rules(found), ["LGB001"])
        self.assertIn("cat_boundaries entry 5, cat_threshold has 1 words",
                      found[0]["evidence"])

    def test_negative_cat_boundary_is_lgb001(self):
        tree = _tree(0, [1, -1], [-2, -3], num_cat="1",
                     decision_type=[1, 2], threshold=[0, 0.5],
                     cat_boundaries=[0, -3], cat_threshold=[10])
        found = _scan(_model([tree]))
        self.assertEqual(_rules(found), ["LGB001"])
        self.assertIn("cat_boundaries entry -3, cat_threshold has 0 words",
                      found[0]["evidence"])

    def test_categorical_flag_with_num_cat_zero_is_lgb006(self):
        found = _scan(_model([_tree(0, [1, -1], [-2, -3],
                                    decision_type=[1, 2])]))
        self.assertEqual(_rules(found), ["LGB006"])
        self.assertIn("node 0: num_cat 0", found[0]["evidence"])

    def test_unknown_decision_type_bits_are_lgb006(self):
        found = _scan(_model([_tree(0, [1, -1], [-2, -3],
                                    decision_type=[2, 64])]))
        self.assertEqual(_rules(found), ["LGB006"])
        self.assertIn("node 1: decision_type 64", found[0]["evidence"])

    def test_linear_leaf_feature_past_max_is_lgb002(self):
        tree = _tree(0, [1, -1], [-2, -3], is_linear="1",
                     leaf_const=[0.1, 0.2, 0.3], num_features=[1, 0, 1],
                     leaf_features="0  9 ", leaf_coeff="0.5  0.1 ")
        found = _scan(_model([tree]))
        self.assertEqual(_rules(found), ["LGB002"])
        self.assertIn("leaf feature 9, max_feature_idx is 3",
                      found[0]["evidence"])

    def test_repeated_tree_key_is_lgb005(self):
        tree = _clean().replace("num_cat=0\n", "num_cat=0\nleft_child=1 -1\n")
        found = _scan(_model([tree]))
        self.assertEqual(_rules(found), ["LGB005"])
        self.assertIn("key left_child", found[0]["evidence"])

    def test_repeated_header_key_is_lgb005(self):
        data = _model([_clean()]).replace(
            b"label_index=0\n", b"label_index=0\nmax_feature_idx=99\n")
        found = _scan(data)
        self.assertEqual(_rules(found), ["LGB005"])
        self.assertIn("key max_feature_idx", found[0]["evidence"])

    def test_tree_sizes_past_end_is_lgb004(self):
        found = _scan(_model([_clean(0), _clean(1)], sizes="999999 5"))
        self.assertEqual(_rules(found), ["LGB004"])
        self.assertIn("tree 1 at byte", found[0]["evidence"])

    def test_tree_sizes_off_a_tree_line_is_lgb007(self):
        found = _scan(_model([_clean(0), _clean(1)], sizes="3 5"))
        self.assertEqual(_rules(found), ["LGB007"])

    def test_tree_found_only_through_tree_sizes_is_checked(self):
        hidden = _tree(2, [5, -1], [-2, -3])
        trees = [_clean(0), _clean(1)]
        text = _model(trees, sizes="00000000 00000001").decode("ascii")
        first = text.index("Tree=0")
        text += hidden
        jump = text.index("Tree=2") - first
        text = text.replace("00000000 00000001", "%08d 00000001" % jump)
        found = _scan(text.encode("ascii"))
        self.assertEqual(_rules(found), ["LGB001", "LGB006"])
        moved = [f for f in found if f["rule"] == "LGB006"][0]
        self.assertIn("tree 1 at byte", moved["evidence"])

    def test_tree_text_ending_without_blank_line_is_lgb004(self):
        data = (_head() + "Tree=0\nnum_leaves=1\nnum_cat=0\n"
                "leaf_value=0.5").encode("ascii")
        self.assertEqual(_rules(_scan(data)), ["LGB004"])

    def test_partial_iteration_is_lgb006(self):
        found = _scan(_model([_clean(0), _clean(1)], num_class=3))
        self.assertEqual(_rules(found), ["LGB006"])
        self.assertIn("2 trees, 3 per iteration", found[0]["evidence"])

    def test_num_leaves_past_lightgbm_limit_is_lgb006(self):
        found = _scan(_model([_tree(0, [1, -1], [-2, -3],
                                    num_leaves="200000")]))
        self.assertEqual(_rules(found), ["LGB006"])

    def test_feature_names_count_mismatch_is_lgb007(self):
        data = _model([_clean()]).replace(b" Column_3\n", b"\n")
        self.assertIn(b"feature_names=Column_0 Column_1 Column_2\n", data)
        self.assertEqual(_rules(_scan(data)), ["LGB007"])

    def test_findings_in_many_trees_are_counted_once(self):
        trees = [_tree(i, [5, -1], [-2, -3]) for i in range(5)]
        found = _scan(_model(trees))
        self.assertEqual(len(found), 1)
        self.assertIn("; 5 in total", found[0]["evidence"])

    def test_other_files_are_lgb007(self):
        for data in (b"\x80\x04K\x01.", b"", b"{\"tree_info\": []}",
                     b"hello", b"Tree=0\nnum_leaves=1\n"):
            self.assertEqual(_rules(_scan(data)), ["LGB007"], data)

    def test_truncated_input_never_crashes_the_checker(self):
        trees = [_clean(0),
                 _tree(1, [1, -1], [-2, -3], num_cat="1",
                       decision_type=[1, 2], threshold=[0, 0.5],
                       cat_boundaries=[0, 1], cat_threshold=[10]),
                 _tree(2, [1, -1], [-2, -3], is_linear="1",
                       leaf_const=[0.1, 0.2, 0.3], num_features=[1, 0, 2],
                       leaf_features="0  1 3 ", leaf_coeff="0.5  0.2 0.1 ")]
        for blob in (_model(trees), _model(trees, sizes=None)):
            for cut in range(len(blob)):
                for item in _scan(blob[:cut]):
                    self.assertNotIn("could not be checked", item["message"],
                                     (cut, item))

    def test_scan_file_and_main_exit_codes(self):
        tmp = tempfile.mkdtemp()
        try:
            clean = os.path.join(tmp, "clean.txt")
            bad = os.path.join(tmp, "bad.txt")
            medium = os.path.join(tmp, "medium.txt")
            with open(clean, "wb") as handle:
                handle.write(_model([_clean()]))
            with open(bad, "wb") as handle:
                handle.write(_model([_tree(0, [1, -1], [-2, -3],
                                           split_feature=[7, 0])]))
            with open(medium, "wb") as handle:
                handle.write(_model([_tree(0, [1, -1], [-2, -3],
                                           decision_type=[2, 64])]))
            self.assertEqual(ls.scan_file(clean), [])
            self.assertEqual(_rules(ls.scan_file(bad)), ["LGB002"])
            self.assertEqual(ls.main([clean]), 0)
            self.assertEqual(ls.main([clean, medium]), 0)
            self.assertEqual(ls.main([clean, bad]), 1)
            self.assertEqual(ls.main([os.path.join(tmp, "nope.txt")]), 2)
            self.assertEqual(ls.main([]), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
