#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Self-contained tests for xgboost_model_scan. Standard library only."""

import json
import os
import shutil
import struct
import tempfile
import unittest

import xgboost_model_scan as xs

ROOT_PARENT = 2147483647


class _Raw(bytes):
    """Bytes that _ubj() copies as they are (already encoded)."""


def _q(n):
    return struct.pack(">q", n)


def _ubj_str(text):
    raw = text.encode("utf-8")
    return b"L" + _q(len(raw)) + raw


def _ubj_obj(pairs):
    return b"{" + b"".join(_ubj_str(k) + _ubj(v) for k, v in pairs) + b"}"


def _ubj(value):
    # The subset XGBoost writes: 'L'-length keys, typed numeric arrays,
    # counted generic arrays, 'd' floats, 'L' integers.
    if isinstance(value, _Raw):
        return bytes(value)
    if value is None:
        return b"Z"
    if value is True:
        return b"T"
    if value is False:
        return b"F"
    if isinstance(value, int):
        return b"L" + _q(value)
    if isinstance(value, float):
        return b"d" + struct.pack(">f", value)
    if isinstance(value, str):
        return b"S" + _ubj_str(value)
    if isinstance(value, dict):
        return _ubj_obj(value.items())
    if value and all(isinstance(v, bool) for v in value):
        return b"[$U#L" + _q(len(value)) + bytes(int(v) for v in value)
    if value and all(isinstance(v, int) and not isinstance(v, bool)
                     for v in value):
        if all(-2 ** 31 <= v < 2 ** 31 for v in value):
            return (b"[$l#L" + _q(len(value))
                    + struct.pack(">%di" % len(value), *value))
        return (b"[$L#L" + _q(len(value))
                + struct.pack(">%dq" % len(value), *value))
    if value and all(isinstance(v, float) for v in value):
        return (b"[$d#L" + _q(len(value))
                + struct.pack(">%df" % len(value), *value))
    return b"[#L" + _q(len(value)) + b"".join(_ubj(v) for v in value)


def _tree(lefts, rights, parents=None, splits=None, tid=0, **extra):
    n = len(lefts)
    if parents is None:
        parents = [0] * n
        parents[0] = ROOT_PARENT
        for i, pair in enumerate(zip(lefts, rights)):
            for child in pair:
                if 0 < child < n:
                    parents[child] = i
    tree = {
        "base_weights": [0.5] * n,
        "categories": [], "categories_nodes": [],
        "categories_segments": [], "categories_sizes": [],
        "default_left": [False] * n,
        "id": tid,
        "left_children": list(lefts),
        "loss_changes": [0.0] * n,
        "parents": list(parents),
        "right_children": list(rights),
        "split_conditions": [0.5] * n,
        "split_indices": [0] * n if splits is None else list(splits),
        "split_type": [0] * n,
        "sum_hessian": [1.0] * n,
        "tree_param": {"num_deleted": "0", "num_feature": "4",
                       "num_nodes": str(n), "size_leaf_vector": "1"},
    }
    tree.update(extra)
    return tree


def _clean_tree(tid=0):
    return _tree([1, -1, -1], [2, -1, -1], tid=tid)


def _model(trees, num_feature=4, num_class=0, tree_info=None,
           booster="gbtree"):
    info = [0] * len(trees) if tree_info is None else tree_info
    model = {"gbtree_model_param": {"num_parallel_tree": "1",
                                    "num_trees": str(len(trees))},
             "iteration_indptr": list(range(len(trees) + 1)),
             "tree_info": info, "trees": trees}
    gb = {"model": model, "name": "gbtree"}
    if booster == "dart":
        gb = {"gbtree": gb, "name": "dart", "weight_drop": [1.0] * len(trees)}
    return {"learner": {
        "attributes": {}, "feature_names": [], "feature_types": [],
        "gradient_booster": gb,
        "learner_model_param": {"base_score": "5E-1",
                                "boost_from_average": "1",
                                "num_class": str(num_class),
                                "num_feature": str(num_feature),
                                "num_target": "1"},
        "objective": {"name": "binary:logistic"}},
        "version": [3, 1, 0]}


def _json(doc):
    return json.dumps(doc).encode("utf-8")


def _rules(findings):
    return sorted(set(f["rule"] for f in findings))


class XGBoostModelScanTests(unittest.TestCase):

    def both(self, doc):
        """Scan the same model as JSON and as UBJSON; both must agree."""
        a = xs.scan_bytes(_json(doc), "m.json")
        b = xs.scan_bytes(_ubj(doc), "m.ubj")
        self.assertEqual(_rules(a), _rules(b))
        return a

    def test_version(self):
        self.assertEqual(xs.__version__, "0.1.0")

    def test_encoder_writes_ubjson_object(self):
        self.assertTrue(_ubj(_model([_clean_tree()])).startswith(b"{L"))

    def test_clean_model_has_no_findings(self):
        self.assertEqual(self.both(_model([_clean_tree(0), _clean_tree(1)])), [])

    def test_clean_dart_model_has_no_findings(self):
        self.assertEqual(self.both(_model([_clean_tree()], booster="dart")), [])

    def test_clean_multiclass_model_has_no_findings(self):
        trees = [_clean_tree(t) for t in range(3)]
        self.assertEqual(self.both(_model(trees, num_class=3,
                                          tree_info=[0, 1, 2])), [])

    def test_gblinear_has_no_findings(self):
        doc = {"learner": {"gradient_booster": {"name": "gblinear",
                                                "model": {"weights": [0.1]}},
                           "learner_model_param": {"num_feature": "1"}}}
        self.assertEqual(xs.scan_bytes(_json(doc)), [])

    def test_left_child_outside_tree_is_xgb001(self):
        found = self.both(_model([_tree([99999, -1, -1], [2, -1, -1])]))
        self.assertEqual(_rules(found), ["XGB001"])
        self.assertIn("left child 99999", found[0]["evidence"])
        self.assertEqual(found[0]["severity"], "high")

    def test_right_branch_past_end_is_xgb001(self):
        # dmlc/xgboost#7903: root, right child, left child.
        found = self.both(_model([_tree([2, -1, -1], [1, -1, -1])]))
        self.assertIn("XGB001", _rules(found))
        self.assertTrue(any("right branch is node 3 of 3" in f["evidence"]
                            for f in found))

    def test_right_child_outside_tree_is_xgb001(self):
        found = self.both(_model([_tree([1, -1, -1], [70, -1, -1])]))
        self.assertIn("XGB001", _rules(found))
        self.assertTrue(any("right child 70" in f["evidence"] for f in found))

    def test_right_child_not_left_plus_one_is_xgb006(self):
        found = self.both(_model([_tree([1, -1, -1, -1, -1],
                                        [3, -1, -1, -1, -1])]))
        self.assertEqual(_rules(found), ["XGB006"])
        self.assertIn("left child 1, right child 3", found[0]["evidence"])
        self.assertEqual(found[0]["severity"], "medium")

    def test_feature_past_num_feature_is_xgb002(self):
        found = self.both(_model([_tree([1, -1, -1], [2, -1, -1],
                                        splits=[7, 0, 0])]))
        self.assertEqual(_rules(found), ["XGB002"])
        self.assertIn("feature 7, model has 4 features", found[0]["evidence"])

    def test_negative_feature_is_xgb002(self):
        found = self.both(_model([_tree([1, -1, -1], [2, -1, -1],
                                        splits=[-1, 0, 0])]))
        self.assertEqual(_rules(found), ["XGB002"])

    def test_leaf_feature_index_is_not_checked(self):
        # Pruned (deleted) leaves keep 2147483647 as their split index.
        found = self.both(_model([_tree([1, -1, -1], [2, -1, -1],
                                        splits=[0, ROOT_PARENT, 9])]))
        self.assertEqual(found, [])

    def test_loop_is_xgb003(self):
        tree = _tree([1, 0, -1], [2, 1, -1], parents=[ROOT_PARENT, 0, 0])
        found = self.both(_model([tree]))
        self.assertIn("XGB003", _rules(found))
        loop = [f for f in found if f["rule"] == "XGB003"][0]
        self.assertIn("node 1 leads back to node 0", loop["evidence"])

    def test_self_loop_is_xgb003(self):
        tree = _tree([1, 1, -1, -1], [2, 2, -1, -1],
                     parents=[ROOT_PARENT, 0, 0, 0])
        self.assertIn("XGB003", _rules(self.both(_model([tree]))))

    def test_parent_outside_tree_is_xgb001(self):
        tree = _tree([1, -1, -1], [2, -1, -1], parents=[ROOT_PARENT, 50, 0])
        found = self.both(_model([tree]))
        self.assertIn("XGB001", _rules(found))
        self.assertTrue(any("parent 50" in f["evidence"] for f in found))

    def test_parent_not_pointing_back_is_xgb006(self):
        tree = _tree([1, -1, -1], [2, -1, -1], parents=[ROOT_PARENT, 2, 0])
        self.assertEqual(_rules(self.both(_model([tree]))), ["XGB006"])

    def test_leaf_with_right_child_is_xgb006(self):
        tree = _tree([1, -1, -1], [2, 2, -1], parents=[ROOT_PARENT, 0, 0])
        found = self.both(_model([tree]))
        self.assertEqual(_rules(found), ["XGB006"])
        self.assertIn("node 1: right child 2", found[0]["evidence"])

    def test_tree_info_group_out_of_range_is_xgb006(self):
        found = self.both(_model([_clean_tree()], tree_info=[5]))
        self.assertEqual(_rules(found), ["XGB006"])
        self.assertIn("group 5 of 1", found[0]["evidence"])

    def test_clean_categorical_split_has_no_findings(self):
        tree = _clean_tree()
        tree.update({"split_type": [1, 0, 0], "categories_nodes": [0],
                     "categories_segments": [0], "categories_sizes": [2],
                     "categories": [1, 3]})
        self.assertEqual(self.both(_model([tree])), [])

    def test_category_range_past_array_is_xgb001(self):
        tree = _clean_tree()
        tree.update({"split_type": [1, 0, 0], "categories_nodes": [0],
                     "categories_segments": [1], "categories_sizes": [40],
                     "categories": [1, 3]})
        found = self.both(_model([tree]))
        self.assertEqual(_rules(found), ["XGB001"])
        self.assertIn("categories[1:41] of 2", found[0]["evidence"])

    def test_more_category_nodes_than_segments_is_xgb001(self):
        tree = _tree([1, 3, -1, -1, -1], [2, 4, -1, -1, -1])
        tree.update({"split_type": [1, 1, 0, 0, 0], "categories_nodes": [0, 1],
                     "categories_segments": [0], "categories_sizes": [1],
                     "categories": [2]})
        found = self.both(_model([tree]))
        self.assertEqual(_rules(found), ["XGB001"])
        self.assertIn("2 nodes, 1 segments, 1 sizes", found[0]["evidence"])

    def test_negative_category_is_xgb006(self):
        tree = _clean_tree()
        tree.update({"split_type": [1, 0, 0], "categories_nodes": [0],
                     "categories_segments": [0], "categories_sizes": [1],
                     "categories": [-4]})
        self.assertEqual(_rules(self.both(_model([tree]))), ["XGB006"])

    def test_array_length_mismatch_is_xgb007_only(self):
        tree = _clean_tree()
        tree["split_conditions"] = [0.5]
        found = self.both(_model([tree]))
        self.assertEqual(_rules(found), ["XGB007"])
        self.assertIn("split_conditions", found[0]["evidence"])

    def test_num_trees_mismatch_is_xgb007(self):
        doc = _model([_clean_tree()])
        doc["learner"]["gradient_booster"]["model"]["gbtree_model_param"][
            "num_trees"] = "3"
        self.assertEqual(_rules(self.both(doc)), ["XGB007"])

    def test_multi_target_tree_is_xgb007(self):
        tree = _clean_tree()
        tree["tree_param"]["size_leaf_vector"] = "2"
        self.assertEqual(_rules(self.both(_model([tree]))), ["XGB007"])

    def test_findings_in_many_trees_are_counted_once(self):
        trees = [_tree([99999, -1, -1], [2, -1, -1], tid=t) for t in range(5)]
        found = self.both(_model(trees))
        self.assertEqual(len(found), 1)
        self.assertIn("; 5 in total", found[0]["evidence"])

    def test_duplicate_key_in_ubjson_is_xgb004_and_first_value_is_checked(self):
        pairs = list(_clean_tree().items())
        pairs.insert(0, ("left_children", [99999, -1, -1]))
        doc = _model([_Raw(_ubj_obj(pairs))])
        found = xs.scan_bytes(_ubj(doc), "m.ubj")
        self.assertEqual(_rules(found), ["XGB001", "XGB004"])
        dup = [f for f in found if f["rule"] == "XGB004"][0]
        self.assertIn("left_children", dup["evidence"])

    def test_duplicate_key_in_json_is_xgb004_and_last_value_is_checked(self):
        text = json.dumps(_model([_clean_tree()]))
        clean = '"left_children": [1, -1, -1]'
        self.assertIn(clean, text)
        text = text.replace(clean, '"left_children": [99999, -1, -1], ' + clean)
        found = xs.scan_bytes(text.encode("utf-8"), "m.json")
        self.assertEqual(_rules(found), ["XGB004"])

    def test_ubjson_key_length_past_end_is_xgb005(self):
        found = xs.scan_bytes(b"{L" + _q(2 ** 40) + b"learner", "m.ubj")
        self.assertEqual(_rules(found), ["XGB005"])
        self.assertIn("declares 1099511627776 bytes", found[0]["evidence"])

    def test_ubjson_typed_array_count_past_end_is_xgb005(self):
        raw = _Raw(b"[$l#L" + _q(10 ** 9) + b"\x00\x00\x00\x01")
        found = xs.scan_bytes(_ubj_obj([("learner", raw)]), "m.ubj")
        self.assertEqual(_rules(found), ["XGB005"])

    def test_ubjson_array_count_past_end_is_xgb005(self):
        raw = _Raw(b"[#L" + _q(10 ** 6) + b"Z")
        found = xs.scan_bytes(_ubj_obj([("learner", raw)]), "m.ubj")
        self.assertEqual(_rules(found), ["XGB005"])

    def test_negative_ubjson_length_is_xgb007(self):
        found = xs.scan_bytes(b"{L" + _q(-5) + b"learner", "m.ubj")
        self.assertEqual(_rules(found), ["XGB007"])

    def test_other_files_are_xgb007(self):
        for data in (b"\x80\x04K\x01.", b"binf" + b"\x00" * 140,
                     b"\x00\x01\x02", b"", b"[1, 2]", b"{\"a\": 1}"):
            found = xs.scan_bytes(data, "x")
            self.assertEqual(_rules(found), ["XGB007"], data)

    def test_truncated_input_never_crashes_the_checker(self):
        doc = _model([_clean_tree(0), _tree([1, -1, -1], [2, -1, -1],
                                            splits=[9, 0, 0], tid=1)],
                     tree_info=[0, 0])
        for blob in (_ubj(doc), _json(doc)):
            step = 1 if blob[:2] == b"{L" else 7
            for cut in range(0, len(blob), step):
                for item in xs.scan_bytes(blob[:cut], "cut"):
                    self.assertNotIn("could not be checked", item["message"],
                                     (cut, item))

    def test_scan_file_and_main_exit_codes(self):
        tmp = tempfile.mkdtemp()
        try:
            clean = os.path.join(tmp, "clean.ubj")
            bad = os.path.join(tmp, "bad.json")
            with open(clean, "wb") as handle:
                handle.write(_ubj(_model([_clean_tree()])))
            with open(bad, "wb") as handle:
                handle.write(_json(_model([_tree([1, -1, -1], [2, -1, -1],
                                                 splits=[7, 0, 0])])))
            self.assertEqual(xs.scan_file(clean), [])
            self.assertEqual(_rules(xs.scan_file(bad)), ["XGB002"])
            self.assertEqual(xs.main([clean]), 0)
            self.assertEqual(xs.main([clean, bad]), 1)
            self.assertEqual(xs.main([os.path.join(tmp, "nope.json")]), 2)
            self.assertEqual(xs.main([]), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
