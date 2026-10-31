#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check for xgboost_model_scan (research/PREREG_XGB_REALFILE.md).

Trains six small models with xgboost on seeded random data, saves each as
.json and .ubj and scans them (P1). Then edits copies of the first model's
files as the pre-registration says (P2-P7) and scans those. Edited files are
only scanned; nothing edited is loaded in xgboost. Writes
OUT/realfile_summary.json and the honest files under OUT/files/.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import copy
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in (os.path.join(HERE, "..", "..", "ship", "xgb"), HERE):
    if os.path.exists(os.path.join(candidate, "xgboost_model_scan.py")):
        sys.path.insert(0, candidate)
        break

import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402
import xgboost_model_scan as xs  # noqa: E402

CONFIGS = [
    ("binary-hist", {"objective": "binary:logistic", "tree_method": "hist",
                     "max_depth": 4}, False),
    ("multiclass", {"objective": "multi:softprob", "num_class": 3,
                    "tree_method": "hist", "max_depth": 3}, False),
    ("dart", {"objective": "binary:logistic", "booster": "dart",
              "rate_drop": 0.1, "max_depth": 3}, False),
    ("categorical", {"objective": "binary:logistic", "tree_method": "hist",
                     "max_cat_to_onehot": 1, "max_depth": 3}, True),
    ("pruned", {"objective": "binary:logistic", "tree_method": "hist",
                "max_depth": 6, "gamma": 2.0}, False),
    ("exact", {"objective": "binary:logistic", "tree_method": "exact",
               "max_depth": 4}, False),
]


def _matrix(params, categorical):
    rng = np.random.default_rng(0)
    x = rng.normal(size=(400, 6)).astype(np.float32)
    if categorical:
        x[:, 0] = rng.integers(0, 6, size=400)
        y = (np.isin(x[:, 0], [1, 3, 4]) ^ (x[:, 2] > 0)).astype(int)
        return xgb.DMatrix(x, label=y, feature_types=["c"] + ["q"] * 5,
                           enable_categorical=True)
    if params.get("num_class"):
        y = (x[:, 1] > 0.5).astype(int) + (x[:, 2] > 0).astype(int)
    else:
        y = (x[:, 1] + x[:, 2] > 0.3).astype(int)
    return xgb.DMatrix(x, label=y)


def _rules(findings):
    return sorted(set(f["rule"] for f in findings))


def _trees(doc):
    gb = doc["learner"]["gradient_booster"]
    if gb.get("name") == "dart":
        gb = gb["gbtree"]
    return gb["model"]["trees"]


def _node_stats(doc, stats):
    try:
        trees = _trees(doc)
    except (KeyError, TypeError):
        stats["layout_not_read"] += 1
        return
    for tree in trees:
        for left, right in zip(tree["left_children"], tree["right_children"]):
            if left != -1:
                stats["split_nodes"] += 1
                stats["right_is_left_plus_one"] += int(right == left + 1)


def _row(rows, case_id, case, expected, func):
    row = {"id": case_id, "case": case, "expected": expected}
    try:
        got = func()
    except Exception as exc:  # pre-registered: an API error is "not run"
        row.update({"result": "NOT RUN",
                    "reason": "%s: %s" % (type(exc).__name__, exc)})
        rows.append(row)
        return
    if isinstance(got, str):
        row.update({"result": "NOT RUN", "reason": got})
    else:
        rules, evidence = got
        row.update({"rules": rules, "evidence": evidence,
                    "result": "PASS" if rules == expected else "FAIL"})
    rows.append(row)


def _scan(data, name):
    findings = xs.scan_bytes(data, name)
    return _rules(findings), [f["evidence"] for f in findings]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    args = ap.parse_args(argv)
    files = os.path.join(args.out, "files")
    os.makedirs(files, exist_ok=True)
    rows = []
    stats = {"split_nodes": 0, "right_is_left_plus_one": 0,
             "layout_not_read": 0}
    honest = {}

    # P1: honest files.
    p1 = []
    for name, params, categorical in CONFIGS:
        try:
            booster = xgb.train(dict(params, seed=0),
                                _matrix(params, categorical),
                                num_boost_round=8)
            for ext in ("json", "ubj"):
                path = os.path.join(files, "%s.%s" % (name, ext))
                booster.save_model(path)
                with open(path, "rb") as handle:
                    honest[(name, ext)] = handle.read()
        except Exception as exc:
            p1.append({"config": name, "result": "NOT RUN",
                       "reason": "%s: %s" % (type(exc).__name__, exc)})
            continue
        _node_stats(json.loads(honest[(name, "json")].decode("utf-8")), stats)
        for ext in ("json", "ubj"):
            findings = xs.scan_bytes(honest[(name, ext)], "%s.%s" % (name, ext))
            p1.append({"config": name, "file": "%s.%s" % (name, ext),
                       "bytes": len(honest[(name, ext)]),
                       "rules": _rules(findings),
                       "evidence": [f["evidence"] for f in findings],
                       "result": "PASS" if not findings else "FAIL"})
    ran = [r for r in p1 if r["result"] != "NOT RUN"]
    rows.append({"id": "P1", "case": "12 honest files", "expected": [],
                 "files": p1,
                 "result": ("NOT RUN" if not ran else
                            "PASS" if all(r["result"] == "PASS" for r in ran)
                            and len(ran) == 12 else
                            "FAIL" if any(r["result"] == "FAIL" for r in ran)
                            else "PARTIAL")})

    base_json = honest.get(("binary-hist", "json"))
    base_ubj = honest.get(("binary-hist", "ubj"))
    doc = json.loads(base_json.decode("utf-8")) if base_json else None

    def edited(change):
        if doc is None:
            return "binary-hist model was not written"
        d = copy.deepcopy(doc)
        tree = _trees(d)[0]
        problem = change(d, tree)
        if problem:
            return problem
        return _scan(json.dumps(d).encode("utf-8"), "edited.json")

    def p2(d, tree):
        tree["left_children"][0] = 99999

    def p3(d, tree):
        tree["split_indices"][0] = int(
            d["learner"]["learner_model_param"]["num_feature"]) + 3

    def p4(d, tree):
        left = tree["left_children"][0]
        if left + 2 >= len(tree["left_children"]):
            return "left child + 2 is not a node"
        tree["right_children"][0] = left + 2

    def p5(d, tree):
        k = tree["left_children"][0]
        if k < 0 or tree["left_children"][k] == -1:
            return "node k is a leaf"
        tree["left_children"][k] = 0
        tree["right_children"][k] = 1

    _row(rows, "P2", "root left child 99999", ["XGB001"], lambda: edited(p2))
    _row(rows, "P3", "root feature num_feature + 3", ["XGB002"],
         lambda: edited(p3))
    _row(rows, "P4", "root right child = left + 2", ["XGB006"],
         lambda: edited(p4))
    _row(rows, "P5", "root's left child points back to the root",
         ["XGB003", "XGB006"], lambda: edited(p5))

    def p6():
        if base_ubj is None:
            return "binary-hist model was not written"
        data = bytearray(base_ubj)
        if bytes(data[:2]) != b"{L":
            return "UBJ file does not start with an object key"
        data[2:10] = struct.pack(">q", 2 ** 40)
        return _scan(bytes(data), "edited.ubj")

    def p7_ubj():
        if base_ubj is None:
            return "binary-hist model was not written"
        extra = (b"L" + struct.pack(">q", 7) + b"version" + b"[$l#L"
                 + struct.pack(">q", 3) + struct.pack(">3i", 9, 9, 9))
        return _scan(base_ubj[:1] + extra + base_ubj[1:], "edited.ubj")

    def p7_json():
        if base_json is None:
            return "binary-hist model was not written"
        text = base_json.decode("utf-8")
        if not text.startswith('{"learner"'):
            return "JSON does not start with {\"learner\""
        text = '{"version": [9, 9, 9], ' + text[1:]
        return _scan(text.encode("utf-8"), "edited.json")

    _row(rows, "P6", "UBJ first key length 2^40", ["XGB005"], p6)
    _row(rows, "P7-ubj", "UBJ duplicate version key", ["XGB004"], p7_ubj)
    _row(rows, "P7-json", "JSON duplicate version key", ["XGB004"], p7_json)

    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    summary = {
        "xgboost": xgb.__version__, "numpy": np.__version__,
        "scanner": xs.__version__,
        "held": sum(1 for r in graded if r["result"] == "PASS"),
        "graded": len(graded),
        "not_run": [r["id"] for r in rows if r["result"] == "NOT RUN"],
        "honest_split_nodes": stats,
        "rows": rows,
    }
    with open(os.path.join(args.out, "realfile_summary.json"), "w",
              encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1)
    for r in rows:
        print(r["id"], r["result"], r.get("rules", ""), r.get("reason", ""))
    print("split nodes:", stats)
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
