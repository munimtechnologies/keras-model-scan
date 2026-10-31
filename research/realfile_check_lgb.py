#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check for lightgbm_model_scan (research/PREREG_LGB_REALFILE.md).

Trains eight small models with lightgbm on seeded random data, saves each as
text and scans it (P1). Then edits copies of the binary and categorical
models as the pre-registration says (P2-P9) and scans those. Edited files are
only scanned; nothing edited is loaded in lightgbm. Writes
OUT/realfile_summary.json and the honest files under OUT/files/.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in (os.path.join(HERE, "..", "..", "ship", "lgb"), HERE):
    if os.path.exists(os.path.join(candidate, "lightgbm_model_scan.py")):
        sys.path.insert(0, candidate)
        break

import json  # noqa: E402

import lightgbm as lgb  # noqa: E402
import numpy as np  # noqa: E402
import lightgbm_model_scan as ls  # noqa: E402

BASE = {"verbose": -1, "seed": 0, "deterministic": True,
        "force_row_wise": True, "num_leaves": 15, "min_data_in_leaf": 10}

# name, extra parameters, data kind, save_model keyword arguments
CONFIGS = [
    ("binary", {"objective": "binary"}, "plain", {}),
    ("multiclass", {"objective": "multiclass", "num_class": 3}, "multi", {}),
    ("categorical", {"objective": "binary", "max_cat_to_onehot": 2},
     "categorical", {}),
    ("linear", {"objective": "regression", "linear_tree": True}, "regress",
     {}),
    ("dart", {"objective": "binary", "boosting": "dart", "drop_rate": 0.2},
     "plain", {}),
    ("rf", {"objective": "binary", "boosting": "rf", "bagging_fraction": 0.7,
            "bagging_freq": 1, "feature_fraction": 0.8}, "plain", {}),
    ("missing", {"objective": "binary", "use_missing": True}, "missing", {}),
    ("from-iteration-2", {"objective": "binary"}, "plain",
     {"start_iteration": 2}),
]


def _data(kind):
    rng = np.random.default_rng(0)
    x = rng.normal(size=(600, 6))
    categorical = "auto"
    if kind == "multi":
        y = (x[:, 1] > 0.5).astype(int) + (x[:, 2] > 0).astype(int)
    elif kind == "regress":
        y = 2.0 * x[:, 1] - x[:, 2] + rng.normal(scale=0.1, size=600)
    elif kind == "categorical":
        x[:, 0] = rng.integers(0, 10, size=600)
        y = (np.isin(x[:, 0], [1, 3, 4, 8]) ^ (x[:, 2] > 0)).astype(int)
        categorical = [0]
    else:
        if kind == "missing":
            x[rng.random(600) < 0.2, 1] = np.nan
        y = (np.nan_to_num(x[:, 1]) + x[:, 2] > 0.3).astype(int)
    return lgb.Dataset(x, label=y, categorical_feature=categorical,
                       free_raw_data=False)


def _rules(findings):
    return sorted(set(f["rule"] for f in findings))


def _scan(text, name):
    findings = ls.scan_bytes(text.encode("utf-8"), name)
    return _rules(findings), [f["evidence"] for f in findings]


def _blocks(text):
    """(head, tree blocks, tail): head ends where the first 'Tree=' line
    starts, tail starts at 'end of trees'."""
    first = text.index("\nTree=") + 1
    end = text.index("\nend of trees") + 1
    body = text[first:end]
    starts = [m.start() for m in re.finditer(r"(?m)^Tree=", body)]
    blocks = [body[a:b] for a, b in zip(starts, starts[1:] + [len(body)])]
    return text[:first], blocks, text[end:]


def _join(head, blocks, tail):
    """Reassemble, writing tree_sizes for the (possibly edited) blocks the
    way LightGBM's writer does, so only the intended edit differs."""
    sizes = " ".join(str(len(b.encode("utf-8"))) for b in blocks)
    head = re.sub(r"(?m)^tree_sizes=.*$", "tree_sizes=" + sizes, head, count=1)
    return head + "".join(blocks) + tail


def _get(block, key):
    for line in block.split("\n"):
        if line.startswith(key + "="):
            return line[len(key) + 1:].split(" ")
    return None


def _set(block, key, tokens):
    lines = block.split("\n")
    for i, line in enumerate(lines):
        if line.startswith(key + "="):
            lines[i] = key + "=" + " ".join(tokens)
            return "\n".join(lines)
    return None


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


def _stats(text, stats):
    head, blocks, _ = _blocks(text)
    sizes = re.search(r"(?m)^tree_sizes=(.*)$", head)
    written = sizes.group(1).split(" ") if sizes else []
    stats["files"] += 1
    stats["tree_sizes_match_blocks"] += int(
        written == [str(len(b.encode("utf-8"))) for b in blocks])
    for block in blocks:
        stats["trees"] += 1
        leaves = int(_get(block, "num_leaves")[0])
        stats["single_leaf_trees"] += int(leaves == 1)
        stats["linear_trees"] += int((_get(block, "is_linear") or ["0"])[0]
                                     == "1")
        kinds = _get(block, "decision_type") or []
        for kind in kinds:
            if kind:
                stats["decision_types"][kind] = (
                    stats["decision_types"].get(kind, 0) + 1)
        stats["categorical_splits"] += sum(1 for k in kinds
                                           if k and int(k) & 1)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    args = ap.parse_args(argv)
    files = os.path.join(args.out, "files")
    os.makedirs(files, exist_ok=True)
    rows = []
    stats = {"files": 0, "trees": 0, "single_leaf_trees": 0,
             "linear_trees": 0, "categorical_splits": 0,
             "tree_sizes_match_blocks": 0, "decision_types": {},
             "not_read": []}
    honest = {}

    # P1: honest files.
    p1 = []
    for name, params, kind, save in CONFIGS:
        path = os.path.join(files, "%s.txt" % name)
        try:
            booster = lgb.train(dict(BASE, **params), _data(kind),
                                num_boost_round=8)
            booster.save_model(path, **save)
            with open(path, "rb") as handle:
                honest[name] = handle.read().decode("utf-8")
        except Exception as exc:
            p1.append({"config": name, "result": "NOT RUN",
                       "reason": "%s: %s" % (type(exc).__name__, exc)})
            continue
        try:
            _stats(honest[name], stats)
        except Exception as exc:  # the counts are reported, not predicted
            stats["not_read"].append("%s: %s" % (name, exc))
        findings = ls.scan_bytes(honest[name].encode("utf-8"), name + ".txt")
        p1.append({"config": name, "file": name + ".txt",
                   "bytes": len(honest[name]),
                   "rules": _rules(findings),
                   "evidence": [f["evidence"] for f in findings],
                   "result": "PASS" if not findings else "FAIL"})
    ran = [r for r in p1 if r["result"] != "NOT RUN"]
    rows.append({"id": "P1", "case": "8 honest files", "expected": [],
                 "files": p1,
                 "result": ("NOT RUN" if not ran else
                            "PASS" if all(r["result"] == "PASS" for r in ran)
                            and len(ran) == len(CONFIGS) else
                            "FAIL" if any(r["result"] == "FAIL" for r in ran)
                            else "PARTIAL")})

    def tree0(change, model="binary"):
        """Edit tree 0 of a model, rewrite tree_sizes, scan the result."""
        if model not in honest:
            return "%s model was not written" % model
        head, blocks, tail = _blocks(honest[model])
        edited = change(blocks[0])
        if isinstance(edited, str) and not edited.startswith("Tree="):
            return edited
        if edited is None:
            return "key not found in tree 0"
        blocks = [edited] + blocks[1:]
        return _scan(_join(head, blocks, tail), "edited.txt")

    def p2(block):
        tokens = _get(block, "left_child")
        if not tokens or not tokens[0]:
            return "tree 0 has no split"
        return _set(block, "left_child", ["9999"] + tokens[1:])

    def p3(block):
        tokens = _get(block, "split_feature")
        head = _blocks(honest["binary"])[0]
        top = int(re.search(r"(?m)^max_feature_idx=(\d+)$", head).group(1))
        if not tokens or not tokens[0]:
            return "tree 0 has no split"
        return _set(block, "split_feature", [str(top + 3)] + tokens[1:])

    def p4(block):
        for key in ("left_child", "right_child"):
            tokens = _get(block, key) or []
            for i, token in enumerate(tokens):
                if token and int(token) > 0:
                    tokens[i] = "0"
                    return _set(block, key, tokens)
        return "tree 0 has only one split node"

    def p5(block):
        leaves = int(_get(block, "num_leaves")[0])
        tokens = _get(block, "right_child") or []
        for i, token in enumerate(tokens):
            if token and int(token) < 0:
                tokens[i] = str(-(leaves + 1))
                return _set(block, "right_child", tokens)
        return "tree 0 has no right child that is a leaf"

    def p9(block):
        tokens = _get(block, "left_child")
        if not tokens or not tokens[0]:
            return "tree 0 has no split"
        return _set(block, "left_child", tokens[:-1])

    _row(rows, "P2", "tree 0 left_child[0] = 9999", ["LGB001"],
         lambda: tree0(p2))
    _row(rows, "P3", "tree 0 split_feature[0] = max_feature_idx + 3",
         ["LGB002"], lambda: tree0(p3))
    _row(rows, "P4", "tree 0: first child that is a split node set to 0 "
         "(the root)", ["LGB003"], lambda: tree0(p4))
    _row(rows, "P5", "tree 0: first right child that is a leaf set to "
         "leaf num_leaves", ["LGB001"], lambda: tree0(p5))

    def p6():
        if "categorical" not in honest:
            return "categorical model was not written"
        head, blocks, tail = _blocks(honest["categorical"])
        for t, block in enumerate(blocks):
            kinds = _get(block, "decision_type") or []
            for i, kind in enumerate(kinds):
                if kind and int(kind) & 1:
                    cats = int(_get(block, "num_cat")[0])
                    tokens = _get(block, "threshold")
                    tokens[i] = str(cats + 5)
                    blocks[t] = _set(block, "threshold", tokens)
                    return _scan(_join(head, blocks, tail), "edited.txt")
        return "no categorical split in the categorical model"

    def p7():
        if "binary" not in honest:
            return "binary model was not written"
        head, blocks, tail = _blocks(honest["binary"])
        if len(blocks) < 2:
            return "fewer than 2 trees"
        sizes = re.search(r"(?m)^tree_sizes=(.*)$", head)
        if not sizes:
            return "no tree_sizes line"
        tokens = sizes.group(1).split(" ")
        tokens[0] = "1000000000"
        head = (head[:sizes.start(1)] + " ".join(tokens)
                + head[sizes.end(1):])
        return _scan(head + "".join(blocks) + tail, "edited.txt")

    def p8():
        if "binary" not in honest:
            return "binary model was not written"
        text = honest["binary"]
        if "\nmax_feature_idx=" not in text:
            return "no max_feature_idx line"
        text = text.replace("\nmax_feature_idx=",
                            "\nmax_feature_idx=1\nmax_feature_idx=", 1)
        return _scan(text, "edited.txt")

    _row(rows, "P6", "categorical model: first categorical split's "
         "threshold = num_cat + 5", ["LGB001"], p6)
    _row(rows, "P7", "binary model: first tree_sizes value = 10^9",
         ["LGB004"], p7)
    _row(rows, "P8", "binary model: a second max_feature_idx line in front "
         "of the real one", ["LGB005"], p8)
    _row(rows, "P9", "tree 0 left_child with its last value removed",
         ["LGB003", "LGB006"], lambda: tree0(p9))

    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    summary = {
        "lightgbm": lgb.__version__, "numpy": np.__version__,
        "scanner": ls.__version__,
        "held": sum(1 for r in graded if r["result"] == "PASS"),
        "graded": len(graded),
        "not_run": [r["id"] for r in rows if r["result"] == "NOT RUN"],
        "honest_stats": stats,
        "rows": rows,
    }
    with open(os.path.join(args.out, "realfile_summary.json"), "w",
              encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1)
    for r in rows:
        print(r["id"], r["result"], r.get("rules", ""), r.get("reason", ""))
    print("honest stats:", json.dumps(stats))
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
