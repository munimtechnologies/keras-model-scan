#!/usr/bin/env python3
# Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""Pre-registered check (research/PREREG_MFS_TREE_ROUTING.md): does
model-file-scan 0.10.0 send files written by XGBoost and LightGBM to the
right scanner, keep a pickled booster on the pickle scanner, and leave honest
files clean?

Run from the job's work folder. model_file_scan.py and its tests come from
ship/unified (this run); every other scanner module was downloaded from the
repository's main branch into lib/ during setup. Nothing written here is
loaded back into XGBoost or LightGBM; the pickle is only written and scanned.
"""

import argparse
import contextlib
import copy
import io
import json
import os
import pickle
import shutil
import sys
import unittest

WORK = os.getcwd()
sys.path[:0] = [os.path.join(WORK, "ship", "unified"), os.path.join(WORK, "lib")]

import numpy as np  # noqa: E402

import model_file_scan as mfs  # noqa: E402


def _rules(findings):
    return sorted(set(mfs._as_dict(f)["rule"] for f in findings))


def _quiet_main(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = mfs.main(args)
    return code, out.getvalue(), err.getvalue()


def build(clean, extra):
    import lightgbm as lgb
    import xgboost as xgb

    rng = np.random.default_rng(7)
    X = rng.normal(size=(400, 6))
    y = (X[:, 0] + X[:, 1] > 0).astype(int)

    booster = xgb.train({"objective": "binary:logistic", "max_depth": 3,
                         "tree_method": "hist"},
                        xgb.DMatrix(X, label=y), num_boost_round=6)
    booster.save_model(os.path.join(clean, "xgb.json"))
    booster.save_model(os.path.join(clean, "xgb.ubj"))
    with open(os.path.join(clean, "xgb.ubj"), "rb") as fh:
        ubj = fh.read()
    with open(os.path.join(clean, "xgb.json"), "rb") as fh:
        js = fh.read()
    with open(os.path.join(clean, "xgb-ubj.model"), "wb") as fh:
        fh.write(ubj)
    with open(os.path.join(clean, "xgb-json.bst"), "wb") as fh:
        fh.write(js)

    gbm = lgb.train({"objective": "binary", "num_leaves": 7, "verbose": -1},
                    lgb.Dataset(X, label=y), num_boost_round=6)
    gbm.save_model(os.path.join(clean, "lgb.txt"))
    with open(os.path.join(clean, "lgb.txt"), "rb") as fh:
        text = fh.read()
    for name in ("lgb.lgb", "lgb-text.model"):
        with open(os.path.join(clean, name), "wb") as fh:
            fh.write(text)

    with open(os.path.join(extra, "xgb-pickled.model"), "wb") as fh:
        fh.write(pickle.dumps(booster))

    doc = json.loads(js.decode("utf-8"))
    edited = copy.deepcopy(doc)
    tree = edited["learner"]["gradient_booster"]["model"]["trees"][0]
    tree["left_children"][0] = 99999
    with open(os.path.join(extra, "edited.json"), "w") as fh:
        json.dump(edited, fh)

    return {"xgboost": xgb.__version__, "lightgbm": lgb.__version__,
            "numpy": np.__version__}


EXPECTED_KINDS = {
    "xgb.json": ["xgboost"],
    "xgb.ubj": ["xgboost"],
    "xgb-ubj.model": ["xgboost"],
    "xgb-json.bst": ["xgboost"],
    "lgb.txt": ["lightgbm"],
    "lgb.lgb": ["lightgbm"],
    "lgb-text.model": ["lightgbm"],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    root = os.path.join(args.out, "files")
    clean = os.path.join(root, "clean")
    extra = os.path.join(root, "extra")
    for d in (clean, extra):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)

    rows = []
    summary = {"model_file_scan": mfs.__version__, "rows": rows}
    try:
        summary.update(build(clean, extra))
    except Exception as exc:  # the libraries could not build the files
        summary["not_run"] = "build failed: %s: %s" % (type(exc).__name__, exc)
        print(summary["not_run"])
        with open(os.path.join(args.out, "route_summary.json"), "w") as fh:
            json.dump(summary, fh, indent=1)
        return 0

    # R1 routing, R2 clean scans
    kinds = {n: mfs.route_kinds(os.path.join(clean, n)) for n in EXPECTED_KINDS}
    rows.append({"id": "R1", "expected": EXPECTED_KINDS, "got": kinds,
                 "result": "PASS" if kinds == EXPECTED_KINDS else "FAIL"})
    found = {n: _rules(mfs.scan_path(os.path.join(clean, n)))
             for n in EXPECTED_KINDS}
    rows.append({"id": "R2", "expected": "no findings on any file",
                 "got": found,
                 "result": "PASS" if not any(found.values()) else "FAIL"})
    pk = os.path.join(extra, "xgb-pickled.model")
    pk_kinds = mfs.route_kinds(pk)
    rows.append({"id": "R3", "expected": ["pickle"], "got": pk_kinds,
                 "pickle_rules": _rules(mfs.scan_path(pk)),
                 "result": "PASS" if pk_kinds == ["pickle"] else "FAIL"})
    # A directory walk does not pick up .bst (by design); explicit paths do.
    walk_expected = sorted(n for n in EXPECTED_KINDS if not n.endswith(".bst"))
    walked, missing = mfs.expand_paths([clean])
    names = sorted(os.path.basename(p) for p in walked)
    rows.append({"id": "R4", "expected": walk_expected, "got": names,
                 "result": "PASS" if names == walk_expected
                 and not missing else "FAIL"})
    code, _out, err = _quiet_main([clean, "--fail-on", "medium"])
    rows.append({"id": "R5", "expected": 0, "got": code, "stderr": err[-400:],
                 "result": "PASS" if code == 0 else "FAIL"})
    ed = os.path.join(extra, "edited.json")
    ed_rules = _rules(mfs.scan_path(ed))
    code, _out, _err = _quiet_main([ed, "--fail-on", "high"])
    rows.append({"id": "R6", "expected": {"kinds": ["xgboost"],
                                          "rules": ["XGB001"], "exit": 1},
                 "got": {"kinds": mfs.route_kinds(ed), "rules": ed_rules,
                         "exit": code},
                 "result": "PASS" if (mfs.route_kinds(ed) == ["xgboost"]
                                      and ed_rules == ["XGB001"]
                                      and code == 1) else "FAIL"})

    os.chdir(os.path.join(WORK, "ship", "unified"))
    import test_model_file_scan
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_model_file_scan)
    stream = io.StringIO()
    res = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    sys.stderr.write(stream.getvalue())
    rows.append({"id": "R7", "expected": "all pass, none skipped",
                 "got": {"run": res.testsRun, "failures": len(res.failures),
                         "errors": len(res.errors),
                         "skipped": len(res.skipped)},
                 "result": "PASS" if res.wasSuccessful() and not res.skipped
                 else "FAIL"})

    held = sum(r["result"] == "PASS" for r in rows)
    summary["held"] = held
    summary["graded"] = len(rows)
    for r in rows:
        print(r["id"], r["result"], json.dumps(r["got"])[:300])
    print("held %d of %d" % (held, len(rows)))
    with open(os.path.join(args.out, "route_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
