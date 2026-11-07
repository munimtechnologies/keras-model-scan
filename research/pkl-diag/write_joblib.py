#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step of job pkl-diag-v1 (no network): write honest files with the real
libraries and record which imports each file really makes.

Usage: python write_joblib.py <out_dir>

Two small scikit-learn RandomForestClassifier models (3 trees, depth 4,
random_state 0) are fitted on synthetic data: one on a pandas DataFrame with
string labels ("No"/"Yes"), one on a numpy array with integer labels.

  J1  joblib.dump(model_df)                  default settings
  J2  joblib.dump(model_np)                  default settings
  J3  joblib.dump(model_df, compress=3)      zlib
  J4  pickle.dump(model_df, protocol=5)      plain pickle (control)

Ground truth: these are our own honest files, so we load each one back
(joblib.load, or pickle's pure-Python Unpickler for J4) with
pickle._Unpickler.find_class wrapped to record every (module, name) the
outer pickle stream imports. joblib's unpickler subclasses pickle._Unpickler.
Writes <out>/files/written/*.pkl and <out>/work/ground_truth.json. Catches its
own errors and always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import pickle
import sys
import traceback


def main(out_dir):
    files_dir = os.path.join(out_dir, "files", "written")
    work_dir = os.path.join(out_dir, "work")
    os.makedirs(files_dir, exist_ok=True)
    os.makedirs(work_dir, exist_ok=True)
    report = {"versions": {}, "files": {}, "errors": []}
    try:
        import joblib
        import numpy as np
        import pandas as pd
        import sklearn
        from sklearn.ensemble import RandomForestClassifier
        report["versions"] = {"joblib": joblib.__version__,
                              "numpy": np.__version__,
                              "pandas": pd.__version__,
                              "sklearn": sklearn.__version__,
                              "python": sys.version.split()[0],
                              "pickle_default_protocol":
                                  pickle.DEFAULT_PROTOCOL}
        rng = np.random.default_rng(0)
        X = rng.normal(size=(200, 4))
        y_int = (X[:, 0] + X[:, 1] > 0).astype(int)
        y_str = np.where(y_int == 1, "Yes", "No")
        df = pd.DataFrame(X, columns=["tenure", "monthly", "total", "age"])
        params = dict(n_estimators=3, max_depth=4, random_state=0)
        model_df = RandomForestClassifier(**params).fit(df, y_str)
        model_np = RandomForestClassifier(**params).fit(X, y_int)
    except Exception:
        report["errors"].append(traceback.format_exc()[-1500:])
        _write(work_dir, report)
        return 0

    plan = [
        ("j1_df_str.pkl", "joblib", lambda p: joblib.dump(model_df, p)),
        ("j2_np_int.pkl", "joblib", lambda p: joblib.dump(model_np, p)),
        ("j3_df_str_z3.pkl", "joblib",
         lambda p: joblib.dump(model_df, p, compress=3)),
        ("j4_df_str_p5.pkl", "pickle", lambda p: _pickle_dump(model_df, p)),
    ]
    for name, kind, writer in plan:
        path = os.path.join(files_dir, name)
        entry = {"kind": kind}
        try:
            writer(path)
            with open(path, "rb") as fh:
                head = fh.read(4)
            entry["bytes"] = os.path.getsize(path)
            entry["magic"] = head.hex()
            entry["imports"] = _record_imports(path, kind)
            entry["distinct_imports"] = sorted(set(entry["imports"]))
        except Exception:
            entry["error"] = traceback.format_exc()[-1500:]
        report["files"][name] = entry
    _write(work_dir, report)
    print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "imports"}
                      for k, v in report["files"].items()}, indent=1))
    return 0


def _pickle_dump(obj, path):
    with open(path, "wb") as fh:
        pickle.dump(obj, fh, protocol=5)


def _record_imports(path, kind):
    seen = []
    original = pickle._Unpickler.find_class

    def recording(self, module, name):
        seen.append("%s %s" % (module, name))
        return original(self, module, name)

    pickle._Unpickler.find_class = recording
    try:
        if kind == "joblib":
            import joblib
            joblib.load(path)
        else:
            with open(path, "rb") as fh:
                pickle._Unpickler(fh).load()
    finally:
        pickle._Unpickler.find_class = original
    return seen


def _write(work_dir, report):
    with open(os.path.join(work_dir, "ground_truth.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/out"))
    except Exception:
        traceback.print_exc()
        sys.exit(0)
