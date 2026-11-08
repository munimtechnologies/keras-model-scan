#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step of job pkl-joblib-v1 (no network): write honest files with the
real libraries and record which imports each file really makes.

Usage: python write_jl.py <out_dir>

Objects (fitted on synthetic data, random_state 0):
  rf_df    RandomForestClassifier(3 trees, depth 4) on a pandas DataFrame,
           string labels "No"/"Yes" (object arrays inside)
  rf_np    the same on a numpy array, integer labels
  text     Pipeline(TfidfVectorizer, LogisticRegression), str labels
  hgb      Pipeline(StandardScaler, HistGradientBoostingClassifier)
  frame    a pandas DataFrame: float, int, bool, str, datetime, category
  zoo      a dict of numpy arrays: float16, complex128, big-endian int32,
           bool, unicode, bytes, structured (numeric, and with an object
           field), object, 0-d, empty, Fortran order, matrix, datetime64[ms],
           timedelta64, int8; plus a scipy.sparse CSR matrix

Files: joblib.dump at its defaults for each object; rf_df also with
compress 3 (zlib), gzip, bz2, xz and lzma, and at pickle protocols 2, 3, 4
and 5; zoo also through a file object without tell() (joblib then writes
no alignment padding); rf_df and zoo also with plain pickle.dump, protocol
5 (controls with no joblib arrays).

Ground truth: these are our own honest files, so each is loaded back
(joblib.load, or pickle's pure-Python Unpickler for the plain pickles) with
pickle._Unpickler.find_class wrapped to record every (module, name) looked
up, in order. joblib 1.6.0's unpickler subclasses pickle._Unpickler and
routes the nested object-array unpickler's find_class through it. Writes
<out>/files/written/* and <out>/work/ground_truth.json. Catches its own
errors and always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import os
import pickle
import sys
import traceback


class NoTell(object):
    """A write-only file object without tell(), like a pipe."""

    def __init__(self, fh):
        self._fh = fh

    def write(self, b):
        return self._fh.write(b)

    def tell(self):
        raise io.UnsupportedOperation("tell")

    def flush(self):
        self._fh.flush()


def build_objects():
    import numpy as np
    import pandas as pd
    from scipy import sparse
    from sklearn.ensemble import (HistGradientBoostingClassifier,
                                  RandomForestClassifier)
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    rng = np.random.default_rng(0)
    X = rng.normal(size=(200, 4))
    y_int = (X[:, 0] + X[:, 1] > 0).astype(int)
    y_str = np.where(y_int == 1, "Yes", "No")
    df = pd.DataFrame(X, columns=["tenure", "monthly", "total", "age"])
    rf = dict(n_estimators=3, max_depth=4, random_state=0)
    objs = {}
    objs["rf_df"] = RandomForestClassifier(**rf).fit(df, y_str)
    objs["rf_np"] = RandomForestClassifier(**rf).fit(X, y_int)
    docs = ["good model file", "bad pickle file", "safe tensors here",
            "unsafe reduce call", "model card text", "plain text file"] * 5
    labels = ["ham", "spam", "ham", "spam", "ham", "ham"] * 5
    objs["text"] = Pipeline([("tfidf", TfidfVectorizer()),
                             ("clf", LogisticRegression(max_iter=200))]
                            ).fit(docs, labels)
    objs["hgb"] = Pipeline([("sc", StandardScaler()),
                            ("hgb", HistGradientBoostingClassifier(
                                max_iter=5, random_state=0))]).fit(X, y_int)
    n = 6
    objs["frame"] = pd.DataFrame({
        "f": np.linspace(0, 1, n), "i": np.arange(n, dtype=np.int64),
        "b": np.array([True, False] * 3),
        "s": ["a", "bb", "ccc", "d", "ee", "f"],
        "t": pd.date_range("2026-01-01", periods=n, freq="D"),
        "c": pd.Categorical(["x", "y", "x", "z", "y", "x"]),
    })
    structured = np.zeros(3, dtype=[("a", "<f8"), ("b", "<i4")])
    with_obj = np.empty(2, dtype=[("name", "O"), ("w", "<f8")])
    with_obj[0] = ("first", 1.0)
    with_obj[1] = ("second", 2.0)
    objs["zoo"] = {
        "f16": np.arange(5, dtype=np.float16),
        "c128": np.array([1 + 2j, 3 - 4j]),
        "be_i4": np.arange(4, dtype=">i4"),
        "bool": np.array([True, False, True]),
        "uni": np.array(["alpha", "be", "gamma7"]),
        "byt": np.array([b"ab", b"cde"]),
        "struct": structured,
        "struct_obj": with_obj,
        "obj": np.array([1, "two", (3,), None], dtype=object),
        "zero_d": np.array(3.5),
        "empty": np.zeros((0, 3)),
        "fortran": np.asfortranarray(np.arange(6.0).reshape(2, 3)),
        "matrix": np.matrix([[1.0, 2.0], [3.0, 4.0]]),
        "dt_ms": np.array(["2026-11-08T12:00"], dtype="datetime64[ms]"),
        "td": np.array([1, 2], dtype="timedelta64[s]"),
        "i8": np.array([-1], dtype=np.int8),
        "csr": sparse.csr_matrix(np.eye(3)),
    }
    return objs


def plan(objs):
    import joblib
    rf_df = objs["rf_df"]
    out = [
        ("rf_df.joblib", "joblib", lambda p: joblib.dump(rf_df, p)),
        ("rf_np.joblib", "joblib", lambda p: joblib.dump(objs["rf_np"], p)),
        ("text.joblib", "joblib", lambda p: joblib.dump(objs["text"], p)),
        ("hgb.joblib", "joblib", lambda p: joblib.dump(objs["hgb"], p)),
        ("frame.joblib", "joblib", lambda p: joblib.dump(objs["frame"], p)),
        ("zoo.joblib", "joblib", lambda p: joblib.dump(objs["zoo"], p)),
        ("rf_df_z3.joblib", "joblib",
         lambda p: joblib.dump(rf_df, p, compress=3)),
    ]
    for method in ("gzip", "bz2", "xz", "lzma"):
        out.append(("rf_df_%s.joblib" % method, "joblib",
                    lambda p, m=method: joblib.dump(rf_df, p,
                                                    compress=(m, 3))))
    for proto in (2, 3, 4, 5):
        out.append(("rf_df_p%d.joblib" % proto, "joblib",
                    lambda p, k=proto: joblib.dump(rf_df, p, protocol=k)))
    out.append(("zoo_notell.joblib", "joblib", _dump_notell(objs["zoo"])))
    out.append(("rf_df_plain_p5.pkl", "pickle", _pickle_dump(rf_df)))
    out.append(("zoo_plain_p5.pkl", "pickle", _pickle_dump(objs["zoo"])))
    return out


def _dump_notell(obj):
    def write(path):
        import joblib
        with open(path, "wb") as fh:
            joblib.dump(obj, NoTell(fh))
    return write


def _pickle_dump(obj):
    def write(path):
        with open(path, "wb") as fh:
            pickle.dump(obj, fh, protocol=5)
    return write


def record_imports(path, kind):
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
        import scipy
        import sklearn
        report["versions"] = {"joblib": joblib.__version__,
                              "numpy": np.__version__,
                              "pandas": pd.__version__,
                              "scipy": scipy.__version__,
                              "sklearn": sklearn.__version__,
                              "python": sys.version.split()[0],
                              "pickle_default_protocol":
                                  pickle.DEFAULT_PROTOCOL}
        objs = build_objects()
        steps = plan(objs)
    except Exception:
        report["errors"].append(traceback.format_exc()[-2000:])
        _write(work_dir, report)
        return 0
    report["planned"] = [name for name, _k, _w in steps]
    for name, kind, writer in steps:
        path = os.path.join(files_dir, name)
        entry = {"kind": kind}
        try:
            writer(path)
            with open(path, "rb") as fh:
                head = fh.read(6)
            entry["bytes"] = os.path.getsize(path)
            entry["magic"] = head.hex()
            entry["imports"] = record_imports(path, kind)
            entry["distinct_imports"] = sorted(set(entry["imports"]))
        except Exception:
            entry["error"] = traceback.format_exc()[-1500:]
        report["files"][name] = entry
    _write(work_dir, report)
    print(json.dumps({k: {kk: vv for kk, vv in v.items()
                          if kk not in ("imports", "distinct_imports")}
                      for k, v in report["files"].items()}, indent=1))
    return 0


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
