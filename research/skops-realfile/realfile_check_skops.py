#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Real-file check for skops_scan (research/PREREG_SKOPS_REALFILE.md).

Fits small scikit-learn models on seeded random data, writes each with
skops.io.dump, and scans the files with skops_scan (H1, H2). For each honest
file it also records what skops itself says a user must trust
(skops.io.get_untrusted_types, which reads the schema without loading) and
what the pickle scanner says about the archive (Q1). Then it edits copies of
the LogisticRegression file's schema.json and scans those (K1-K6). Edited
files are only scanned; nothing is ever loaded. No network is used.

Writes OUT/realfile_summary.json and the honest files under OUT/files/.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import argparse
import functools
import json
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
KMS = os.path.join(HERE, "kms")
sys.path.insert(0, KMS)

import numpy as np  # noqa: E402
import joblib  # noqa: E402
import sklearn  # noqa: E402
import skops  # noqa: E402
import skops.io as sio  # noqa: E402
from sklearn.cluster import KMeans  # noqa: E402
from sklearn.compose import ColumnTransformer  # noqa: E402
from sklearn.ensemble import (HistGradientBoostingClassifier,  # noqa: E402
                              RandomForestClassifier)
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.naive_bayes import MultinomialNB  # noqa: E402
from sklearn.neighbors import KNeighborsClassifier  # noqa: E402
from sklearn.neural_network import MLPClassifier  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import (FunctionTransformer,  # noqa: E402
                                   OneHotEncoder, StandardScaler)
from sklearn.svm import SVC  # noqa: E402

import skops_scan as ss  # noqa: E402
import pickle_model_scan as pms  # noqa: E402

LOUD = ("MEDIUM", "HIGH", "CRITICAL")

WORDS = ["model", "file", "scan", "load", "trust", "graph", "weight", "tree",
         "zip", "json", "type", "node"]


def _data():
    rng = np.random.default_rng(0)
    x = rng.normal(size=(120, 4))
    y = (x[:, 0] + x[:, 1] > 0).astype(int)
    xc = x.copy()
    xc[:, 2] = rng.integers(0, 4, size=120)
    texts = [" ".join(rng.choice(WORDS, size=6)) for _ in range(60)]
    ty = np.array([int("trust" in t) for t in texts])
    return x, y, xc, texts, ty


def honest_models():
    x, y, xc, texts, ty = _data()
    return [
        ("logreg", lambda: LogisticRegression().fit(x, y)),
        ("random-forest", lambda: RandomForestClassifier(
            n_estimators=5, random_state=0).fit(x, y)),
        ("scaler-svc", lambda: make_pipeline(StandardScaler(),
                                             SVC()).fit(x, y)),
        ("hist-gb", lambda: HistGradientBoostingClassifier(
            max_iter=10, random_state=0).fit(x, y)),
        ("kmeans", lambda: KMeans(n_clusters=3, n_init=2,
                                  random_state=0).fit(x)),
        ("tfidf-nb", lambda: make_pipeline(TfidfVectorizer(),
                                           MultinomialNB()).fit(texts, ty)),
        ("columns-onehot", lambda: make_pipeline(
            ColumnTransformer([
                ("num", StandardScaler(), [0, 1, 3]),
                ("cat", OneHotEncoder(handle_unknown="ignore"), [2])]),
            LogisticRegression()).fit(xc, y)),
        ("mlp", lambda: MLPClassifier(hidden_layer_sizes=(8,), max_iter=50,
                                      random_state=0).fit(x, y)),
        ("knn", lambda: KNeighborsClassifier(n_neighbors=3).fit(x, y)),
        ("ufunc-transformer", lambda: make_pipeline(
            FunctionTransformer(np.log1p), LogisticRegression()).fit(
                np.abs(x), y)),
    ]


def partial_model():
    x, y = _data()[:2]
    clip = functools.partial(np.clip, a_min=-1.0, a_max=1.0)
    return make_pipeline(FunctionTransformer(clip),
                         LogisticRegression()).fit(x, y)


def _scan(path):
    result = ss.ScanResult()
    ss.scan_file(path, result)
    return result


def _rules(result):
    return sorted(set(f.rule for f in result.findings))


def _types(path):
    with zipfile.ZipFile(path) as zf:
        schema = json.loads(zf.read(ss.SCHEMA_MEMBER).decode("utf-8"))
    return schema, sorted(set(
        "%s | %s.%s" % (n.get("__loader__"), n.get("__module__"),
                        n.get("__class__"))
        for n in ss.iter_nodes(schema)))


def _pickle_view(path):
    out = []
    for f in pms.scan_file(path):
        d = f.as_dict() if hasattr(f, "as_dict") else dict(f)
        out.append((str(d.get("rule")), str(d.get("severity", "")).upper()))
    return out


def _rezip(src, dst, schema=None, drop_schema=False):
    with zipfile.ZipFile(src) as zin, \
            zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            if info.filename == ss.SCHEMA_MEMBER:
                if drop_schema:
                    continue
                if schema is not None:
                    zout.writestr(ss.SCHEMA_MEMBER, json.dumps(schema))
                    continue
            zout.writestr(info, zin.read(info.filename))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/out")
    ap.add_argument("--work", default="/tmp/skops")
    args = ap.parse_args(argv)
    files = os.path.join(args.out, "files")
    shutil.rmtree(args.work, ignore_errors=True)
    os.makedirs(files, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)
    rows = []
    reported = {"untrusted_by_skops": {}, "node_types": {},
                "pickle_scanner": {}}

    def row(case_id, case, expected, func):
        r = {"id": case_id, "case": case, "expected": expected}
        try:
            got = func()
        except Exception as exc:  # pre-registered: an API error is "not run"
            r.update({"result": "NOT RUN",
                      "reason": "%s: %s" % (type(exc).__name__, exc)})
            rows.append(r)
            return
        if isinstance(got, str):
            r.update({"result": "NOT RUN", "reason": got})
        else:
            ok, detail = got
            r.update({"got": detail, "result": "PASS" if ok else "FAIL"})
        rows.append(r)

    # ---- H1: ten honest models ------------------------------------------
    honest = {}
    h1 = []
    for label, fit in honest_models():
        sub = {"model": label}
        path = os.path.join(files, label + ".skops")
        try:
            sio.dump(fit(), path)
        except Exception as exc:
            sub.update({"result": "NOT RUN",
                        "reason": "%s: %s" % (type(exc).__name__, exc)})
            h1.append(sub)
            continue
        honest[label] = path
        result = _scan(path)
        sub.update({"rules": _rules(result),
                    "types": [f.type_ref for f in result.findings][:10],
                    "errors": result.errors,
                    "result": ("PASS" if not result.findings
                               and not result.errors else "FAIL")})
        h1.append(sub)
        try:
            reported["untrusted_by_skops"][label] = sorted(
                sio.get_untrusted_types(file=path))
        except Exception as exc:
            reported["untrusted_by_skops"][label] = "error: %s: %s" % (
                type(exc).__name__, exc)
        try:
            reported["node_types"][label] = _types(path)[1]
        except Exception as exc:
            reported["node_types"][label] = "error: %s" % exc
        try:
            reported["pickle_scanner"][label] = _pickle_view(path)
        except Exception as exc:
            reported["pickle_scanner"][label] = "error: %s: %s" % (
                type(exc).__name__, exc)
    ran = [s for s in h1 if s["result"] != "NOT RUN"]
    rows.append({"id": "H1", "case": "ten honest models from skops.io.dump",
                 "expected": [], "files": h1,
                 "result": ("NOT RUN" if not ran else
                            "FAIL" if any(s["result"] == "FAIL" for s in ran)
                            else "PASS")})

    # ---- H2: FunctionTransformer(functools.partial(np.clip, ...)) --------
    def h2():
        path = os.path.join(files, "partial-transformer.skops")
        sio.dump(partial_model(), path)
        result = _scan(path)
        try:
            reported["untrusted_by_skops"]["partial-transformer"] = sorted(
                sio.get_untrusted_types(file=path))
        except Exception as exc:
            reported["untrusted_by_skops"]["partial-transformer"] = str(exc)
        reported["node_types"]["partial-transformer"] = _types(path)[1]
        rules = _rules(result)
        return rules == ["SKP003"], {"rules": rules, "types": [
            f.type_ref for f in result.findings]}

    row("H2", "FunctionTransformer(functools.partial(np.clip, ...))",
        ["SKP003"], h2)

    # ---- Q1: the pickle scanner on the honest archives -------------------
    def q1():
        views = reported["pickle_scanner"]
        if not views:
            return "no honest file was written"
        if any(isinstance(v, str) for v in views.values()):
            return "the pickle scanner raised on a file: %s" % [
                k for k, v in views.items() if isinstance(v, str)]
        loud = {k: v for k, v in views.items()
                if any(sev in LOUD for _, sev in v)}
        return not loud, {"files_with_medium_or_above": loud}

    row("Q1", "pickle_model_scan on every honest .skops",
        "nothing at MEDIUM or above", q1)

    # ---- K1-K6: edited copies of logreg.skops ---------------------------
    base = honest.get("logreg")

    def edit(name, change, expected):
        def run():
            if base is None:
                return "logreg was not written"
            schema = _types(base)[0]
            if not ss.is_node(schema):
                return "top-level schema object is not a node"
            change(schema)
            dst = os.path.join(args.work, name + ".skops")
            _rezip(base, dst, schema=schema)
            result = _scan(dst)
            rules = _rules(result)
            return rules == expected, {"rules": rules,
                                       "errors": result.errors}
        return run

    def k1(s):
        s["__module__"], s["__class__"] = "os", "system"

    def k2(s):
        s["__loader__"] = "MethodNode"

    def k3(s):
        s["__module__"] = "mypkg.models"

    def k4(s):
        s["__module__"], s["__class__"] = "builtins", "eval"

    row("K1", "top node module os, class system", ["SKP001"],
        edit("k1-os-system", k1, ["SKP001"]))
    row("K2", "top node loader MethodNode", ["SKP002"],
        edit("k2-method-node", k2, ["SKP002"]))
    row("K3", "top node module mypkg.models", ["SKP003"],
        edit("k3-other-package", k3, ["SKP003"]))
    row("K4", "top node builtins.eval", ["SKP001"],
        edit("k4-builtins-eval", k4, ["SKP001"]))

    def k5():
        if base is None:
            return "logreg was not written"
        x, y = _data()[:2]
        dst = os.path.join(args.work, "k5-joblib-named.skops")
        joblib.dump(LogisticRegression().fit(x, y), dst)
        result = _scan(dst)
        rules = _rules(result)
        return rules == ["SKP010"], {"rules": rules, "errors": result.errors}

    def k6():
        if base is None:
            return "logreg was not written"
        dst = os.path.join(args.work, "k6-no-schema.skops")
        _rezip(base, dst, drop_schema=True)
        result = _scan(dst)
        ok = not result.findings and len(result.errors) == 1
        return ok, {"rules": _rules(result), "errors": result.errors}

    row("K5", "joblib pickle of the same model saved as .skops", ["SKP010"],
        k5)
    row("K6", "the archive without schema.json",
        "no findings, one error", k6)

    # ---- reported: types skops asks to trust that skops_scan passes ------
    gap = {}
    for label, types in reported["untrusted_by_skops"].items():
        if isinstance(types, list) and types:
            gap[label] = types
    reported["skops_untrusted_nonempty"] = gap

    graded = [r for r in rows if r["result"] in ("PASS", "FAIL")]
    summary = {
        "skops": skops.__version__, "sklearn": sklearn.__version__,
        "numpy": np.__version__, "joblib": joblib.__version__,
        "scanner": ss.__version__, "pickle_scanner": pms.__version__,
        "held": sum(1 for r in graded if r["result"] == "PASS"),
        "graded": len(graded),
        "not_run": [r["id"] for r in rows if r["result"] == "NOT RUN"],
        "reported": reported,
        "rows": rows,
    }
    with open(os.path.join(args.out, "realfile_summary.json"), "w",
              encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1, default=str)
    for r in rows:
        print(r["id"], r["result"],
              json.dumps(r.get("got", r.get("files", "")),
                         default=str)[:600], r.get("reason", ""))
    print("untrusted by skops:", json.dumps(gap, default=str)[:2000])
    print("held %d of %d graded" % (summary["held"], summary["graded"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
