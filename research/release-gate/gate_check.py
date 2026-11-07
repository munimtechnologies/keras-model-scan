#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Grade the release gate. Reads fetch_report.json (working folder),
OUT/apply_report.json and OUT/tests_summary.json; writes OUT/gate_summary.json.

Rows (see research/PREREG_RELEASE_GATE_OED.md):
  G0  main carried every required module version and every candidate
      manifest when the tree was downloaded
  G1  every candidate applied: the files it replaces were still the versions
      it was checked against, all its files were copied, and the versions
      after the overlay are the candidate's
  G2  the whole suite on the overlaid tree: 0 failures, 0 errors
Reported, not graded: tests run and skipped (predicted in the prereg).
release_rule_holds = G0 and G1 and G2.  Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import json
import os
import sys


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        return {"_error": "%s: %s" % (type(exc).__name__, exc)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--predict-ran", type=int, default=None)
    ap.add_argument("--predict-skipped", type=int, default=None)
    args = ap.parse_args()
    fetch = load("fetch_report.json")
    apply_ = load(os.path.join(args.out, "apply_report.json"))
    tests = load(os.path.join(args.out, "tests_summary.json"))
    g0 = (not fetch.get("_error")
          and all(n.get("met") for n in (fetch.get("needs") or {}).values())
          and all((fetch.get("manifests") or {}).values())
          and bool(fetch.get("manifests")))
    g1 = bool(apply_.get("all_ok"))
    g2 = (bool(tests.get("ok")) and tests.get("failures") == []
          and tests.get("errors") == [])
    rows = {"G0": {"held": bool(g0), "needs": fetch.get("needs"),
                   "manifests": fetch.get("manifests")},
            "G1": {"held": g1, "candidates": [
                {k: r.get(k) for k in ("name", "ok", "problems",
                                       "main_versions", "after_versions")}
                for r in apply_.get("candidates", [])]},
            "G2": {"held": bool(g2), "ran": tests.get("ran"),
                   "failures": tests.get("failures"),
                   "errors": tests.get("errors"),
                   "skipped": tests.get("skipped"),
                   "error": tests.get("error")}}
    reported = {"predicted_ran": args.predict_ran,
                "ran": tests.get("ran"),
                "ran_as_predicted": (args.predict_ran is not None
                                     and tests.get("ran") == args.predict_ran),
                "predicted_skipped": args.predict_skipped,
                "skipped": tests.get("skipped"),
                "tree_versions": fetch.get("tree_versions"),
                "waited_seconds": fetch.get("waited_seconds"),
                "tarball_bytes": fetch.get("tarball_bytes")}
    held = [k for k, v in rows.items() if v["held"]]
    summary = {"rows": rows, "reported": reported, "held": len(held),
               "graded": len(rows), "held_rows": held,
               "release_rule_holds": len(held) == len(rows)}
    with open(os.path.join(args.out, "gate_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({"held": len(held), "graded": len(rows),
                      "held_rows": held,
                      "release_rule_holds": summary["release_rule_holds"],
                      "ran": tests.get("ran")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
