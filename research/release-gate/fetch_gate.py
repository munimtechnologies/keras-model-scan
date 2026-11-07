#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step of the release gate: wait (up to WAIT_MIN minutes) until
keras-model-scan's main branch carries what the gate needs (a module at a
minimum version, and each named candidate's manifest under
research/candidates/<name>/), then download main as ./tree.

Usage: python fetch_gate.py --need nemo_container_scan.py=0.2.0 \
           --candidates oed-functions

Writes fetch_report.json in the working folder. Exits 0 even if the wait
timed out (gate_check.py then fails row G0), and 3 only if the tarball has an
unexpected layout.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.request

REPO = "munimtechnologies/keras-model-scan"
TARBALL = "https://codeload.github.com/%s/tar.gz/refs/heads/main" % REPO
RAW = "https://raw.githubusercontent.com/%s/main/" % REPO
WAIT_MIN = 120
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"(\d+)\.(\d+)\.(\d+)"')


def version_of(text):
    m = VER_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def raw(path):
    try:
        req = urllib.request.Request(RAW + path + "?t=%d" % int(time.time()),
                                     headers={"Cache-Control": "no-cache"})
        return urllib.request.urlopen(req, timeout=60).read().decode("utf-8")
    except Exception:
        return None


def ready(needs, candidates):
    for name, want in needs:
        if (version_of(raw(name)) or (0, 0, 0)) < want:
            return False
    for cand in candidates:
        if raw("research/candidates/%s/manifest.json" % cand) is None:
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--need", action="append", default=[])
    ap.add_argument("--candidates", nargs="*", default=[])
    args = ap.parse_args()
    needs = []
    for item in args.need:
        name, _, ver = item.partition("=")
        needs.append((name, tuple(int(x) for x in ver.split("."))))
    start = time.time()
    polls = 0
    ok = False
    while True:
        polls += 1
        ok = ready(needs, args.candidates)
        if ok or time.time() - start > WAIT_MIN * 60:
            break
        time.sleep(60)
    data = urllib.request.urlopen(TARBALL, timeout=300).read()
    shutil.rmtree("tree.tmp", ignore_errors=True)
    os.makedirs("tree.tmp")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall("tree.tmp", filter="data")
    tops = os.listdir("tree.tmp")
    if len(tops) != 1:
        print("unexpected layout %r" % tops, file=sys.stderr)
        return 3
    shutil.rmtree("tree", ignore_errors=True)
    os.rename(os.path.join("tree.tmp", tops[0]), "tree")
    shutil.rmtree("tree.tmp", ignore_errors=True)
    versions = {}
    for fn in sorted(os.listdir("tree")):
        if fn.endswith(".py") and not fn.startswith("test_"):
            with open(os.path.join("tree", fn), encoding="utf-8",
                      errors="replace") as fh:
                v = version_of(fh.read())
            if v:
                versions[fn] = ".".join(map(str, v))
    needs_met = {}
    for name, want in needs:
        have = versions.get(name)
        have_t = tuple(int(x) for x in have.split(".")) if have else None
        needs_met[name] = {"want": ".".join(map(str, want)), "have": have,
                           "met": bool(have_t and have_t >= want)}
    manifests = {c: os.path.isfile(os.path.join(
        "tree", "research", "candidates", c, "manifest.json"))
        for c in args.candidates}
    report = {"waited_seconds": int(time.time() - start), "polls": polls,
              "ready_seen": ok, "needs": needs_met, "manifests": manifests,
              "tree_versions": versions, "tarball_bytes": len(data)}
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
