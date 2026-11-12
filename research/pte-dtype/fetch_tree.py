#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step for job pte-dtype-v1: download keras-model-scan at the
released tag v0.60.0 (executorch_pte_scan 0.1.0) as ./tree. The tree is
the unpatched baseline; patch_pte.py writes the candidate fix to ./patched.

Records fetch_report.json; exits non-zero if the tag cannot be fetched or
files are missing.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.request

TAG = "v0.60.0"
URL = ("https://codeload.github.com/munimtechnologies/keras-model-scan/"
       "tar.gz/refs/tags/" + TAG)
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"([0-9.]+)"')
NEED = ("executorch_pte_scan.py", "test_executorch_pte_scan.py",
        "EXECUTORCH_PTE_SCAN.md", "model_file_scan.py")


def download():
    last = None
    for attempt in range(1, 6):
        try:
            return urllib.request.urlopen(URL, timeout=300).read(), attempt
        except Exception as exc:  # transient network error
            last = "%s: %s" % (type(exc).__name__, exc)
            print("attempt %d: %s" % (attempt, last), flush=True)
            time.sleep(30)
    raise RuntimeError("tag %s not fetched (%s)" % (TAG, last))


def main():
    data, attempts = download()
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
    missing = [n for n in NEED if not os.path.isfile(os.path.join("tree", n))]
    ver = {}
    for name in ("model_file_scan.py", "executorch_pte_scan.py"):
        try:
            with open(os.path.join("tree", name), encoding="utf-8") as fh:
                m = VER_RE.search(fh.read())
            ver[name] = m.group(1) if m else None
        except OSError:
            ver[name] = None
    report = {"tag": TAG, "attempts": attempts, "tarball_bytes": len(data),
              "missing": missing, "versions": ver}
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report))
    return 4 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
