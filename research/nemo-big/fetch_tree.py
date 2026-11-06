#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download keras-model-scan's main branch as ./tree and record
the versions of model_file_scan and nemo_container_scan in fetch_report.json.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import os
import re
import shutil
import sys
import tarfile
import urllib.request

URL = ("https://codeload.github.com/munimtechnologies/keras-model-scan/"
       "tar.gz/refs/heads/main")
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"([0-9.]+)"')
NEED = ("nemo_container_scan.py", "test_nemo_container_scan.py",
        "NEMO_CONTAINER_SCAN.md", "model_file_scan.py")


def version_of(name):
    try:
        with open(os.path.join("tree", name), encoding="utf-8") as fh:
            m = VER_RE.search(fh.read())
        return m.group(1) if m else None
    except OSError:
        return None


def main():
    data = urllib.request.urlopen(URL, timeout=300).read()
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
    report = {"tarball_bytes": len(data), "missing": missing,
              "versions": {n: version_of(n) for n in
                           ("model_file_scan.py", "nemo_container_scan.py")}}
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report))
    return 4 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
