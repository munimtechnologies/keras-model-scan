#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download keras-model-scan at tag v0.54.0 (model-file-scan
0.12.1, pickle_model_scan 0.4.0) as ./tree (patched later) and an untouched
copy as ./base (the baseline every row compares against). Records
fetch_report.json.

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

TAG = "v0.54.0"
URL = ("https://codeload.github.com/munimtechnologies/keras-model-scan/"
       "tar.gz/refs/tags/" + TAG)
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"([0-9.]+)"')
NEED = ("model_file_scan.py", "pickle_model_scan.py", "test_attribution.py",
        "PICKLE_SCAN.md", "MODEL_FILE_SCAN.md", "README.md", "pyproject.toml")


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
    for d in ("tree", "base"):
        shutil.rmtree(d, ignore_errors=True)
    os.rename(os.path.join("tree.tmp", tops[0]), "tree")
    shutil.rmtree("tree.tmp", ignore_errors=True)
    shutil.copytree("tree", "base")
    missing = [n for n in NEED if not os.path.isfile(os.path.join("tree", n))]
    ver = {}
    for name in ("model_file_scan.py", "pickle_model_scan.py"):
        try:
            with open(os.path.join("tree", name), encoding="utf-8") as fh:
                m = VER_RE.search(fh.read())
            ver[name] = m.group(1) if m else None
        except OSError:
            ver[name] = None
    report = {"tag": TAG, "tarball_bytes": len(data), "missing": missing,
              "versions": ver,
              "files": len([1 for _ in os.scandir("tree")])}
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report))
    return 4 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
