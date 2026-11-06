#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: wait (up to WAIT_MIN minutes) until keras-model-scan's main
branch carries model-file-scan 0.12.0 or later (release v0.52.0), then
download main as ./tree. The walk-names patch is written against 0.12.0.
Records what it found in fetch_report.json. After WAIT_MIN it downloads main
as it is (the patch then refuses to apply if 0.12.0 is not there).

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

URL = ("https://codeload.github.com/munimtechnologies/keras-model-scan/"
       "tar.gz/refs/heads/main")
PYPROJECT = ("https://raw.githubusercontent.com/munimtechnologies/"
             "keras-model-scan/main/pyproject.toml")
WANT = (0, 12, 0)
WAIT_MIN = 60
VER_RE = re.compile(r'(?m)^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"')
MFS_RE = re.compile(r'(?m)^__version__\s*=\s*"(\d+)\.(\d+)\.(\d+)"')
NEED = ("model_file_scan.py", "pickle_model_scan.py", "test_attribution.py",
        "MODEL_FILE_SCAN.md", "pyproject.toml")


def remote_version():
    try:
        req = urllib.request.Request(PYPROJECT + "?t=%d" % int(time.time()),
                                     headers={"Cache-Control": "no-cache"})
        text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8")
        m = VER_RE.search(text)
        return tuple(int(x) for x in m.groups()) if m else None
    except Exception:
        return None


def main():
    start = time.time()
    seen = None
    polls = 0
    while True:
        polls += 1
        seen = remote_version()
        if seen and seen >= WANT:
            break
        if time.time() - start > WAIT_MIN * 60:
            break
        time.sleep(60)
    waited = int(time.time() - start)
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
    mfs = None
    try:
        with open(os.path.join("tree", "model_file_scan.py"),
                  encoding="utf-8") as fh:
            m = MFS_RE.search(fh.read())
        mfs = tuple(int(x) for x in m.groups()) if m else None
    except OSError:
        pass
    report = {"waited_seconds": waited, "polls": polls,
              "pyproject_seen": ".".join(map(str, seen)) if seen else None,
              "tree_mfs_version": ".".join(map(str, mfs)) if mfs else None,
              "combined": bool(mfs and mfs >= WANT),
              "tarball_bytes": len(data), "missing": missing}
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report))
    return 4 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
