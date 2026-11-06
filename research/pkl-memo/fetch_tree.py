#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: wait (up to WAIT_MIN minutes) until keras-model-scan's main
branch carries openvino_ir_scan 0.1.2 (release v0.52.1, which ships in the
same run that pre-registers this job), then download main as ./tree. The
pickle-memo patch is then applied to the tree that would be released next.
Records what it found in fetch_report.json ("combined" is true only if the
tree has openvino_ir_scan 0.1.2 or later).

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
OVI = ("https://raw.githubusercontent.com/munimtechnologies/"
       "keras-model-scan/main/openvino_ir_scan.py")
WANT = (0, 1, 2)
WAIT_MIN = 90
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"(\d+)\.(\d+)\.(\d+)"')
NEED = ("model_file_scan.py", "pickle_model_scan.py",
        "test_pickle_model_scan.py", "openvino_ir_scan.py", "PICKLE_SCAN.md",
        "pyproject.toml", "test_attribution.py")


def version_of(text):
    m = VER_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def remote_version():
    try:
        req = urllib.request.Request(OVI + "?t=%d" % int(time.time()),
                                     headers={"Cache-Control": "no-cache"})
        text = urllib.request.urlopen(req, timeout=60).read().decode("utf-8")
        return version_of(text)
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
    vers = {}
    for name in ("openvino_ir_scan.py", "pickle_model_scan.py",
                 "model_file_scan.py"):
        try:
            with open(os.path.join("tree", name), encoding="utf-8") as fh:
                v = version_of(fh.read())
            vers[name] = ".".join(map(str, v)) if v else None
        except OSError:
            vers[name] = None
    ovi = vers.get("openvino_ir_scan.py")
    ovi_t = tuple(int(x) for x in ovi.split(".")) if ovi else None
    report = {"waited_seconds": waited, "polls": polls,
              "remote_ovi_seen": ".".join(map(str, seen)) if seen else None,
              "tree_versions": vers,
              "combined": bool(ovi_t and ovi_t >= WANT),
              "tarball_bytes": len(data), "missing": missing}
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report))
    return 4 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
