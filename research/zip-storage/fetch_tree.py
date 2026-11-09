#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download keras-model-scan at tag v0.54.0 (model-file-scan
0.12.1, pickle_model_scan 0.4.0) as ./base. Nothing is patched in this job:
it only measures what the released scanner reports. Records fetch_report.json.

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


def main():
    rep = {"tag": TAG}
    try:
        data = urllib.request.urlopen(URL, timeout=300).read()
        shutil.rmtree("base.tmp", ignore_errors=True)
        os.makedirs("base.tmp")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            archive.extractall("base.tmp", filter="data")
        tops = os.listdir("base.tmp")
        shutil.rmtree("base", ignore_errors=True)
        os.rename(os.path.join("base.tmp", tops[0]), "base")
        shutil.rmtree("base.tmp", ignore_errors=True)
        for name in ("model_file_scan.py", "pickle_model_scan.py"):
            with open(os.path.join("base", name), encoding="utf-8") as fh:
                m = VER_RE.search(fh.read())
            rep[name] = m.group(1) if m else None
        rep["ok"] = True
    except Exception as exc:
        rep["ok"] = False
        rep["error"] = "%s: %s" % (type(exc).__name__, exc)
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
