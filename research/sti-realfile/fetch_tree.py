#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download keras-model-scan's live main branch as ./tree.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import os
import shutil
import sys
import tarfile
import urllib.request

URL = ("https://codeload.github.com/munimtechnologies/keras-model-scan/"
       "tar.gz/refs/heads/main")


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
    need = ("model_file_scan.py", "safetensors_index_scan.py",
            "safetensors_scan.py")
    missing = [n for n in need if not os.path.isfile(os.path.join("tree", n))]
    print("main: %d bytes, %d entries, missing %r"
          % (len(data), len(os.listdir("tree")), missing))
    return 4 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
