#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fetch the keras-model-scan v0.49.0 source tarball and unpack it as ./kms.

Setup step for job ovi-realfile (research/PREREG_OVI_REALFILE.md). Made with
AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import io
import os
import shutil
import sys
import tarfile
import urllib.request

URL = ("https://codeload.github.com/munimtechnologies/keras-model-scan/"
       "tar.gz/refs/tags/v0.49.0")


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    dest = args[0] if args else "kms"
    data = urllib.request.urlopen(URL, timeout=180).read()
    tmp = dest + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(tmp, filter="data")
    tops = os.listdir(tmp)
    if len(tops) != 1:
        print("unexpected tarball layout: %r" % (tops,), file=sys.stderr)
        return 3
    shutil.rmtree(dest, ignore_errors=True)
    os.rename(os.path.join(tmp, tops[0]), dest)
    shutil.rmtree(tmp, ignore_errors=True)
    needed = ("openvino_ir_scan.py", "model_file_scan.py",
              "pickle_model_scan.py")
    missing = [n for n in needed if not os.path.isfile(os.path.join(dest, n))]
    print("unpacked %s -> %s (%d entries); missing: %r"
          % (tops[0], dest, len(os.listdir(dest)), missing))
    return 4 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
