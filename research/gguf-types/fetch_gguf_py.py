#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fetch llama.cpp tag b12034 and unpack only its gguf-py/ folder as ./gguf-py.

gguf-py is llama.cpp's own Python GGUF writer and reader (MIT). The PyPI
release (0.19.0, May 2026) predates the newest tensor types, so the check
uses the copy at the tag. Setup step for job gguf-types. Made with AI agents
working in the name of MV2 of Munim, Inc. Apache-2.0.
"""

import io
import os
import shutil
import sys
import tarfile
import urllib.request

TAG = "b12034"
URL = ("https://codeload.github.com/ggml-org/llama.cpp/tar.gz/refs/tags/"
       + TAG)


def main():
    data = urllib.request.urlopen(URL, timeout=600).read()
    dest = "gguf-py"
    shutil.rmtree(dest, ignore_errors=True)
    n = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = []
        for m in archive.getmembers():
            parts = m.name.split("/", 2)
            if len(parts) >= 2 and parts[1] == "gguf-py":
                m.name = "/".join(["gguf-py"] + parts[2:]) if len(parts) == 3 \
                    else "gguf-py"
                members.append(m)
        archive.extractall(".", members=members, filter="data")
        n = len(members)
    ok = os.path.isfile(os.path.join(dest, "pyproject.toml"))
    print("llama.cpp %s: %d bytes, %d gguf-py entries, pyproject: %s"
          % (TAG, len(data), n, ok))
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
