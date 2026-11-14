#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step for job pte-dtype-v2: save the ExecuTorch source files that
are the ground truth for which ScalarType values the runtime accepts and how
many bytes each takes, at the SAME commit job pte-dtype-v1 read
(3e85cae1e744454713413db4deb31090a505adf4), so v2 grades against identical
source. Read as text only; nothing is built or run.

Writes vendor/<name> for each file and vendor/fetch.json (commit, byte
counts and SHA-256 of each file; v1's SHA-256 values are recorded next to
them). Never fails setup: a missing file makes rows V1/V2/V3 untestable.

ExecuTorch is BSD-licensed (Meta Platforms, Inc. and affiliates); the files
are kept only inside the sealed job.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import hashlib
import json
import os
import sys
import time
import urllib.request

COMMIT = "3e85cae1e744454713413db4deb31090a505adf4"
RAW = "https://raw.githubusercontent.com/pytorch/executorch/%s/" % COMMIT
FILES = {
    "scalar_type.h": "runtime/core/portable_type/scalar_type.h",
    "scalar_type_util.h": "runtime/core/exec_aten/util/scalar_type_util.h",
    "tensor_parser_portable.cpp": "runtime/executor/tensor_parser_portable.cpp",
    "scalar_type.fbs": "schema/scalar_type.fbs",
}
# SHA-256 of each file as job pte-dtype-v1 fetched it (its vendor_check.json).
V1_SHA256 = {
    "scalar_type.h":
        "7c9fda3e0a6b465bfd3d98b14c729d295d03c6fe56e0ccc00cbaa4ae59144b38",
    "scalar_type_util.h":
        "b785986ae3a240c13405fbc21a7b4bbb9e2e6d80662ff4ad2a68d65d98dad9c3",
    "tensor_parser_portable.cpp":
        "1474773fecbf0bcbe88eeb3e8f7b9e71db27ac70c2b9c4228e2b87900ec86d56",
    "scalar_type.fbs":
        "a4c83c25ee7da8eedf61f04fe3df979e5866035763f0ee8d3ed68463e3baad8f",
}
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan dtype check)"


def get(url):
    last = None
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except Exception as exc:
            last = "%s: %s" % (type(exc).__name__, str(exc)[:160])
            time.sleep(10 * attempt)
    raise RuntimeError(last)


def main():
    os.makedirs("vendor", exist_ok=True)
    rep = {"commit": COMMIT, "files": {}}
    for name, path in FILES.items():
        try:
            data = get(RAW + path)
            with open(os.path.join("vendor", name), "wb") as fh:
                fh.write(data)
            sha = hashlib.sha256(data).hexdigest()
            rep["files"][name] = {"path": path, "bytes": len(data),
                                  "sha256": sha,
                                  "same_as_v1": sha == V1_SHA256.get(name)}
        except Exception as exc:
            rep["files"][name] = {"path": path, "error": str(exc)}
    with open(os.path.join("vendor", "fetch.json"), "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps(rep))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_vendor failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
