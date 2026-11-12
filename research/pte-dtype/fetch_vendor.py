#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step for job pte-dtype-v1: save the ExecuTorch source files that
are the ground truth for which ScalarType values the runtime accepts and how
many bytes each takes. Read as text only; nothing is built or run.

Writes vendor/<name> for each file and vendor/fetch.json (main-branch commit
SHA when the API answers, byte counts and SHA-256 of each file). Never fails
setup: a missing file makes rows V1/V2 untestable.

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

RAW = "https://raw.githubusercontent.com/pytorch/executorch/main/"
FILES = {
    "scalar_type.h": "runtime/core/portable_type/scalar_type.h",
    "scalar_type_util.h": "runtime/core/exec_aten/util/scalar_type_util.h",
    "tensor_parser_portable.cpp": "runtime/executor/tensor_parser_portable.cpp",
    "scalar_type.fbs": "schema/scalar_type.fbs",
}
COMMIT = "https://api.github.com/repos/pytorch/executorch/commits/main"
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
    rep = {"commit": None, "files": {}}
    try:
        rep["commit"] = json.loads(get(COMMIT)).get("sha")
    except Exception as exc:
        rep["commit_error"] = str(exc)
    for name, path in FILES.items():
        try:
            data = get(RAW + path)
            with open(os.path.join("vendor", name), "wb") as fh:
                fh.write(data)
            rep["files"][name] = {"path": path, "bytes": len(data),
                                  "sha256": hashlib.sha256(data).hexdigest()}
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
