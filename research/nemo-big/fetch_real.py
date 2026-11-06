#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download two published NVIDIA .nemo models (CC BY 4.0, not
gated), pinned to a revision, into ./real/. They are only read as bytes by
the scanners and by tarfile/zipfile here; nothing is unpickled or loaded.

Writes real_report.json: size, sha256, compression, and for the member whose
name ends in model_weights.ckpt its size and first 4 bytes. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import hashlib
import json
import os
import sys
import tarfile
import urllib.request

FILES = {
    "titanet_large": (
        "https://huggingface.co/nvidia/speakerverification_en_titanet_large/"
        "resolve/0dc382f40121a5fbd34db10a2bb04d826c2be6a8/"
        "speakerverification_en_titanet_large.nemo", 101621760),
    "parakeet_tdt_ctc_110m": (
        "https://huggingface.co/nvidia/parakeet-tdt_ctc-110m/"
        "resolve/431a349f3051ab85c22b9b7a2741b5fe77065665/"
        "parakeet-tdt_ctc-110m.nemo", 459243520),
}
UA = {"User-Agent": "mv2-keras-model-scan-check/1 (mv2@munimtech.com)"}


def download(url, dest):
    h = hashlib.sha256()
    n = 0
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=600) as resp, \
            open(dest, "wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def describe(path):
    info = {}
    with open(path, "rb") as fh:
        head = fh.read(512)
    info["compression"] = ("gzip" if head[:2] == b"\x1f\x8b" else
                           "none" if head[257:262] == b"ustar" else "other")
    members = []
    with tarfile.open(path, "r:*") as tar:
        for m in tar:
            members.append(m.name)
            if m.isfile() and m.name.endswith("model_weights.ckpt"):
                fh = tar.extractfile(m)
                info["weights_member"] = m.name
                info["weights_bytes"] = m.size
                info["weights_head"] = fh.read(4).hex()
    info["members"] = members[:60]
    info["member_count"] = len(members)
    return info


def main():
    os.makedirs("real", exist_ok=True)
    report = {}
    for key, (url, size) in FILES.items():
        entry = {"url": url, "expected_bytes": size}
        dest = os.path.join("real", key + ".nemo")
        try:
            n, sha = download(url, dest)
            entry.update({"bytes": n, "sha256": sha, "size_ok": n == size})
            entry.update(describe(dest))
        except Exception as exc:
            entry["error"] = "%s: %s" % (type(exc).__name__, exc)
        report[key] = entry
    with open("real_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
