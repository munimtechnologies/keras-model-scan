#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: a size census of published .nemo files (metadata only).

Lists the 100 most-downloaded Hugging Face model repos tagged nemo
(filter=nemo; the API ignores library=), then reads each repo's public file
list with sizes (/api/models/<id>?blobs=true). No model file is downloaded.
Counts .nemo files by size band: up to 50 MiB (ModelAudit's checkpoint scan
limit), up to 256 MiB (nemo_container_scan 0.1.0's member limit), up to
2 GiB, and above. File size stands in for checkpoint size (the weights are
nearly all of a .nemo). Writes hub_nemo.json. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

LIST = ("https://huggingface.co/api/models?filter=nemo&sort=downloads"
        "&direction=-1&limit=100")
INFO = "https://huggingface.co/api/models/%s?blobs=true"
MIB = 1024 * 1024
BANDS = (("<=50MiB", 50 * MIB), ("50-256MiB", 256 * MIB),
         ("256MiB-2GiB", 2048 * MIB), (">2GiB", None))
UA = {"User-Agent": "mv2-keras-model-scan-census/1 (mv2@munimtech.com)"}


def get(url):
    req = urllib.request.Request(url, headers=UA)
    return json.loads(urllib.request.urlopen(req, timeout=60).read())


def band(size):
    for name, top in BANDS:
        if top is None or size <= top:
            return name
    return BANDS[-1][0]


def main():
    report = {"repos_listed": 0, "repos_read": 0, "errors": [],
              "repos_with_nemo": 0, "nemo_files": 0,
              "bands": {name: 0 for name, _ in BANDS},
              "unique_blobs": 0, "unique_blobs_over_256MiB": 0,
              "repos_with_nemo_over_256MiB": 0, "files": []}
    try:
        listed = get(LIST)
        repos = [m.get("id") for m in listed if m.get("id")]
        report["library_names"] = sorted({str(m.get("library_name"))
                                          for m in listed})
    except Exception as exc:
        report["errors"].append("list: %s" % exc)
        repos = []
    report["repos_listed"] = len(repos)
    blobs, big_blobs = set(), set()
    for rid in repos:
        try:
            info = get(INFO % urllib.parse.quote(rid, safe="/"))
        except Exception as exc:
            report["errors"].append("%s: %s" % (rid, str(exc)[:120]))
            continue
        report["repos_read"] += 1
        has, has_big = False, False
        for s in info.get("siblings") or []:
            name = s.get("rfilename", "")
            size = s.get("size")
            if not name.lower().endswith(".nemo") or not isinstance(size, int):
                continue
            has = True
            report["nemo_files"] += 1
            report["bands"][band(size)] += 1
            key = s.get("blobId") or (rid, name)
            blobs.add(key)
            if size > 256 * MIB:
                has_big = True
                big_blobs.add(key)
            report["files"].append([rid, name, size])
        report["repos_with_nemo"] += int(has)
        report["repos_with_nemo_over_256MiB"] += int(has_big)
        time.sleep(0.3)
    report["unique_blobs"] = len(blobs)
    report["unique_blobs_over_256MiB"] = len(big_blobs)
    n = report["nemo_files"]
    over = report["bands"]["256MiB-2GiB"] + report["bands"][">2GiB"]
    over50 = n - report["bands"]["<=50MiB"]
    report["share_over_256MiB"] = round(over / n, 4) if n else None
    report["share_over_50MiB"] = round(over50 / n, 4) if n else None
    report["errors"] = report["errors"][:30]
    with open("hub_nemo.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps({k: v for k, v in report.items() if k != "files"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
