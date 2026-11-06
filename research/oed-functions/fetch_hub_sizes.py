#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: a size census of published .onnx files (metadata only).

Lists the 100 most-downloaded Hugging Face model repos tagged library=onnx,
then reads each repo's public file list with sizes (/api/models/<id>?blobs=true).
No model file is downloaded. Counts .onnx files by size band, especially the
band (256 MiB, 2 GiB] that onnx_external_data_scan 0.1.0 never fully read.
Writes hub_sizes.json. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

LIST = ("https://huggingface.co/api/models?library=onnx&sort=downloads"
        "&direction=-1&limit=100")
INFO = "https://huggingface.co/api/models/%s?blobs=true"
MIB = 1024 * 1024
OLD_CAP = 256 * MIB
PB_LIMIT = 2 * 1024 * MIB
UA = {"User-Agent": "mv2-keras-model-scan-census/1 (mv2@munimtech.com)"}


def get(url):
    req = urllib.request.Request(url, headers=UA)
    return json.loads(urllib.request.urlopen(req, timeout=60).read())


def main():
    report = {"repos_listed": 0, "repos_read": 0, "errors": [],
              "onnx_files": 0, "bands": {"<=256MiB": 0, "256MiB-2GiB": 0,
                                         ">2GiB": 0},
              "unique_blobs_256MiB_2GiB": 0, "repos_with_band_file": 0,
              "repos_with_external_data_file": 0, "examples_band": [],
              "examples_over_2GiB": []}
    try:
        repos = [m.get("id") for m in get(LIST) if m.get("id")]
    except Exception as exc:
        report["errors"].append("list: %s" % exc)
        repos = []
    report["repos_listed"] = len(repos)
    band_blobs = set()
    for rid in repos:
        try:
            info = get(INFO % urllib.parse.quote(rid, safe="/"))
        except Exception as exc:
            report["errors"].append("%s: %s" % (rid, str(exc)[:120]))
            continue
        report["repos_read"] += 1
        sib = info.get("siblings") or []
        in_band = False
        ext = False
        for s in sib:
            name = s.get("rfilename", "")
            low = name.lower()
            if low.endswith((".onnx_data", ".onnx.data", ".onnx_data.bin")):
                ext = True
            if not low.endswith(".onnx"):
                continue
            size = s.get("size")
            if not isinstance(size, int):
                continue
            report["onnx_files"] += 1
            if size <= OLD_CAP:
                report["bands"]["<=256MiB"] += 1
            elif size <= PB_LIMIT:
                report["bands"]["256MiB-2GiB"] += 1
                band_blobs.add(s.get("blobId") or (rid, name))
                in_band = True
                if len(report["examples_band"]) < 15:
                    report["examples_band"].append([rid, name, size])
            else:
                report["bands"][">2GiB"] += 1
                if len(report["examples_over_2GiB"]) < 15:
                    report["examples_over_2GiB"].append([rid, name, size])
        report["repos_with_band_file"] += int(in_band)
        report["repos_with_external_data_file"] += int(ext)
        time.sleep(0.3)
    report["unique_blobs_256MiB_2GiB"] = len(band_blobs)
    report["errors"] = report["errors"][:30]
    with open("hub_sizes.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("examples_band", "examples_over_2GiB")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
