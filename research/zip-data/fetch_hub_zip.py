#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download a sample of published, zip-format PyTorch checkpoints
(torch.save since PyTorch 1.6) from the Hugging Face Hub. They are read later
only as bytes, by the scanner and by zipfile. Nothing is unpickled or loaded.

One public API query, no authentication: the 1,000 most downloaded models
tagged pytorch. For each model with a top-level pytorch_model.bin, one Range
request reads the first 64 bytes (zip magic, and the total size from
Content-Range). Zip-format files of at most 140 MB are then downloaded whole,
one at a time with a short pause, until 50 files or 1.5 GB. (Job
zip-storage-v1 capped files at 25 MB and got only 6.) Writes
hub/zip_census.json. Never fails setup.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

LIST_URL = ("https://huggingface.co/api/models?filter=pytorch&sort=downloads"
            "&direction=-1&limit=1000&full=true")
CAP = 140_000_000
HEAD_BUDGET = 400
MAX_FILES = 50
MAX_TOTAL = 1_500_000_000
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan zip census)"
PAUSE = 0.15
RANGE_RX = re.compile(r"/(\d+)\s*$")
TARGET = "pytorch_model.bin"


def url_for(mid, rf):
    return "https://huggingface.co/%s/resolve/main/%s" % (
        urllib.parse.quote(mid, safe="/"), urllib.parse.quote(rf, safe="/"))


def head_of(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Range": "bytes=0-63"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        head = resp.read(64)
        total = None
        m = RANGE_RX.search(resp.headers.get("Content-Range") or "")
        if m:
            total = int(m.group(1))
        elif resp.status == 200 and resp.headers.get("Content-Length"):
            total = int(resp.headers["Content-Length"])
        return head, total


def get_all(url, cap):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=600) as resp:
        data = resp.read(cap + 1)
    if len(data) > cap:
        raise ValueError("larger than %d bytes" % cap)
    return data


def main():
    os.makedirs(os.path.join("hub", "zip"), exist_ok=True)
    rep = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "cap_bytes": CAP, "heads": [], "downloads": []}
    total = 0
    n = 0
    try:
        models = json.loads(urllib.request.urlopen(urllib.request.Request(
            LIST_URL, headers={"User-Agent": UA}), timeout=300).read())
    except Exception as exc:
        rep["list"] = "error: %s: %s" % (type(exc).__name__, exc)
        models = []
    cands = []
    for rank, m in enumerate(models, 1):
        mid = m.get("id") or m.get("modelId")
        if not mid or m.get("gated") or m.get("private"):
            continue
        rfs = {s.get("rfilename") for s in (m.get("siblings") or [])
               if isinstance(s, dict)}
        if TARGET in rfs:
            cands.append((rank, mid))
    if models:
        rep["list"] = {"models": len(models), "with_target": len(cands)}
    for rank, mid in cands[:HEAD_BUDGET]:
        if n >= MAX_FILES or total >= MAX_TOTAL:
            break
        entry = {"rank": rank, "model": mid}
        try:
            time.sleep(PAUSE)
            head, size = head_of(url_for(mid, TARGET))
            entry.update(zip=head[:4] == b"PK\x03\x04", size=size)
        except Exception as exc:
            entry.update(zip=None, error="%s: %s" % (
                type(exc).__name__, str(exc)[:160]))
        rep["heads"].append(entry)
        if not entry.get("zip") or not isinstance(entry.get("size"), int):
            continue
        if entry["size"] > CAP or total + entry["size"] > MAX_TOTAL:
            continue
        n += 1
        d = {"n": n, "rank": rank, "model": mid}
        dst = os.path.join("hub", "zip", "%03d" % n)
        os.makedirs(dst, exist_ok=True)
        try:
            time.sleep(PAUSE)
            data = get_all(url_for(mid, TARGET), CAP)
            path = os.path.join(dst, TARGET)
            with open(path, "wb") as fh:
                fh.write(data)
            total += len(data)
            d.update(status="ok", bytes=len(data), path=path)
        except Exception as exc:
            d.update(status="error: %s: %s" % (type(exc).__name__,
                                               str(exc)[:160]))
        rep["downloads"].append(d)
    rep["total_bytes"] = total
    rep["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(os.path.join("hub", "zip_census.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"list": rep.get("list"), "heads": len(rep["heads"]),
                      "downloads": sum(1 for d in rep["downloads"]
                                       if d["status"] == "ok"),
                      "bytes": total}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_zip failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
