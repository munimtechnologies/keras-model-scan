#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download a sample of published, zip-format PyTorch checkpoints
(torch.save since PyTorch 1.6) from the Hugging Face Hub, read later only as
bytes by the scanner and by zipfile. Nothing is unpickled or loaded.

Two lists, each a public API query, no authentication:
  A  models by hf-internal-testing (small, randomly initialised test models
     that transformers writes with save_pretrained), pytorch_model.bin of at
     most 10 MB;
  B  the 1,000 most downloaded models tagged pytorch, pytorch_model.bin of
     at most 25 MB.
For each candidate one Range request reads the first 64 bytes (zip magic and
total size from Content-Range); only zip-format files under the cap are then
downloaded whole, one at a time with a short pause, until 160 files or
600 MB. Writes hub/zip_census.json. Never fails setup.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

LISTS = {
    "A": ("https://huggingface.co/api/models?author=hf-internal-testing"
          "&limit=1000&full=true", 10_000_000, 220),
    "B": ("https://huggingface.co/api/models?filter=pytorch&sort=downloads"
          "&direction=-1&limit=1000&full=true", 25_000_000, 300),
}
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan zip census)"
PAUSE = 0.15
MAX_FILES = 160
MAX_TOTAL = 600_000_000
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
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = resp.read(cap + 1)
    if len(data) > cap:
        raise ValueError("larger than %d bytes" % cap)
    return data


def main():
    os.makedirs(os.path.join("hub", "zip"), exist_ok=True)
    rep = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "lists": {}, "heads": [], "downloads": []}
    seen = set()
    total = 0
    n = 0
    for key, (url, cap, budget) in LISTS.items():
        try:
            models = json.loads(urllib.request.urlopen(urllib.request.Request(
                url, headers={"User-Agent": UA}), timeout=300).read())
        except Exception as exc:
            rep["lists"][key] = "error: %s: %s" % (type(exc).__name__, exc)
            continue
        cands = []
        for rank, m in enumerate(models, 1):
            mid = m.get("id") or m.get("modelId")
            if not mid or mid in seen or m.get("gated") or m.get("private"):
                continue
            rfs = {s.get("rfilename") for s in (m.get("siblings") or [])
                   if isinstance(s, dict)}
            if TARGET in rfs:
                cands.append((rank, mid))
        rep["lists"][key] = {"models": len(models), "with_target": len(cands)}
        heads = 0
        for rank, mid in cands:
            if heads >= budget or n >= MAX_FILES or total >= MAX_TOTAL:
                break
            seen.add(mid)
            heads += 1
            entry = {"list": key, "rank": rank, "model": mid}
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
            if entry["size"] > cap or total + entry["size"] > MAX_TOTAL:
                continue
            n += 1
            d = {"n": n, "list": key, "model": mid}
            dst = os.path.join("hub", "zip", "%03d" % n)
            os.makedirs(dst, exist_ok=True)
            try:
                time.sleep(PAUSE)
                data = get_all(url_for(mid, TARGET), cap)
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
    print(json.dumps({"lists": rep["lists"], "heads": len(rep["heads"]),
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
