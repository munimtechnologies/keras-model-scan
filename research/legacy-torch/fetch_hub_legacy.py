#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: which serialization format do the most downloaded Hugging Face
PyTorch checkpoints use?

Lists the 1,000 most downloaded models tagged `pytorch` (non-gated, public),
then reads the first 64 bytes of each top-level `pytorch_model.bin` (one HTTP
Range request each, one at a time with a short pause), and, while the budget
lasts, of one other torch-style file per model (*.bin / *.pt / *.pth /
*.ckpt). Each header is classed as:
  legacy  starts with a PROTO 2-5 pickle whose first value is torch's magic
          number 0x1950A86A20F9469CFC6C (torch.save with
          _use_new_zipfile_serialization=False, the default before 1.6)
  zip     starts with PK\\x03\\x04 (torch.save since 1.6)
  pickle  another pickle (PROTO 2-5)
  other   anything else (GGML, OpenVINO weights, raw data, ...)
The total size comes from Content-Range. Up to 12 legacy files of at most
25 MB (distinct models first) are downloaded whole, each in its own folder,
for the static scan. Nothing is unpickled or loaded: the files are only read
as bytes by the scanner later. No authentication.
Writes hub/legacy_census.json. Never fails setup.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

LIST = ("https://huggingface.co/api/models?filter=pytorch&sort=downloads"
        "&direction=-1&limit=1000&full=true")
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan legacy census)"
PAUSE = 0.15
HEADER_BUDGET = 500
MAX_DOWNLOADS = 12
MAX_BYTES = 25_000_000
MAGIC_LE = bytes.fromhex("6cfc9c46f9206aa85019")
OTHER_RX = re.compile(r"\.(?:bin|pt|pth|ckpt)$", re.I)
RANGE_RX = re.compile(r"/(\d+)\s*$")


def classify(head):
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        # protocol 2-3: 8a 0a <magic> right after PROTO; protocol 4-5 put a
        # 9-byte FRAME header first. Look for LONG1 of length 10 + magic.
        if b"\x8a\x0a" + MAGIC_LE in head[:32]:
            return "legacy"
        return "pickle"
    return "other"


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
        return head, total, resp.status


def get_all(url, cap):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = resp.read(cap + 1)
    if len(data) > cap:
        raise ValueError("larger than %d bytes" % cap)
    return data


def main():
    os.makedirs(os.path.join("hub", "legacy"), exist_ok=True)
    rep = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "list": None, "headers": [], "downloads": [], "errors": []}
    try:
        models = json.loads(urllib.request.urlopen(urllib.request.Request(
            LIST, headers={"User-Agent": UA}), timeout=300).read())
        rep["list"] = len(models)
    except Exception as exc:
        rep["list"] = "error: %s: %s" % (type(exc).__name__, exc)
        models = []
    open_models = []
    for rank, m in enumerate(models, 1):
        mid = m.get("id") or m.get("modelId")
        if not mid or m.get("gated") or m.get("private"):
            continue
        rfs = [s.get("rfilename", "") for s in (m.get("siblings") or [])
               if isinstance(s, dict)]
        open_models.append((rank, mid, m.get("lastModified"),
                            m.get("downloads"), rfs))
    rep["open_models"] = len(open_models)
    rep["with_pytorch_model_bin"] = sum(
        1 for o in open_models if "pytorch_model.bin" in o[4])
    plan = [(o, "pytorch_model.bin", "pytorch_model.bin") for o in open_models
            if "pytorch_model.bin" in o[4]]
    for o in open_models:
        others = [r for r in o[4] if OTHER_RX.search(r)
                  and r != "pytorch_model.bin"]
        if others:
            plan.append((o, sorted(others)[0], "other"))
    for (rank, mid, modified, downloads, _rfs), rf, group in plan:
        if len(rep["headers"]) >= HEADER_BUDGET:
            break
        entry = {"rank": rank, "model": mid, "rfilename": rf, "group": group,
                 "last_modified": modified, "downloads": downloads}
        try:
            time.sleep(PAUSE)
            head, total, status = head_of(url_for(mid, rf))
            entry.update(kind=classify(head), size=total, status=status,
                         head_hex=head[:16].hex())
        except Exception as exc:
            entry.update(kind=None, error="%s: %s" % (
                type(exc).__name__, str(exc)[:160]))
        rep["headers"].append(entry)
    small = [e for e in rep["headers"] if e.get("kind") == "legacy"
             and isinstance(e.get("size"), int) and e["size"] <= MAX_BYTES]
    seen, picks = set(), []
    for e in small:
        if e["model"] not in seen:
            picks.append(e)
            seen.add(e["model"])
    for e in small:
        if e not in picks:
            picks.append(e)
    for n, e in enumerate(picks[:MAX_DOWNLOADS], 1):
        d = {"n": n, "model": e["model"], "rfilename": e["rfilename"]}
        dst = os.path.join("hub", "legacy", "%02d" % n)
        os.makedirs(dst, exist_ok=True)
        try:
            time.sleep(PAUSE)
            data = get_all(url_for(e["model"], e["rfilename"]), MAX_BYTES)
            path = os.path.join(dst, e["rfilename"].rsplit("/", 1)[-1])
            with open(path, "wb") as fh:
                fh.write(data)
            d.update(status="ok", bytes=len(data), path=os.path.relpath(path))
        except Exception as exc:
            d.update(status="error: %s: %s" % (type(exc).__name__,
                                               str(exc)[:160]))
        rep["downloads"].append(d)
    kinds = {}
    for e in rep["headers"]:
        key = "%s:%s" % (e["group"], e.get("kind"))
        kinds[key] = kinds.get(key, 0) + 1
    rep["kinds"] = kinds
    rep["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(os.path.join("hub", "legacy_census.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"list": rep["list"], "open": rep["open_models"],
                      "kinds": kinds,
                      "downloads": sum(1 for d in rep["downloads"]
                                       if d["status"] == "ok")}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_legacy failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
