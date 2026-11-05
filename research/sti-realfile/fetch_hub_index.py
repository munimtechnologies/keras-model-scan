#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download public shard-index files from the Hugging Face Hub.

Pre-registered in research/PREREG_STI_REALFILE.md. Lists the most downloaded
models with the `safetensors` filter (1,000) and the `diffusers` filter (200),
skips gated and private models, and downloads every file whose name matches
the candidate index pattern, at most 4 per model, 400 in all, 30 MB each.
Requests are made one at a time with a short pause. Public files only; no
authentication. Writes hub/manifest.json. Never fails setup.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

LISTS = [
    ("safetensors", "https://huggingface.co/api/models?filter=safetensors"
     "&sort=downloads&direction=-1&limit=1000&full=true"),
    ("diffusers", "https://huggingface.co/api/models?filter=diffusers"
     "&sort=downloads&direction=-1&limit=200&full=true"),
]
CAND = re.compile(r"\.index(\.[A-Za-z0-9_\-]+)?\.json$", re.I)
MAX_FILES = 400
PER_MODEL = 4
MAX_BYTES = 30_000_000
MAX_INFO_CALLS = 150
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; shard-index scanner check)"
PAUSE = 0.15


def get(url, cap=None, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if cap is None:
            return resp.read()
        data = resp.read(cap + 1)
        if len(data) > cap:
            raise ValueError("larger than %d bytes" % cap)
        return data


def main():
    out_dir = os.path.join("hub", "files")
    os.makedirs(out_dir, exist_ok=True)
    man = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "lists": {}, "files": [], "skipped_gated": [],
           "info_calls": 0, "errors": []}
    seen = set()
    n = 0
    for label, url in LISTS:
        try:
            models = json.loads(get(url, timeout=300))
            man["lists"][label] = len(models)
        except Exception as exc:
            man["lists"][label] = "error: %s: %s" % (type(exc).__name__, exc)
            continue
        for m in models:
            if n >= MAX_FILES:
                break
            mid = m.get("id") or m.get("modelId")
            if not mid or mid in seen:
                continue
            seen.add(mid)
            sibs = m.get("siblings")
            if sibs is None and man["info_calls"] < MAX_INFO_CALLS:
                man["info_calls"] += 1
                try:
                    time.sleep(PAUSE)
                    info = json.loads(get(
                        "https://huggingface.co/api/models/"
                        + urllib.parse.quote(mid, safe="/")))
                    sibs = info.get("siblings")
                    m = dict(m, gated=info.get("gated", m.get("gated")),
                             private=info.get("private", m.get("private")))
                except Exception as exc:
                    man["errors"].append([mid, "info: %s" % exc])
                    continue
            names = [s.get("rfilename", "") for s in (sibs or [])
                     if isinstance(s, dict)]
            picked = [r for r in names
                      if CAND.search(r.rsplit("/", 1)[-1])][:PER_MODEL]
            if not picked:
                continue
            if m.get("gated") or m.get("private"):
                man["skipped_gated"].append(mid)
                continue
            for rf in picked:
                if n >= MAX_FILES:
                    break
                n += 1
                entry = {"n": n, "model": mid, "list": label,
                         "rfilename": rf}
                dst_dir = os.path.join(out_dir, "%04d" % n)
                os.makedirs(dst_dir, exist_ok=True)
                try:
                    time.sleep(PAUSE)
                    data = get("https://huggingface.co/%s/resolve/main/%s" % (
                        urllib.parse.quote(mid, safe="/"),
                        urllib.parse.quote(rf, safe="/")), cap=MAX_BYTES)
                    path = os.path.join(dst_dir, rf.rsplit("/", 1)[-1])
                    with open(path, "wb") as fh:
                        fh.write(data)
                    entry.update(status="ok", bytes=len(data),
                                 path=os.path.relpath(path))
                except Exception as exc:
                    entry.update(status="error: %s: %s" % (
                        type(exc).__name__, str(exc)[:160]))
                man["files"].append(entry)
    man["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    man["ok_files"] = sum(1 for f in man["files"] if f["status"] == "ok")
    man["models_with_files"] = len({f["model"] for f in man["files"]
                                    if f["status"] == "ok"})
    with open(os.path.join("hub", "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(man, fh, indent=1)
    print("lists %r; ok files %d from %d models; gated skipped %d; errors %d"
          % (man["lists"], man["ok_files"], man["models_with_files"],
             len(man["skipped_gated"]), len(man["errors"])))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_index failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
