#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: download a small set of published pickle files from the most
downloaded Hugging Face models tagged `paddlepaddle` and `sklearn` (500 each):
names ending .pdparams, .pdopt, .pkl or .pickle; non-gated models only; at
most 2 per model, 15 per list (40 attempts), 40 MB each (streamed to disk in 1 MB chunks
and dropped if larger), each in its own folder. Requests are made one at a
time with a short pause. Public files only; no authentication. The files are
only read as bytes by the scanner later; nothing is unpickled or loaded.
Writes hub/manifest.json. Never fails setup.

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
    ("paddlepaddle", "https://huggingface.co/api/models?filter=paddlepaddle"
     "&sort=downloads&direction=-1&limit=500&full=true"),
    ("sklearn", "https://huggingface.co/api/models?filter=sklearn"
     "&sort=downloads&direction=-1&limit=500&full=true"),
]
CAND = re.compile(r"\.(?:pdparams|pdopt|pkl|pickle)$", re.I)
PER_LIST = 15
PER_MODEL = 2
MAX_TRIES = 40
MAX_BYTES = 40_000_000
CHUNK = 1 << 20
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan pickle check)"
PAUSE = 0.2


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())


def download(url, path):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    total = 0
    with urllib.request.urlopen(req, timeout=180) as resp, \
            open(path, "wb") as fh:
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise ValueError("larger than %d bytes" % MAX_BYTES)
            fh.write(chunk)
    return total


def main():
    out_dir = os.path.join("hub", "files")
    os.makedirs(out_dir, exist_ok=True)
    man = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "lists": {}, "files": [], "skipped_gated": []}
    seen = set()
    n = 0
    for label, url in LISTS:
        try:
            models = get_json(url)
            man["lists"][label] = len(models)
        except Exception as exc:
            man["lists"][label] = "error: %s: %s" % (type(exc).__name__, exc)
            continue
        taken = 0
        tries = 0
        for m in models:
            if taken >= PER_LIST or tries >= MAX_TRIES:
                break
            mid = m.get("id") or m.get("modelId")
            if not mid or mid in seen:
                continue
            seen.add(mid)
            sibs = m.get("siblings") or []
            rfs = [s.get("rfilename", "") for s in sibs if isinstance(s, dict)]
            picked = [r for r in rfs
                      if CAND.search(r.rsplit("/", 1)[-1])][:PER_MODEL]
            if not picked:
                continue
            if m.get("gated") or m.get("private"):
                man["skipped_gated"].append(mid)
                continue
            for rf in picked:
                if taken >= PER_LIST or tries >= MAX_TRIES:
                    break
                tries += 1
                n += 1
                entry = {"n": n, "model": mid, "list": label,
                         "rfilename": rf}
                dst_dir = os.path.join(out_dir, "%04d" % n)
                os.makedirs(dst_dir, exist_ok=True)
                path = os.path.join(dst_dir, rf.rsplit("/", 1)[-1])
                try:
                    time.sleep(PAUSE)
                    size = download("https://huggingface.co/%s/resolve/main/%s"
                                    % (urllib.parse.quote(mid, safe="/"),
                                       urllib.parse.quote(rf, safe="/")),
                                    path)
                    entry.update(status="ok", bytes=size,
                                 path=os.path.relpath(path))
                    taken += 1
                except Exception as exc:
                    entry.update(status="error: %s: %s" % (
                        type(exc).__name__, str(exc)[:160]))
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                    try:
                        os.rmdir(dst_dir)
                    except OSError:
                        pass
                man["files"].append(entry)
    man["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    man["ok_files"] = sum(1 for f in man["files"] if f["status"] == "ok")
    with open(os.path.join("hub", "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(man, fh, indent=1)
    print("lists %r; ok files %d; gated skipped %d"
          % (man["lists"], man["ok_files"], len(man["skipped_gated"])))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_pkl failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
