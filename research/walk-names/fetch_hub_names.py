#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: a file-name census of the most downloaded Hugging Face models
tagged `pytorch` (1,000) and `paddlepaddle` (500), plus a small download of
published files whose names the walk-names fix adds (*.pth.tar, *.pt.tar,
*.ckpt.tar, .pdparams, .pdopt): non-gated models only, at most 2 per model,
30 in all, 25 MB each, each in its own folder. Requests are made one at a
time with a short pause. Public files only; no authentication. The files are
only read as bytes by the scanner later; nothing is unpickled or loaded.
Writes hub/names.json (every listed model's file names) and
hub/manifest.json. Never fails setup.

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
    ("pytorch", "https://huggingface.co/api/models?filter=pytorch"
     "&sort=downloads&direction=-1&limit=1000&full=true"),
    ("paddlepaddle", "https://huggingface.co/api/models?filter=paddlepaddle"
     "&sort=downloads&direction=-1&limit=500&full=true"),
]
CAND = re.compile(r"\.(?:pt|pth|ckpt)\.tar$|\.(?:pdparams|pdopt)$", re.I)
MAX_FILES = 30
PER_MODEL = 2
MAX_BYTES = 25_000_000
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan walk check)"
PAUSE = 0.2


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
           "lists": {}, "files": [], "skipped_gated": [], "errors": []}
    names = {}
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
            mid = m.get("id") or m.get("modelId")
            if not mid or mid in seen:
                continue
            seen.add(mid)
            sibs = m.get("siblings") or []
            rfs = [s.get("rfilename", "") for s in sibs if isinstance(s, dict)]
            names[mid] = {"list": label, "gated": bool(m.get("gated")),
                          "files": rfs}
            picked = [r for r in rfs
                      if CAND.search(r.rsplit("/", 1)[-1])][:PER_MODEL]
            if not picked or n >= MAX_FILES:
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
                    # an oversized file leaves an empty folder; drop it
                    try:
                        os.rmdir(dst_dir)
                    except OSError:
                        pass
                man["files"].append(entry)
    man["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    man["ok_files"] = sum(1 for f in man["files"] if f["status"] == "ok")
    man["models_listed"] = len(names)
    with open(os.path.join("hub", "names.json"), "w", encoding="utf-8") as fh:
        json.dump(names, fh)
    with open(os.path.join("hub", "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(man, fh, indent=1)
    print("lists %r; models %d; ok files %d; gated skipped %d"
          % (man["lists"], len(names), man["ok_files"],
             len(man["skipped_gated"])))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_names failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
