#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step of job pkl-joblib-v1 (network allowed here only).

1. Wait (up to WAIT_MIN minutes) until keras-model-scan's main branch carries
   research/PREREG_PKL_JOBLIB.md (the pre-registration, published in the
   same run that files this job), then download main as ./tree.
2. Download published pickle files from the most downloaded Hugging Face
   models tagged `sklearn` (filter=sklearn; the `library=` parameter is
   ignored by the API): names ending .joblib, .pkl or .pickle, non-gated
   models only, at most 2 per model, 30 files, 40 MB each and 500 MB in all,
   streamed to disk in 1 MB chunks, one request at a time.
3. Download the three files of OKTAYBBS/DataScientst-models that jobs
   pkl-memo-v1 and pkl-diag-v1 examined, pinned to the same repo commit.

Public files only, no authentication. The files are only read as bytes
later; nothing is unpickled or loaded. Writes fetch_report.json and
hub/manifest.json. Never fails setup (the check grades rows instead).

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.parse
import urllib.request

REPO = "munimtechnologies/keras-model-scan"
TARBALL = "https://codeload.github.com/%s/tar.gz/refs/heads/main" % REPO
RAW = "https://raw.githubusercontent.com/%s/main/" % REPO
NEED = "research/PREREG_PKL_JOBLIB.md"
NEED_TEXT = "pkl-joblib-v1"
WAIT_MIN = 120
LIST_URL = ("https://huggingface.co/api/models?filter=sklearn&sort=downloads"
            "&direction=-1&limit=500&full=true")
CAND = re.compile(r"\.(?:joblib|pkl|pickle)$", re.I)
PER_MODEL = 2
MAX_FILES = 30
MAX_TRIES = 60
MAX_BYTES = 40_000_000
MAX_TOTAL = 500_000_000
PINNED_REPO = "OKTAYBBS/DataScientst-models"
PINNED_REV = "c40104b6f379f3bc7a0f5d000cdf35fa8caf9467"
PINNED = ["classification/churn_model.pkl", "classification/mobile_model.pkl",
          "classification/wine_model.pkl"]
CHUNK = 1 << 20
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan joblib check)"
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"(\d+\.\d+\.\d+)"')
PAUSE = 0.3


def _get(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Cache-Control": "no-cache"})
    return urllib.request.urlopen(req, timeout=timeout)


def need_ready():
    try:
        with _get(RAW + NEED + "?t=%d" % int(time.time()), 60) as resp:
            return NEED_TEXT in resp.read().decode("utf-8", "replace")
    except Exception:
        return False


def fetch_tree(report):
    start = time.time()
    polls = 0
    ok = False
    while True:
        polls += 1
        ok = need_ready()
        if ok or time.time() - start > WAIT_MIN * 60:
            break
        time.sleep(60)
    report["tree"] = {"waited_seconds": int(time.time() - start),
                      "polls": polls, "prereg_seen": ok}
    with _get(TARBALL, 300) as resp:
        data = resp.read()
    shutil.rmtree("tree.tmp", ignore_errors=True)
    os.makedirs("tree.tmp")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall("tree.tmp", filter="data")
    tops = os.listdir("tree.tmp")
    if len(tops) != 1:
        report["tree"]["error"] = "unexpected layout %r" % tops
        return
    shutil.rmtree("tree", ignore_errors=True)
    os.rename(os.path.join("tree.tmp", tops[0]), "tree")
    shutil.rmtree("tree.tmp", ignore_errors=True)
    versions = {}
    for rel in ("pickle_model_scan.py", "model_file_scan.py"):
        path = os.path.join("tree", rel)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                m = VER_RE.search(fh.read())
            versions[rel] = m.group(1) if m else "no version"
        except OSError:
            versions[rel] = None
    report["tree"].update(tarball_bytes=len(data), versions=versions,
                          prereg_in_tree=os.path.isfile(
                              os.path.join("tree", *NEED.split("/"))))


def download(url, path, cap):
    digest = hashlib.sha256()
    total = 0
    with _get(url, 300) as resp, open(path, "wb") as fh:
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ValueError("larger than %d bytes" % cap)
            digest.update(chunk)
            fh.write(chunk)
    return total, digest.hexdigest()


def fetch_hub(report):
    out_dir = os.path.join("hub", "files")
    os.makedirs(out_dir, exist_ok=True)
    man = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "list": None, "files": [], "skipped_gated": [], "pinned": []}
    total_bytes = 0
    try:
        with _get(LIST_URL, 300) as resp:
            models = json.loads(resp.read())
        man["list"] = len(models)
    except Exception as exc:
        man["list"] = "error: %s: %s" % (type(exc).__name__, exc)
        models = []
    taken = tries = n = 0
    for m in models:
        if taken >= MAX_FILES or tries >= MAX_TRIES or total_bytes > MAX_TOTAL:
            break
        mid = m.get("id") or m.get("modelId")
        if not mid or mid == PINNED_REPO:
            continue
        sibs = m.get("siblings") or []
        rfs = [s.get("rfilename", "") for s in sibs if isinstance(s, dict)]
        picked = [r for r in rfs if CAND.search(r.rsplit("/", 1)[-1])]
        picked = picked[:PER_MODEL]
        if not picked:
            continue
        if m.get("gated") or m.get("private"):
            man["skipped_gated"].append(mid)
            continue
        sha = m.get("sha") or "main"
        for rf in picked:
            if taken >= MAX_FILES or tries >= MAX_TRIES \
                    or total_bytes > MAX_TOTAL:
                break
            tries += 1
            n += 1
            entry = {"n": n, "model": mid, "rfilename": rf, "revision": sha}
            dst_dir = os.path.join(out_dir, "%04d" % n)
            os.makedirs(dst_dir, exist_ok=True)
            path = os.path.join(dst_dir, rf.rsplit("/", 1)[-1])
            try:
                time.sleep(PAUSE)
                size, digest = download(
                    "https://huggingface.co/%s/resolve/%s/%s" % (
                        urllib.parse.quote(mid, safe="/"), sha,
                        urllib.parse.quote(rf, safe="/")), path, MAX_BYTES)
                total_bytes += size
                entry.update(status="ok", bytes=size, sha256=digest,
                             path=os.path.relpath(path).replace(os.sep, "/"))
                taken += 1
            except Exception as exc:
                entry["status"] = "error: %s: %s" % (type(exc).__name__,
                                                     str(exc)[:160])
                for p in (path,):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                try:
                    os.rmdir(dst_dir)
                except OSError:
                    pass
            man["files"].append(entry)
    pdir = os.path.join("hub", "pinned")
    os.makedirs(pdir, exist_ok=True)
    for rf in PINNED:
        entry = {"model": PINNED_REPO, "rfilename": rf,
                 "revision": PINNED_REV}
        path = os.path.join(pdir, rf.rsplit("/", 1)[-1])
        try:
            time.sleep(PAUSE)
            size, digest = download(
                "https://huggingface.co/%s/resolve/%s/%s" % (
                    PINNED_REPO, PINNED_REV, urllib.parse.quote(rf, safe="/")),
                path, 45_000_000)
            entry.update(status="ok", bytes=size, sha256=digest,
                         path=os.path.relpath(path).replace(os.sep, "/"))
        except Exception as exc:
            entry["status"] = "error: %s: %s" % (type(exc).__name__,
                                                 str(exc)[:160])
        man["pinned"].append(entry)
    man["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    man["ok_files"] = sum(1 for f in man["files"] if f["status"] == "ok")
    man["total_bytes"] = total_bytes
    with open(os.path.join("hub", "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(man, fh, indent=1)
    report["hub"] = {"list": man["list"], "ok_files": man["ok_files"],
                     "pinned_ok": sum(1 for f in man["pinned"]
                                      if f["status"] == "ok"),
                     "total_bytes": total_bytes}


def main():
    report = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    for step in (fetch_tree, fetch_hub):
        try:
            step(report)
        except Exception as exc:
            report.setdefault("errors", []).append(
                "%s: %s: %s" % (step.__name__, type(exc).__name__, exc))
    report["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open("fetch_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_jl failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
