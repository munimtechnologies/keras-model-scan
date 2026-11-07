#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step of job pkl-diag-v1 (network allowed here only).

1. Wait (up to WAIT_MIN minutes) until keras-model-scan's main branch carries
   research/pkl-memo/results/patched/pickle_model_scan.py at 0.3.0 (the file
   job pkl-memo-v1 wrote, published with its write-up), then download main
   as ./tree.
2. Download three public files from the Hugging Face model repo
   OKTAYBBS/DataScientst-models, pinned to the repo's current commit:
   classification/churn_model.pkl and classification/mobile_model.pkl (the
   two files on which pickle_model_scan 0.3.0 still reported PKL007 in job
   pkl-memo-v1) and classification/wine_model.pkl (same author and folder,
   not in that job's sample). Streamed to disk in 1 MB chunks, 45 MB cap.

The files are only read as bytes later; nothing is unpickled or loaded.
Writes fetch_report.json. Never fails setup (the check grades F0 instead).

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
NEED = "research/pkl-memo/results/patched/pickle_model_scan.py"
NEED_VERSION = '__version__ = "0.3.0"'
WAIT_MIN = 120
HUB_REPO = "OKTAYBBS/DataScientst-models"
HUB_FILES = [
    "classification/churn_model.pkl",
    "classification/mobile_model.pkl",
    "classification/wine_model.pkl",
]
MAX_BYTES = 45_000_000
CHUNK = 1 << 20
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan pickle check)"
VER_RE = re.compile(r'(?m)^__version__\s*=\s*"(\d+\.\d+\.\d+)"')


def _get(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Cache-Control": "no-cache"})
    return urllib.request.urlopen(req, timeout=timeout)


def need_ready():
    try:
        with _get(RAW + NEED + "?t=%d" % int(time.time()), 60) as resp:
            return NEED_VERSION in resp.read().decode("utf-8", "replace")
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
                      "polls": polls, "ready_seen": ok}
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
    for rel in ("pickle_model_scan.py", "joblib_pickle_scan.py",
                "model_file_scan.py", NEED):
        path = os.path.join("tree", *rel.split("/"))
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                m = VER_RE.search(fh.read())
            versions[rel] = m.group(1) if m else "no version"
        else:
            versions[rel] = None
    report["tree"].update(tarball_bytes=len(data), versions=versions)


def fetch_hub(report):
    hub = {"repo": HUB_REPO, "files": []}
    report["hub"] = hub
    try:
        with _get("https://huggingface.co/api/models/%s" % HUB_REPO) as resp:
            info = json.loads(resp.read())
        sha = info.get("sha") or "main"
    except Exception as exc:
        sha = "main"
        hub["api_error"] = "%s: %s" % (type(exc).__name__, exc)
    hub["revision"] = sha
    os.makedirs("hub", exist_ok=True)
    for i, rf in enumerate(HUB_FILES, 1):
        entry = {"rfilename": rf}
        dst_dir = os.path.join("hub", "%02d" % i)
        os.makedirs(dst_dir, exist_ok=True)
        path = os.path.join(dst_dir, rf.rsplit("/", 1)[-1])
        url = "https://huggingface.co/%s/resolve/%s/%s" % (
            urllib.parse.quote(HUB_REPO, safe="/"), sha,
            urllib.parse.quote(rf, safe="/"))
        try:
            time.sleep(0.3)
            digest = hashlib.sha256()
            total = 0
            with _get(url, 300) as resp, open(path, "wb") as fh:
                while True:
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise ValueError("larger than %d bytes" % MAX_BYTES)
                    digest.update(chunk)
                    fh.write(chunk)
            entry.update(status="ok", bytes=total, sha256=digest.hexdigest(),
                         path=path.replace(os.sep, "/"))
        except Exception as exc:
            entry["status"] = "error: %s: %s" % (type(exc).__name__,
                                                 str(exc)[:160])
            try:
                os.remove(path)
            except OSError:
                pass
        hub["files"].append(entry)


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
        print("fetch_diag failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
