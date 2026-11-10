#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step for job pt2-census-v1: how often do published Hugging Face
models ship torch.export (.pt2), TorchScript (.torchscript) and PyTorch
mobile (.ptl) files, and what is inside a sample of them?

1. Lists, sorted by downloads (public API, no authentication):
     pytorch     models tagged `pytorch`, up to 10 pages of 1,000
     executorch  models tagged `executorch`, up to 3 pages
     all         all models, up to 2 pages
   For every open (not gated, not private) model it records which of the
   COUNTED extensions its file list has.
2. For every .pt2 / .torchscript / .ptl file found (budget HEAD_BUDGET), one
   HTTP Range request reads the first 64 bytes and the total size.
3. Zip files of at most MAX_BYTES are downloaded whole (up to MAX_PT2 .pt2
   and MAX_TS TorchScript-family files, distinct models first), each in its
   own folder, for the static scan in the run step.
4. For larger zip files (up to MAX_REMOTE), the zip central directory is
   read with Range requests (Python's zipfile over a ranged reader) to list
   member names, plus the first 4 bytes of up to MEMBER_READS chosen
   members. Nothing is decompressed beyond those bytes.
Nothing is unpickled, imported or loaded: files are only read as bytes.
Writes hub/archive_census.json. Never fails setup.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import zipfile

from census_lib import (COUNTED, NATIVE, TARGETS, classify_head, ext_of,
                        member_role, next_link)

BASE = "https://huggingface.co/api/models?sort=downloads&direction=-1&limit=1000&full=true"
LISTS = (("pytorch", BASE + "&filter=pytorch", 10),
         ("executorch", BASE + "&filter=executorch", 3),
         ("all", BASE, 2))
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan archive census)"
PAUSE = 0.2
PAGE_PAUSE = 1.0
HEAD_BUDGET = 150
MAX_BYTES = 25_000_000
MAX_PT2 = 10
MAX_TS = 10
MAX_REMOTE = 25
MEMBER_READS = 12
REMOTE_REQUESTS = 60
BLOCK = 65536
RANGE_RX = re.compile(r"/(\d+)\s*$")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def url_for(mid, rf):
    return "https://huggingface.co/%s/resolve/main/%s" % (
        urllib.parse.quote(mid, safe="/"), urllib.parse.quote(rf, safe="/"))


def fetch_range(url, start, end):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Range": "bytes=%d-%d" % (start, end)})
    with urllib.request.urlopen(req, timeout=120) as resp:
        want = end - start + 1
        data = resp.read(want)  # never more, even if the range is ignored
        total = None
        m = RANGE_RX.search(resp.headers.get("Content-Range") or "")
        if m:
            total = int(m.group(1))
        elif resp.status == 200 and resp.headers.get("Content-Length"):
            total = int(resp.headers["Content-Length"])
        return data, total, resp.status


class RangeFile(io.RawIOBase):
    """Read-only, seekable view of a remote file through Range requests,
    cached in BLOCK-sized blocks, with a hard request budget."""

    def __init__(self, url, size, budget=REMOTE_REQUESTS):
        super().__init__()
        self.url, self.size, self.budget = url, size, budget
        self.pos, self.cache, self.requests = 0, {}, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        else:
            self.pos = self.size + offset
        self.pos = max(0, self.pos)
        return self.pos

    def _block(self, i):
        if i not in self.cache:
            if self.requests >= self.budget:
                raise OSError("range request budget used up")
            start = i * BLOCK
            end = min(self.size, start + BLOCK) - 1
            time.sleep(PAUSE)
            data, _total, status = fetch_range(self.url, start, end)
            self.requests += 1
            if status != 206 and start > 0:
                raise OSError("server ignored the Range header")
            self.cache[i] = data
        return self.cache[i]

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = max(0, min(n, self.size - self.pos))
        out = bytearray()
        while n > 0:
            i = self.pos // BLOCK
            off = self.pos - i * BLOCK
            chunk = self._block(i)[off:off + n]
            if not chunk:
                break
            out += chunk
            self.pos += len(chunk)
            n -= len(chunk)
        return bytes(out)

    def readinto(self, b):
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


def pick_members(names):
    """Members whose first bytes are worth reading, in a fixed order."""
    chosen = []
    by_role = {}
    for n in names:
        by_role.setdefault(member_role(n), []).append(n)
    for role in ("native-library", "sample_inputs", "constants",
                 "legacy-export:serialized_state_dict.pt",
                 "legacy-export:serialized_constants.pt",
                 "legacy-export:serialized_example_inputs.pt", "weights"):
        for n in sorted(by_role.get(role, []))[:3]:
            if n not in chosen:
                chosen.append(n)
    return chosen[:MEMBER_READS]


def describe_zip(zf):
    names = [i.filename for i in zf.infolist()]
    roles = {}
    for n in names:
        r = member_role(n)
        roles[r] = roles.get(r, 0) + 1
    firsts = {}
    for n in pick_members(names):
        try:
            with zf.open(n) as fh:
                firsts[n] = fh.read(4).hex()
        except Exception as exc:
            firsts[n] = "error: %s" % type(exc).__name__
    return {"members": len(names), "names": names[:300], "roles": roles,
            "native": [n for n in names if ext_of(n) in NATIVE][:50],
            "first4": firsts}


def collect_lists(rep):
    """Census of extensions per list; returns {(model, rfilename): info}."""
    targets = {}
    for label, url, pages in LISTS:
        entry = {"pages": 0, "models": 0, "open": 0, "ext_models": {},
                 "error": None}
        rank = 0
        for _ in range(pages):
            if not url:
                break
            try:
                time.sleep(PAGE_PAUSE)
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=600) as resp:
                    models = json.loads(resp.read())
                    url = next_link(resp.headers.get("Link"))
            except Exception as exc:
                entry["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
                break
            entry["pages"] += 1
            for m in models:
                rank += 1
                entry["models"] += 1
                mid = m.get("id") or m.get("modelId")
                if not mid or m.get("gated") or m.get("private"):
                    continue
                entry["open"] += 1
                rfs = [s.get("rfilename", "") for s in (m.get("siblings") or [])
                       if isinstance(s, dict)]
                exts = {ext_of(r) for r in rfs}
                for e in COUNTED:
                    if e in exts:
                        entry["ext_models"][e] = entry["ext_models"].get(e, 0) + 1
                for key, group in (("torchscript|ptl", {".torchscript", ".ptl"}),
                                   ("any-target", set(TARGETS))):
                    if exts & group:
                        entry["ext_models"][key] = entry["ext_models"].get(key, 0) + 1
                for r in rfs:
                    if ext_of(r) in TARGETS:
                        t = targets.setdefault((mid, r), {
                            "model": mid, "rfilename": r, "ext": ext_of(r),
                            "lists": [], "rank": {},
                            "downloads": m.get("downloads"),
                            "last_modified": m.get("lastModified"),
                            "library": m.get("library_name")})
                        if label not in t["lists"]:
                            t["lists"].append(label)
                            t["rank"][label] = rank
            del models
        rep["lists"][label] = entry
        print("list %s: %s" % (label, json.dumps(entry)), flush=True)
    return targets


def main():
    os.makedirs(os.path.join("hub", "files"), exist_ok=True)
    rep = {"started": now(), "lists": {}, "targets": [], "downloads": [],
           "remote": [], "budgets": {"HEAD_BUDGET": HEAD_BUDGET,
                                     "MAX_BYTES": MAX_BYTES, "MAX_PT2": MAX_PT2,
                                     "MAX_TS": MAX_TS, "MAX_REMOTE": MAX_REMOTE}}
    targets = collect_lists(rep)
    # Most downloaded models first, then file name, so the order is fixed.
    order = sorted(targets.values(), key=lambda t: (
        -(t.get("downloads") or 0), t["model"], t["rfilename"]))
    rep["targets_found"] = len(order)
    for t in order[:HEAD_BUDGET]:
        try:
            time.sleep(PAUSE)
            head, total, status = fetch_range(url_for(t["model"], t["rfilename"]),
                                              0, 63)
            t.update(kind=classify_head(head), size=total, status=status,
                     head_hex=head[:16].hex())
        except Exception as exc:
            t.update(kind=None, error="%s: %s" % (type(exc).__name__,
                                                  str(exc)[:160]))
        rep["targets"].append(t)
    # Whole-file downloads of small zips, distinct models first.
    small = [t for t in rep["targets"] if t.get("kind") == "zip"
             and isinstance(t.get("size"), int) and t["size"] <= MAX_BYTES]
    picks, used = [], {"pt2": 0, "ts": 0}
    for pass_no in (0, 1):
        seen = {p["model"] for p in picks}
        for t in small:
            if t in picks or (pass_no == 0 and t["model"] in seen):
                continue
            fam = "pt2" if t["ext"] == ".pt2" else "ts"
            cap = MAX_PT2 if fam == "pt2" else MAX_TS
            if used[fam] >= cap:
                continue
            picks.append(t)
            used[fam] += 1
            seen.add(t["model"])
    for n, t in enumerate(picks, 1):
        d = {"n": n, "model": t["model"], "rfilename": t["rfilename"],
             "ext": t["ext"]}
        dst = os.path.join("hub", "files", "%02d" % n)
        os.makedirs(dst, exist_ok=True)
        try:
            time.sleep(PAUSE)
            req = urllib.request.Request(url_for(t["model"], t["rfilename"]),
                                         headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=600) as resp:
                data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("larger than %d bytes" % MAX_BYTES)
            path = os.path.join(dst, t["rfilename"].rsplit("/", 1)[-1])
            with open(path, "wb") as fh:
                fh.write(data)
            d.update(status="ok", bytes=len(data), path=os.path.relpath(path))
        except Exception as exc:
            d.update(status="error: %s: %s" % (type(exc).__name__,
                                               str(exc)[:160]))
        rep["downloads"].append(d)
    # Remote member listing of larger zips (names + a few first bytes).
    big = [t for t in rep["targets"] if t.get("kind") == "zip"
           and isinstance(t.get("size"), int) and t["size"] > MAX_BYTES]
    for t in big[:MAX_REMOTE]:
        r = {"model": t["model"], "rfilename": t["rfilename"], "ext": t["ext"],
             "size": t["size"]}
        rf = RangeFile(url_for(t["model"], t["rfilename"]), t["size"])
        try:
            with zipfile.ZipFile(rf) as zf:
                r.update(describe_zip(zf))
            r["status"] = "ok"
        except Exception as exc:
            r["status"] = "error: %s: %s" % (type(exc).__name__, str(exc)[:160])
        r["range_requests"] = rf.requests
        rep["remote"].append(r)
    rep["finished"] = now()
    with open(os.path.join("hub", "archive_census.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"lists": {k: [v["open"], v["ext_models"]]
                                for k, v in rep["lists"].items()},
                      "targets": rep["targets_found"],
                      "downloads": sum(1 for d in rep["downloads"]
                                       if d["status"] == "ok"),
                      "remote": sum(1 for r in rep["remote"]
                                    if r["status"] == "ok")}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_archives failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
