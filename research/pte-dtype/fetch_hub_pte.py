#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step for jobs pte-census-v1 and pte-dtype-v1 (same code): collect
the bytes needed to run executorch_pte_scan on published ExecuTorch programs
(.pte) from the Hugging Face Hub, exactly as it would run on the whole files.

1. Lists open (not gated, not private) models tagged `executorch`, sorted
   by downloads (public API, no authentication, up to PAGES pages of 1,000),
   and records per model which COUNTED extensions it ships.
2. Orders every .pte file by model downloads, then model id and file name,
   keeping at most PER_MODEL files per model. For up to PROBE_BUDGET files
   one HTTP Range request reads the first 64 bytes and the total size.
3. The scanner reads only the eh00 header and the FlatBuffer program (the
   first program_size bytes); it never reads segment bytes. For each probed
   file with an ET12 identifier the first program_size bytes are fetched with
   one Range request (or the whole file when it has no extended header), if
   that is at most CAP bytes, within a total of TOTAL_BUDGET bytes.
4. Up to WHOLE_MAX files of at most CAP bytes in total are downloaded whole,
   so the run step can check that a scan of (program bytes + true length)
   equals a scan of the whole file.
Nothing is loaded or executed; files are only read as bytes. Writes
hub/pte_census_fetch.json. Never fails setup.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

from pte_lib import COUNTED, ext_of, fetch_plan, next_link, parse_head

LIST_URL = ("https://huggingface.co/api/models?sort=downloads&direction=-1"
            "&limit=1000&full=true&filter=executorch")
PAGES = 3
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan .pte census)"
PAUSE = 0.3
PAGE_PAUSE = 1.0
PER_MODEL = 3
PROBE_BUDGET = 450
CAP = 25_000_000
TOTAL_BUDGET = 1_500_000_000
WHOLE_MAX = 40
RANGE_RX = re.compile(r"/(\d+)\s*$")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def url_for(mid, rf):
    return "https://huggingface.co/%s/resolve/main/%s" % (
        urllib.parse.quote(mid, safe="/"), urllib.parse.quote(rf, safe="/"))


def fetch_range(url, start, end):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Range": "bytes=%d-%d" % (start, end)})
    with urllib.request.urlopen(req, timeout=300) as resp:
        want = end - start + 1
        data = resp.read(want)  # never more, even if the range is ignored
        total = None
        m = RANGE_RX.search(resp.headers.get("Content-Range") or "")
        if m:
            total = int(m.group(1))
        elif resp.status == 200 and resp.headers.get("Content-Length"):
            total = int(resp.headers["Content-Length"])
        return data, total, resp.status


def collect(rep):
    files = []
    url = LIST_URL
    entry = {"pages": 0, "models": 0, "open": 0, "ext_models": {},
             "pte_files": 0, "error": None}
    rank = 0
    for _ in range(PAGES):
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
            if ".pte" in exts and ".ptd" in exts:
                entry["ext_models"]["pte+ptd"] = entry["ext_models"].get(
                    "pte+ptd", 0) + 1
            ptes = sorted(r for r in rfs if ext_of(r) == ".pte")
            entry["pte_files"] += len(ptes)
            for r in ptes[:PER_MODEL]:
                files.append({"model": mid, "rfilename": r, "rank": rank,
                              "downloads": m.get("downloads"),
                              "library": m.get("library_name"),
                              "pte_in_model": len(ptes)})
    rep["list"] = entry
    print("list: %s" % json.dumps(entry), flush=True)
    return files


def main():
    os.makedirs(os.path.join("hub", "prog"), exist_ok=True)
    os.makedirs(os.path.join("hub", "whole"), exist_ok=True)
    rep = {"started": now(), "files": [],
           "budgets": {"PAGES": PAGES, "PER_MODEL": PER_MODEL,
                       "PROBE_BUDGET": PROBE_BUDGET, "CAP": CAP,
                       "TOTAL_BUDGET": TOTAL_BUDGET, "WHOLE_MAX": WHOLE_MAX}}
    files = collect(rep)
    files.sort(key=lambda f: (-(f.get("downloads") or 0), f["model"],
                              f["rfilename"]))
    rep["candidates"] = len(files)
    spent, whole_n = 0, 0
    for n, f in enumerate(files[:PROBE_BUDGET], 1):
        f["n"] = n
        url = url_for(f["model"], f["rfilename"])
        try:
            time.sleep(PAUSE)
            head, total, status = fetch_range(url, 0, 63)
            info = parse_head(head)
            f.update(size=total, status=status, head_hex=head[:48].hex(),
                     info=info)
        except Exception as exc:
            f["error"] = "probe %s: %s" % (type(exc).__name__, str(exc)[:160])
            rep["files"].append(f)
            continue
        if info.get("identifier") != "ET12":
            f["plan"] = [None, "identifier is not ET12"]
            rep["files"].append(f)
            continue
        want, why = fetch_plan(info, total, CAP)
        f["plan"] = [want, why]
        if want is not None and spent + want > TOTAL_BUDGET:
            f["plan"] = [None, "total budget used up"]
            want = None
        if want is not None:
            try:
                time.sleep(PAUSE)
                data, total2, status2 = fetch_range(url, 0, want - 1)
                if len(data) != want or (total2 is not None and total2 != total):
                    raise ValueError("got %d of %d bytes (total %s vs %s)" % (
                        len(data), want, total2, total))
                path = os.path.join("hub", "prog", "%04d.bin" % n)
                with open(path, "wb") as fh:
                    fh.write(data)
                spent += want
                f["prog"] = path
            except Exception as exc:
                f["error"] = "program %s: %s" % (type(exc).__name__,
                                                 str(exc)[:160])
        if (f.get("prog") and isinstance(total, int) and total <= CAP
                and whole_n < WHOLE_MAX and spent + total <= TOTAL_BUDGET):
            try:
                if want == total:
                    with open(f["prog"], "rb") as fh:
                        data = fh.read()
                else:
                    time.sleep(PAUSE)
                    data, _t, _s = fetch_range(url, 0, total - 1)
                    spent += len(data)
                if len(data) != total:
                    raise ValueError("got %d of %d bytes" % (len(data), total))
                path = os.path.join("hub", "whole", "%04d.pte" % n)
                with open(path, "wb") as fh:
                    fh.write(data)
                f["whole"] = path
                whole_n += 1
            except Exception as exc:
                f["whole_error"] = "%s: %s" % (type(exc).__name__,
                                               str(exc)[:160])
        rep["files"].append(f)
    rep["bytes_fetched"] = spent
    rep["finished"] = now()
    with open(os.path.join("hub", "pte_census_fetch.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"candidates": rep["candidates"],
                      "probed": len(rep["files"]),
                      "programs": sum(1 for f in rep["files"] if f.get("prog")),
                      "whole": whole_n, "bytes": spent}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_pte failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
