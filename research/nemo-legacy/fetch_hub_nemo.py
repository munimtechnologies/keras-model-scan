#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: what is inside the most downloaded public .nemo files on
Hugging Face, and in which format is their checkpoint saved?

Lists the 100 most downloaded models tagged `nemo` (non-gated, public) and
their .nemo files (at most 2 per repo, 120 files in all). For each file it
reads only tar headers, with HTTP Range requests: the first 1,024 bytes say
whether the file is a plain tar (walked) or compressed (gzip/bz2/xz: counted,
not walked, because a compressed stream cannot be entered in the middle).
For a plain tar, each member's 512-byte header plus the first 64 bytes of its
content are read (one request per member, at most 80 members per file, 2,500
requests in all), and each member is classed:
  zip     starts with PK\\x03\\x04 (torch.save since PyTorch 1.6)
  legacy  a PROTO 2-5 pickle whose first value is torch's magic number
          0x1950A86A20F9469CFC6C (torch.save with
          _use_new_zipfile_serialization=False, the default before 1.6)
  pickle  another pickle (PROTO 2-5)
  other   anything else (YAML, tokenizer files, raw bytes, ...)
At most 3 files whose checkpoint is legacy and that are 100 MB or smaller are
downloaded whole, each in its own folder, for the static scan later. Nothing
is unpickled, extracted or loaded. No authentication.
Writes hub/nemo_census.json. Never fails setup.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

LIST = ("https://huggingface.co/api/models?filter=nemo&sort=downloads"
        "&direction=-1&limit=100&full=true")
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; model-file-scan nemo census)"
PAUSE = 0.1
PER_REPO = 2
FILE_BUDGET = 120
REQUEST_BUDGET = 2500
MAX_MEMBERS_WALK = 80
MAX_DOWNLOADS = 3
MAX_BYTES = 100_000_000
MAGIC_LE = bytes.fromhex("6cfc9c46f9206aa85019")
RANGE_RX = re.compile(r"/(\d+)\s*$")
WEIGHT_RX = re.compile(r"\.(?:ckpt|pt|pth|bin)$", re.I)

state = {"requests": 0}


def classify(head):
    if not head:
        return "empty"
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        if b"\x8a\x0a" + MAGIC_LE in head[:32]:
            return "legacy"
        return "pickle"
    return "other"


def container(head):
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "plain"
    return "other"


def url_for(mid, rf):
    return "https://huggingface.co/%s/resolve/main/%s" % (
        urllib.parse.quote(mid, safe="/"), urllib.parse.quote(rf, safe="/"))


def ranged(url, start, length):
    """(bytes, total size or None, HTTP status, final URL)."""
    if state["requests"] >= REQUEST_BUDGET:
        raise RuntimeError("request budget used up")
    state["requests"] += 1
    time.sleep(PAUSE)
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Range": "bytes=%d-%d" % (start, start + length - 1)})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read(length)
        total = None
        m = RANGE_RX.search(resp.headers.get("Content-Range") or "")
        if m:
            total = int(m.group(1))
        elif resp.status == 200 and resp.headers.get("Content-Length"):
            total = int(resp.headers["Content-Length"])
        return data, total, resp.status, resp.geturl()


def nts(b):
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def tar_size(field):
    if field[:1] and field[0] & 0x80:  # GNU base-256
        return int.from_bytes(field[1:], "big")
    s = field.split(b"\0", 1)[0].strip()
    return int(s, 8) if s else 0


def pax_records(blob):
    out = {}
    pos = 0
    while pos < len(blob):
        sp = blob.find(b" ", pos)
        if sp < 0:
            break
        try:
            n = int(blob[pos:sp])
        except ValueError:
            break
        if n <= 0:
            break
        rec = blob[sp + 1:pos + n - 1]
        k, _, v = rec.partition(b"=")
        out[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
        pos += n
    return out


def walk_tar(url, head, total):
    """Walk a plain tar's headers. Returns (members, capped, error); the
    members read before an error are kept."""
    members = []
    try:
        return _walk(url, head, total, members)
    except Exception as exc:
        return members, False, "%s: %s" % (type(exc).__name__, str(exc)[:160])


def _walk(url, head, total, members):
    offset = 0
    pend_name, pend_size = None, None
    for _ in range(MAX_MEMBERS_WALK * 2):
        if len(members) >= MAX_MEMBERS_WALK:
            return members, True, None
        if total is not None and offset + 512 > total:
            break
        if offset + 576 <= len(head):
            blk = head[offset:offset + 576]
        else:
            blk, _t, status, _u = ranged(url, offset, 576)
            if status != 206:
                return members, False, "range not honoured (HTTP %d)" % status
        hdr = blk[:512]
        if len(hdr) < 512 or hdr == b"\0" * 512:
            break
        name = nts(hdr[0:100])
        if hdr[257:262] == b"ustar":
            prefix = nts(hdr[345:500])
            if prefix:
                name = prefix + "/" + name
        size = tar_size(hdr[124:136])
        flag = hdr[156:157]
        nxt = offset + 512 + ((size + 511) // 512) * 512
        if flag in (b"L", b"x", b"g"):
            if flag != b"g" and 0 < size <= 65536:
                content, _t, _s, _u = ranged(url, offset + 512, size)
                if flag == b"L":
                    pend_name = nts(content)
                else:
                    rec = pax_records(content)
                    pend_name = rec.get("path", pend_name)
                    if rec.get("size", "").isdigit():
                        pend_size = int(rec["size"])
            offset = nxt
            continue
        if pend_name:
            name = pend_name
        if pend_size is not None:
            size = pend_size
            nxt = offset + 512 + ((size + 511) // 512) * 512
        pend_name, pend_size = None, None
        kind = ("dir" if flag == b"5" else
                classify(blk[512:576]) if flag in (b"0", b"\0", b"7") else
                "link" if flag in (b"1", b"2") else "special")
        members.append({"name": name, "size": size, "type": flag.decode(
            "latin-1") or "0", "kind": kind})
        offset = nxt
    return members, False, None


def main():
    os.makedirs(os.path.join("hub", "nemo"), exist_ok=True)
    rep = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "list": None, "files": [], "downloads": []}
    try:
        models = json.loads(urllib.request.urlopen(urllib.request.Request(
            LIST, headers={"User-Agent": UA}), timeout=300).read())
        rep["list"] = len(models)
    except Exception as exc:
        rep["list"] = "error: %s: %s" % (type(exc).__name__, exc)
        models = []
    plan = []
    for rank, m in enumerate(models, 1):
        mid = m.get("id") or m.get("modelId")
        if not mid or m.get("gated") or m.get("private"):
            continue
        rfs = sorted(s.get("rfilename", "") for s in (m.get("siblings") or [])
                     if isinstance(s, dict)
                     and s.get("rfilename", "").endswith(".nemo"))
        for rf in rfs[:PER_REPO]:
            plan.append((rank, mid, rf, m.get("downloads"),
                         m.get("lastModified")))
    rep["planned"] = len(plan)
    for rank, mid, rf, downloads, modified in plan[:FILE_BUDGET]:
        e = {"rank": rank, "model": mid, "rfilename": rf,
             "downloads": downloads, "last_modified": modified}
        try:
            head, total, status, final = ranged(url_for(mid, rf), 0, 1024)
            e.update(size=total, status=status, container=container(head))
            if e["container"] == "plain":
                members, capped, err = walk_tar(final, head, total)
                e.update(members=members, capped=capped, walk_error=err)
                e["weights"] = [x for x in members
                                if WEIGHT_RX.search(x["name"])
                                and x["type"] in ("0", "7")]
        except Exception as exc:
            e["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:160])
        rep["files"].append(e)
        if state["requests"] >= REQUEST_BUDGET:
            rep["budget_hit"] = True
            break
    picks = [e for e in rep["files"]
             if any(w["kind"] == "legacy" for w in e.get("weights") or [])
             and isinstance(e.get("size"), int) and e["size"] <= MAX_BYTES]
    for n, e in enumerate(picks[:MAX_DOWNLOADS], 1):
        d = {"n": n, "model": e["model"], "rfilename": e["rfilename"]}
        dst = os.path.join("hub", "nemo", "%02d" % n)
        os.makedirs(dst, exist_ok=True)
        try:
            req = urllib.request.Request(url_for(e["model"], e["rfilename"]),
                                         headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=600) as resp:
                data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("larger than %d bytes" % MAX_BYTES)
            path = os.path.join(dst, e["rfilename"].rsplit("/", 1)[-1])
            with open(path, "wb") as fh:
                fh.write(data)
            d.update(status="ok", bytes=len(data), path=os.path.relpath(path))
        except Exception as exc:
            d.update(status="error: %s: %s" % (type(exc).__name__,
                                               str(exc)[:160]))
        rep["downloads"].append(d)
    rep["requests"] = state["requests"]
    rep["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(os.path.join("hub", "nemo_census.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"list": rep["list"], "planned": rep["planned"],
                      "files": len(rep["files"]), "requests": rep["requests"],
                      "downloads": sum(1 for d in rep["downloads"]
                                       if d["status"] == "ok")}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # never fail setup
        print("fetch_hub_nemo failed: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        sys.exit(0)
