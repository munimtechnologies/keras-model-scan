#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""First setup step for job pte-dtype-v2: grading starts only once the
pre-registration is public. Polls the raw file on the repo's main branch
(up to about 60 minutes) until it exists and names this job, then records
its SHA-256 in prereg_check.json. Exits 1 if it never appears, so the job
stops before anything is graded.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import hashlib
import json
import sys
import time
import urllib.request

URL = ("https://raw.githubusercontent.com/munimtechnologies/keras-model-scan/"
       "main/research/PREREG_PTE_DTYPE_FIX_V2.md")
TOKEN = b"job pte-dtype-v2"
UA = "mv2-munim-research/1.0 (mv2@munimtech.com; prereg check)"
TRIES, PAUSE = 13, 300


def main():
    last = None
    for attempt in range(1, TRIES + 1):
        try:
            req = urllib.request.Request(URL, headers={"User-Agent": UA,
                                                       "Cache-Control": "no-cache"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            if TOKEN in data:
                rep = {"url": URL, "attempt": attempt, "bytes": len(data),
                       "sha256": hashlib.sha256(data).hexdigest(),
                       "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                with open("prereg_check.json", "w", encoding="utf-8") as fh:
                    json.dump(rep, fh, indent=1)
                print(json.dumps(rep))
                return 0
            last = "token not found"
        except Exception as exc:
            last = "%s: %s" % (type(exc).__name__, str(exc)[:160])
        print("attempt %d: %s" % (attempt, last), flush=True)
        if attempt < TRIES:
            time.sleep(PAUSE)
    print("pre-registration not public: %s" % last, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
