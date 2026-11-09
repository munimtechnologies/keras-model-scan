#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one version of pickle_model_scan on files, in its own process.

Usage: probe.py VERSION_DIR OUT_JSON FILE...
For each file: pickle_walk() of the whole file (and of each *.pkl member when
the file is a zip, as torch.save's data.pkl), and scan_file() findings. Only
reads bytes; nothing is unpickled. Always exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import sys
import zipfile


def main():
    vdir, out, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    sys.path.insert(0, vdir)
    import pickle_model_scan as pms
    res = {"version": pms.__version__, "files": {}}
    for path in files:
        r = {}
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            r["length"] = len(data)
            if data[:4] == b"PK\x03\x04":
                members = {}
                with zipfile.ZipFile(path) as zf:
                    for name in zf.namelist():
                        if name.endswith(".pkl"):
                            members[name] = pms.pickle_walk(zf.read(name), name)
                r["members"] = members
            else:
                r["walk"] = pms.pickle_walk(data, path)
            r["findings"] = [f.as_dict() for f in (pms.scan_file(path) or [])]
        except Exception as exc:
            r["error"] = "%s: %s" % (type(exc).__name__, exc)
        res["files"][path] = r
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
