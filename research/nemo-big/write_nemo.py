#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Write honest .nemo files the way NeMo's SaveRestoreConnector does (run in a
child process): torch.save(state_dict, "model_weights.ckpt") next to a
model_config.yaml, then tarfile.open(filename, "w:") / tar.add(folder,
arcname="."). Older NeMo releases wrote "w:gz"; one file uses that.
Every tensor is zeros: these files test size handling, not content.

Usage: write_nemo.py WORKDIR   (writes WORKDIR/<case>.nemo and
WORKDIR/writer_report.json; always exits 0)

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import collections
import json
import os
import shutil
import sys
import tarfile
import traceback

BIG_N = 280_000_000          # > 256 MiB (268,435,456)
SMALL_N = 4_000_000
CONFIG = (b"target: mv2.check.SizeModel\nsample_rate: 16000\n"
          b"note: written by keras-model-scan research/nemo-big\n")


def make(work, case, n, mode, legacy=False):
    import torch
    folder = os.path.join(work, case + "_folder")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "model_config.yaml"), "wb") as fh:
        fh.write(CONFIG)
    sd = collections.OrderedDict()
    sd["encoder.weight"] = torch.zeros(n, dtype=torch.uint8)
    sd["decoder.bias"] = torch.zeros(16, dtype=torch.float32)
    ckpt = os.path.join(folder, "model_weights.ckpt")
    if legacy:
        torch.save(sd, ckpt, _use_new_zipfile_serialization=False)
    else:
        torch.save(sd, ckpt)
    with open(ckpt, "rb") as fh:
        head = fh.read(4)
    size = os.path.getsize(ckpt)
    del sd
    path = os.path.join(work, case + ".nemo")
    with tarfile.open(path, mode) as tar:
        tar.add(folder, arcname=".")
    shutil.rmtree(folder, ignore_errors=True)
    with tarfile.open(path, "r:*") as tar:
        names = tar.getnames()
    return {"weights_bytes": size, "weights_head": head.hex(),
            "nemo_bytes": os.path.getsize(path), "members": names,
            "mode": mode}


def main():
    work = os.path.abspath(sys.argv[1])
    os.makedirs(work, exist_ok=True)
    rep = {"ok": False, "cases": {}}
    try:
        import torch
        rep["torch"] = torch.__version__
        for case, n, mode in (("w_small", SMALL_N, "w:"),
                              ("w_big", BIG_N, "w:"),
                              ("w_big_gz", BIG_N, "w:gz")):
            rep["cases"][case] = make(work, case, n, mode)
        rep["ok"] = True
    except Exception as exc:
        rep["error"] = "%s: %s" % (type(exc).__name__, exc)
        rep["traceback"] = traceback.format_exc()[-3000:]
    try:   # reported only: legacy (pre-1.6) torch.save format
        rep["cases"]["w_legacy_big"] = make(work, "w_legacy_big", BIG_N, "w:",
                                            legacy=True)
    except Exception as exc:
        rep["legacy_error"] = "%s: %s" % (type(exc).__name__, exc)
    with open(os.path.join(work, "writer_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({k: v for k, v in rep.items() if k != "traceback"},
                     indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
