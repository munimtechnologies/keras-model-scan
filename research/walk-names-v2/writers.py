#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Write HONEST files with the real libraries, under the names their own
code or docs use, then load each one back with the same library (ground
truth: the library reads the file as a pickle-based model file).

Usage: writers.py KIND DIR      KIND in tv_pth_tar, legacy_pth_tar,
                                pd_params, joblib_c, limits, controls
Prints one JSON line {"files": [...], "loaded": {...}, "magic": {...}}.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import os
import shutil
import sys
import tarfile


def magic(path):
    with open(path, "rb") as fh:
        return fh.read(4).hex()


def tv_pth_tar(d):
    # pytorch/examples imagenet/main.py: save_checkpoint(state, is_best,
    # filename='checkpoint.pth.tar') -> torch.save; best copied with shutil.
    import torch
    model = torch.nn.Sequential(torch.nn.Linear(4, 3), torch.nn.ReLU(),
                                torch.nn.Linear(3, 2))
    opt = torch.optim.SGD(model.parameters(), lr=0.1, momentum=0.9)
    model(torch.randn(5, 4)).sum().backward()
    opt.step()
    state = {"epoch": 1, "arch": "tiny", "state_dict": model.state_dict(),
             "best_acc1": torch.tensor(0.5), "optimizer": opt.state_dict()}
    f = os.path.join(d, "checkpoint.pth.tar")
    torch.save(state, f)
    shutil.copyfile(f, os.path.join(d, "model_best.pth.tar"))
    loaded = {}
    for n in ("checkpoint.pth.tar", "model_best.pth.tar"):
        torch.load(os.path.join(d, n), weights_only=True)
        loaded[n] = "torch.load(weights_only=True) ok"
    return loaded


def legacy_pth_tar(d):
    import torch
    model = torch.nn.Linear(4, 2)
    f = os.path.join(d, "checkpoint.pth.tar")
    torch.save({"epoch": 1, "state_dict": model.state_dict()}, f,
               _use_new_zipfile_serialization=False)
    torch.load(f, weights_only=True)
    return {"checkpoint.pth.tar": "torch.load(weights_only=True) ok"}


def pd_params(d):
    import paddle
    layer = paddle.nn.Linear(4, 2)
    opt = paddle.optimizer.Adam(parameters=layer.parameters())
    layer(paddle.randn([3, 4])).mean().backward()
    opt.step()
    paddle.save(layer.state_dict(), os.path.join(d, "model.pdparams"))
    paddle.save(opt.state_dict(), os.path.join(d, "model.pdopt"))
    loaded = {}
    for n in ("model.pdparams", "model.pdopt"):
        paddle.load(os.path.join(d, n))
        loaded[n] = "paddle.load ok"
    return loaded


def _obj():
    import numpy as np
    return {"coef": np.arange(12, dtype=np.float64).reshape(3, 4),
            "intercept": np.zeros(3, dtype=np.float32),
            "n_iter": 7, "params": {"alpha": 0.1, "fit_intercept": True}}


def joblib_c(d):
    # joblib.dump infers the compressor from the file name's ending.
    import joblib
    names = ["model.joblib.%s" % e for e in ("z", "gz", "bz2", "xz", "lzma")]
    names.append("model.pkl.gz")
    try:
        import lz4  # noqa: F401
        names.append("model.joblib.lz4")
    except Exception:
        pass
    loaded = {}
    for n in names:
        p = os.path.join(d, n)
        joblib.dump(_obj(), p)
        joblib.load(p)
        loaded[n] = "joblib.load ok"
    return loaded


def limits(d):
    # joblib also compresses a bare 'model.gz'; the walk fix does not pick up
    # a bare .gz (too broad), so this is a documented limit, not a gate.
    import joblib
    p = os.path.join(d, "model.gz")
    joblib.dump(_obj(), p)
    joblib.load(p)
    return {"model.gz": "joblib.load ok"}


def controls(d):
    import gzip
    import lzma
    csv = b"a,b\n1,2\n"
    with tarfile.open(os.path.join(d, "data.tar"), "w") as t:
        info = tarfile.TarInfo("data.csv")
        info.size = len(csv)
        t.addfile(info, io.BytesIO(csv))
    with tarfile.open(os.path.join(d, "logs.tar.gz"), "w:gz") as t:
        info = tarfile.TarInfo("train.log")
        info.size = len(csv)
        t.addfile(info, io.BytesIO(csv))
    with open(os.path.join(d, "notes.txt.gz"), "wb") as fh:
        fh.write(gzip.compress(b"hello\n"))
    with open(os.path.join(d, "archive.tar.xz"), "wb") as fh:
        fh.write(lzma.compress(b"not really a tar\n"))
    return {}


KINDS = {"tv_pth_tar": tv_pth_tar, "legacy_pth_tar": legacy_pth_tar,
         "pd_params": pd_params, "joblib_c": joblib_c, "limits": limits,
         "controls": controls}


def main():
    kind, d = sys.argv[1], sys.argv[2]
    os.makedirs(d, exist_ok=True)
    err = None
    try:
        loaded = KINDS[kind](d)
    except Exception as exc:
        loaded = {}
        err = "%s: %s" % (type(exc).__name__, str(exc)[:300])
    files = sorted(os.listdir(d))
    print(json.dumps({"files": files, "loaded": loaded, "error": err,
                      "magic": {f: magic(os.path.join(d, f)) for f in files}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
