#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step (no network): write honest files with torch and pickle, then load
each one back as ground truth.

  bn_<N>.pt          state_dict of a tiny Conv2d + BatchNorm2d + Linear model
                     after exactly N training-mode forward passes, N in 127,
                     128, 129, 384. BatchNorm counts them in
                     num_batches_tracked, an int64 scalar that torch.save
                     stores as its own 8-byte storage, little-endian, so for
                     N = 128 and 384 its first byte is 0x80.
  mlp_<SSS>.pt       state_dict of an 8-layer 16x16 MLP at its default random
                     initialisation, seeds 0-199 (16 float32 storages each).
  ts_mlp.pt          the same MLP (seed 0) saved by torch.jit (TorchScript).
  ep_mlp.pt2         the same MLP (seed 0) saved by torch.export (if
                     available; reported only).
  legacy_bn_128.pt   bn_128's state_dict in the legacy (non-zip) format
                     (_use_new_zipfile_serialization=False); control.
  state.pkl          one pickle.dump of a plain dict at protocol 4; control.

The same writers and seeds as job zip-storage-v1, plus the two controls.
No byte of any file is written by hand. Writes local/local_manifest.json.
Catches its own exceptions, exits 0.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import datetime
import json
import os
import pickle
import sys
import traceback

OUT = "local"
NS = (127, 128, 129, 384)
SEEDS = range(200)


def main():
    os.makedirs(OUT, exist_ok=True)
    man = {"files": {}, "errors": []}
    try:
        path = os.path.join(OUT, "state.pkl")
        obj = {"epoch": 3, "lr": 0.01, "when": datetime.date(2026, 11, 9),
               "names": ["a", "b"]}
        with open(path, "wb") as fh:
            pickle.dump(obj, fh, protocol=4)
        with open(path, "rb") as fh:
            man["files"]["state.pkl"] = {"kind": "control",
                                         "load_ok": pickle.load(fh) == obj}
    except Exception as exc:
        man["files"]["state.pkl"] = {"kind": "control", "load_ok": False,
                                     "error": "%s: %s" % (type(exc).__name__,
                                                          exc)}
    try:
        import torch
        import torch.nn as nn
        man["torch"] = torch.__version__
    except Exception as exc:
        man["errors"].append("torch import: %s" % exc)
        return man

    def bn_model():
        torch.manual_seed(0)
        return nn.Sequential(nn.Conv2d(3, 4, 3), nn.BatchNorm2d(4), nn.ReLU(),
                             nn.Flatten(), nn.Linear(4 * 6 * 6, 2))

    def mlp(seed):
        torch.manual_seed(seed)
        return nn.Sequential(*[nn.Linear(16, 16) for _ in range(8)])

    for n in NS:
        name = "bn_%d.pt" % n
        try:
            m = bn_model()
            m.train()
            torch.manual_seed(1)
            x = torch.randn(2, 3, 8, 8)
            with torch.no_grad():
                for _ in range(n):
                    m(x)
            path = os.path.join(OUT, name)
            torch.save(m.state_dict(), path)
            sd = torch.load(path, weights_only=True)
            man["files"][name] = {
                "kind": "bn", "n": n, "load_ok": True,
                "num_batches_tracked": int(sd["1.num_batches_tracked"])}
            if n == 128:
                lpath = os.path.join(OUT, "legacy_bn_128.pt")
                torch.save(m.state_dict(), lpath,
                           _use_new_zipfile_serialization=False)
                lsd = torch.load(lpath, weights_only=True)
                man["files"]["legacy_bn_128.pt"] = {
                    "kind": "control", "load_ok": True,
                    "num_batches_tracked": int(lsd["1.num_batches_tracked"])}
        except Exception as exc:
            man["files"][name] = {"kind": "bn", "n": n, "load_ok": False,
                                  "error": "%s: %s" % (type(exc).__name__, exc)}
    for seed in SEEDS:
        name = "mlp_%03d.pt" % seed
        try:
            path = os.path.join(OUT, name)
            torch.save(mlp(seed).state_dict(), path)
            sd = torch.load(path, weights_only=True)
            man["files"][name] = {"kind": "mlp", "seed": seed,
                                  "load_ok": True, "tensors": len(sd)}
        except Exception as exc:
            man["files"][name] = {"kind": "mlp", "seed": seed, "load_ok": False,
                                  "error": "%s: %s" % (type(exc).__name__, exc)}
    try:
        path = os.path.join(OUT, "ts_mlp.pt")
        torch.jit.script(mlp(0)).save(path)
        torch.jit.load(path)
        man["files"]["ts_mlp.pt"] = {"kind": "torchscript", "load_ok": True}
    except Exception as exc:
        man["files"]["ts_mlp.pt"] = {"kind": "torchscript", "load_ok": False,
                                     "error": "%s: %s" % (type(exc).__name__,
                                                          str(exc)[:300])}
    try:
        path = os.path.join(OUT, "ep_mlp.pt2")
        ep = torch.export.export(mlp(0), (torch.randn(1, 16),))
        torch.export.save(ep, path)
        torch.export.load(path)
        man["files"]["ep_mlp.pt2"] = {"kind": "export", "load_ok": True}
    except Exception as exc:
        man["files"]["ep_mlp.pt2"] = {"kind": "export", "load_ok": False,
                                      "error": "%s: %s" % (type(exc).__name__,
                                                           str(exc)[:300])}
    return man


if __name__ == "__main__":
    try:
        result = main()
    except Exception:
        result = {"files": {}, "errors": [traceback.format_exc()[-800:]]}
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "local_manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(result, fh, indent=1)
    print(json.dumps({"files": len(result.get("files", {})),
                      "errors": result.get("errors")}))
    sys.exit(0)
