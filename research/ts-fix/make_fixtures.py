#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step: write HONEST model files with torch's own writers into ./fx and
record what torch's own loaders do with them (the ground truth). Same
fixtures as job torchscript-v1 (research/torchscript/make_fixtures.py).

Fixtures (one small ordinary model, nothing crafted):
  F1 model.pt           torch.jit.script(...) saved with torch.jit.save
  F2 model.torchscript  torch.jit.trace(...) saved with torch.jit.save
  F3 model.ptl          _save_for_lite_interpreter (PyTorch mobile)
  F4 model.pt2          torch.export.save
  F5 weights.pth        torch.save(state_dict)  (control, not TorchScript)

Writes fixtures_report.json. Never fails the job: a missing writer or loader
is recorded and its rows become "not run".

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import sys
import traceback
import warnings

FX = os.path.abspath("fx")


def err(exc):
    return "%s: %s" % (type(exc).__name__, str(exc).splitlines()[0][:300]
                       if str(exc) else "")


def main():
    rep = {"fixtures": {}, "loaders": {}, "errors": {}}
    os.makedirs(FX, exist_ok=True)
    try:
        import torch
        from torch import nn
    except Exception as exc:
        rep["errors"]["import_torch"] = err(exc)
        with open("fixtures_report.json", "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1)
        print(json.dumps(rep))
        return 0
    rep["torch"] = torch.__version__
    torch.manual_seed(0)

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc1 = nn.Linear(8, 16)
            self.bn = nn.BatchNorm1d(16)
            self.fc2 = nn.Linear(16, 4)

        def forward(self, x):
            return self.fc2(torch.relu(self.bn(self.fc1(x))))

    net = Net().eval()
    x = torch.randn(2, 8)
    paths = {
        "F1": os.path.join(FX, "model.pt"),
        "F2": os.path.join(FX, "model.torchscript"),
        "F3": os.path.join(FX, "model.ptl"),
        "F4": os.path.join(FX, "model.pt2"),
        "F5": os.path.join(FX, "weights.pth"),
    }

    def write(key, fn):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                fn(paths[key])
            rep["fixtures"][key] = {"path": paths[key],
                                    "bytes": os.path.getsize(paths[key])}
        except Exception as exc:
            rep["errors"]["write_" + key] = err(exc)
            rep["errors"]["write_" + key + "_tb"] = traceback.format_exc()[-800:]

    write("F1", lambda p: torch.jit.save(torch.jit.script(net), p))
    write("F2", lambda p: torch.jit.save(torch.jit.trace(net, x), p))
    write("F3", lambda p: torch.jit.script(net)._save_for_lite_interpreter(p))
    write("F4", lambda p: torch.export.save(torch.export.export(net, (x,)), p))
    write("F5", lambda p: torch.save(net.state_dict(), p))

    def load(key, label, fn):
        if key not in rep["fixtures"]:
            rep["loaders"][label] = {"ok": None, "why": "fixture missing"}
            return
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                obj = fn(paths[key])
            rep["loaders"][label] = {
                "ok": True, "type": type(obj).__name__,
                "warnings": [str(w.message)[:300] for w in caught][:3]}
        except Exception as exc:
            rep["loaders"][label] = {"ok": False, "error": err(exc)}

    load("F1", "jit_load_F1", torch.jit.load)
    load("F2", "jit_load_F2", torch.jit.load)
    try:
        from torch.jit.mobile import _load_for_lite_interpreter
        load("F3", "lite_load_F3", _load_for_lite_interpreter)
    except Exception as exc:
        rep["loaders"]["lite_load_F3"] = {"ok": None, "why": err(exc)}
    load("F4", "export_load_F4", torch.export.load)
    load("F5", "torch_load_F5_weights_only_true",
         lambda p: torch.load(p, weights_only=True))

    # Member listing of every fixture (names only), for the record.
    import zipfile
    listing = {}
    for key, p in paths.items():
        if key in rep["fixtures"]:
            try:
                with zipfile.ZipFile(p) as zf:
                    listing[key] = zf.namelist()[:200]
            except Exception as exc:
                listing[key] = ["<not a zip: %s>" % type(exc).__name__]
    rep["members"] = listing

    with open("fixtures_report.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"torch": rep.get("torch"),
                      "fixtures": sorted(rep["fixtures"]),
                      "loaders": {k: v.get("ok")
                                  for k, v in rep["loaders"].items()}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
