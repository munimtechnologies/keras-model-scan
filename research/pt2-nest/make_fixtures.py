#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step: write HONEST model files with torch's own writers into ./fx and
record what torch's own loaders do with them (the ground truth).

Fixtures (one small ordinary model, nothing crafted):
  F1 model.pt           torch.jit.script(...) saved with torch.jit.save
  F2 model.torchscript  torch.jit.trace(...) saved with torch.jit.save
  F3 model.ptl          _save_for_lite_interpreter (PyTorch mobile)
  F4 model.pt2          torch.export.save
  F5 weights.pth        torch.save(state_dict)  (control)
  F6 model_b.pt2        torch.export.save of the same network after setting
                        the first element of every float parameter and
                        buffer to 1.0000153 (stored little-endian as
                        80 00 80 3f) and num_batches_tracked to 128 (stored
                        as 80 00 00 00 ...), ordinary values a trained model
                        can hold, so its raw weight bytes start with 0x80.

For every member of F4 and F6 it records the size and first four bytes, and
for each member whose bytes start with the zip magic PK\\x03\\x04 whether
zipfile opens it, its member names, and whether
torch.load(weights_only=True) reads it (rows M2 and D1 of
research/PREREG_PT2_NEST.md).

Writes fixtures_report.json. Never fails the job: a missing writer or loader
is recorded and its rows become "not run".

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import io
import json
import os
import struct
import sys
import traceback
import warnings
import zipfile

FX = os.path.abspath("fx")
ZIP_MAGIC = b"PK\x03\x04"


def err(exc):
    return "%s: %s" % (type(exc).__name__, str(exc).splitlines()[0][:300]
                       if str(exc) else "")


def describe_members(path, torch):
    out = {}
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist()[:400]:
            data = zf.read(name)
            row = {"bytes": len(data), "head": data[:4].hex()}
            if data[:4] == ZIP_MAGIC:
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as inner:
                        row["inner_names"] = inner.namelist()[:100]
                    row["opens_as_zip"] = True
                except Exception as exc:
                    row["opens_as_zip"] = False
                    row["zip_error"] = err(exc)
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        obj = torch.load(io.BytesIO(data), weights_only=True)
                    row["torch_load_weights_only"] = {
                        "ok": True, "type": type(obj).__name__}
                except Exception as exc:
                    row["torch_load_weights_only"] = {"ok": False,
                                                      "error": err(exc)}
            out[name] = row
    return out


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
        "F6": os.path.join(FX, "model_b.pt2"),
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

    # F6: same network, first element of every tensor starts with byte 0x80.
    value = struct.unpack("<f", b"\x80\x00\x80\x3f")[0]
    net_b = Net().eval()
    with torch.no_grad():
        for t in list(net_b.parameters()) + list(net_b.buffers()):
            flat = t.view(-1)
            if t.dtype == torch.int64:
                flat[0] = 128
            else:
                flat[0] = value
    rep["f6_value"] = value
    write("F6", lambda p: torch.export.save(torch.export.export(net_b, (x,)),
                                            p))

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
    load("F4", "export_load_F4", torch.export.load)
    load("F6", "export_load_F6", torch.export.load)
    load("F5", "torch_load_F5_weights_only_true",
         lambda p: torch.load(p, weights_only=True))

    members = {}
    for key in ("F4", "F6"):
        if key in rep["fixtures"]:
            try:
                members[key] = describe_members(paths[key], torch)
            except Exception as exc:
                members[key] = {"<error>": err(exc)}
    rep["members"] = members

    with open("fixtures_report.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"torch": rep.get("torch"),
                      "fixtures": sorted(rep["fixtures"]),
                      "loaders": {k: v.get("ok")
                                  for k, v in rep["loaders"].items()}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
