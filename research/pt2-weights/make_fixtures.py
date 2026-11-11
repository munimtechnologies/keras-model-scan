#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step: write HONEST model files with torch's own writers into ./fx and
record what torch's own loaders do with them (the ground truth).

Fixtures (small ordinary models, nothing crafted):
  F1 model.pt      torch.jit.script(...) saved with torch.jit.save (control)
  F3 model.ptl     _save_for_lite_interpreter (PyTorch mobile, control)
  F4 model.pt2     torch.export.save, default weights
  F5 weights.pth   torch.save(state_dict)  (control)
  F6 model_b.pt2   torch.export.save of the same network after setting the
                   first element of every float parameter and buffer to
                   1.0000153 (stored little-endian as 80 00 80 3f) and
                   num_batches_tracked to 128, so its raw weight bytes start
                   with 0x80 (the fixture of pt2-nest-v1's row D1)
  F7 model_c.pt2   torch.export.save of a network with a plain tensor
                   attribute (torch.export lifts it as a tensor constant),
                   whose first element is also 1.0000153

For every member of F4, F6 and F7 it records the size and first four bytes,
and it reads each archive's weights and constants configs with the json
module (path_name and use_pickle of every entry; row W1). Writes
fixtures_report.json. Never fails the job: a missing writer or loader is
recorded and its rows become "not run".

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import struct
import sys
import traceback
import warnings
import zipfile

FX = os.path.abspath("fx")


def err(exc):
    return "%s: %s" % (type(exc).__name__, str(exc).splitlines()[0][:300]
                       if str(exc) else "")


def describe(path):
    members, configs = {}, {}
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist()[:400]:
            data = zf.read(name)
            members[name] = {"bytes": len(data), "head": data[:4].hex()}
            if (name.endswith("_weights_config.json")
                    or name.endswith("_constants_config.json")):
                row = {"text_head": data[:800].decode("utf-8", "replace")}
                try:
                    doc = json.loads(data.decode("utf-8"))
                    entries = doc.get("config") if isinstance(doc, dict) \
                        else None
                    row["top_keys"] = (sorted(doc)[:10]
                                       if isinstance(doc, dict) else None)
                    row["entries"] = [
                        {"fqn": k, "path_name": (v or {}).get("path_name"),
                         "use_pickle": (v or {}).get("use_pickle")}
                        for k, v in (entries or {}).items()][:100]
                except Exception as exc:
                    row["error"] = err(exc)
                configs[name] = row
    return members, configs


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
    value = struct.unpack("<f", b"\x80\x00\x80\x3f")[0]
    rep["value"] = value

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc1 = nn.Linear(8, 16)
            self.bn = nn.BatchNorm1d(16)
            self.fc2 = nn.Linear(16, 4)

        def forward(self, x):
            return self.fc2(torch.relu(self.bn(self.fc1(x))))

    class NetC(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc = nn.Linear(8, 4)
            self.scale = torch.full((4,), value)

        def forward(self, x):
            return self.fc(x) * self.scale

    net = Net().eval()
    x = torch.randn(2, 8)
    paths = {
        "F1": os.path.join(FX, "model.pt"),
        "F3": os.path.join(FX, "model.ptl"),
        "F4": os.path.join(FX, "model.pt2"),
        "F5": os.path.join(FX, "weights.pth"),
        "F6": os.path.join(FX, "model_b.pt2"),
        "F7": os.path.join(FX, "model_c.pt2"),
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
    write("F3", lambda p: torch.jit.script(net)._save_for_lite_interpreter(p))
    write("F4", lambda p: torch.export.save(torch.export.export(net, (x,)), p))
    write("F5", lambda p: torch.save(net.state_dict(), p))

    net_b = Net().eval()
    with torch.no_grad():
        for t in list(net_b.parameters()) + list(net_b.buffers()):
            flat = t.view(-1)
            if t.dtype == torch.int64:
                flat[0] = 128
            else:
                flat[0] = value
    write("F6", lambda p: torch.export.save(torch.export.export(net_b, (x,)),
                                            p))

    net_c = NetC().eval()
    with torch.no_grad():
        net_c.fc.weight.view(-1)[0] = value
    write("F7", lambda p: torch.export.save(torch.export.export(net_c, (x,)),
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
    load("F7", "export_load_F7", torch.export.load)

    # The loaded F6 must give back the 0x80-leading values (ground truth that
    # those bytes are tensor data, read raw).
    try:
        ep = torch.export.load(paths["F6"])
        firsts = {k: float(v.reshape(-1)[0]) for k, v in ep.state_dict.items()}
        rep["f6_first_values"] = firsts
    except Exception as exc:
        rep["errors"]["f6_values"] = err(exc)

    members, configs = {}, {}
    for key in ("F4", "F6", "F7"):
        if key in rep["fixtures"]:
            try:
                members[key], configs[key] = describe(paths[key])
            except Exception as exc:
                members[key] = {"<error>": err(exc)}
    rep["members"] = members
    rep["configs"] = configs

    with open("fixtures_report.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({"torch": rep.get("torch"),
                      "fixtures": sorted(rep["fixtures"]),
                      "loaders": {k: v.get("ok")
                                  for k, v in rep["loaders"].items()}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
