#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Child process: load ONE scanner module from a file path and scan a list of
files with its scan_file(path). Each scanner version runs in its own process,
so two versions of pickle_model_scan never share sys.modules.

Usage: python scan_one.py <module_path> <module_name> <in.json> <out.json>
in.json is a JSON list of file paths. out.json maps path -> list of
{rule, severity, location} (severity upper-cased), or {"error": "..."}.
The scanners only disassemble bytes; nothing is unpickled.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import dataclasses
import importlib.util
import json
import os
import sys
import traceback


def load(path, name):
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # before exec_module (dataclasses need it)
    spec.loader.exec_module(mod)
    return mod


def norm(res):
    if res is None:
        return []
    if hasattr(res, "findings"):
        res = res.findings
    if isinstance(res, dict) and "findings" in res:
        res = res["findings"]
    out = []
    for f in res or []:
        if hasattr(f, "as_dict"):
            d = f.as_dict()
        elif isinstance(f, dict):
            d = f
        elif dataclasses.is_dataclass(f):
            d = dataclasses.asdict(f)
        else:
            d = {"rule": str(f)}
        out.append({
            "rule": d.get("rule"),
            "severity": str(d.get("severity", "")).upper(),
            "location": str(d.get("location", d.get("evidence", "")))[:300],
        })
    return out


def main(argv):
    module_path, module_name, in_json, out_json = argv[1:5]
    result = {}
    try:
        mod = load(module_path, module_name)
        result["__version__"] = getattr(mod, "__version__", None)
    except Exception:
        result["__load_error__"] = traceback.format_exc()[-1500:]
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1)
        return 0
    with open(in_json, encoding="utf-8") as fh:
        paths = json.load(fh)
    for p in paths:
        try:
            result[p] = norm(mod.scan_file(p))
        except Exception as exc:
            result[p] = {"error": "%s: %s" % (type(exc).__name__,
                                              str(exc)[:300])}
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
