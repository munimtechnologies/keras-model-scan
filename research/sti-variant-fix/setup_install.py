#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: install the writers (CPU torch, transformers, huggingface_hub,
safetensors). Records every step in setup_report.json and never fails setup:
a writer that did not install makes its rows "not run".

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import subprocess
import sys

STEPS = [
    ("torch", [sys.executable, "-m", "pip", "install", "--no-cache-dir",
               "torch", "--index-url", "https://download.pytorch.org/whl/cpu"]),
    ("libs", [sys.executable, "-m", "pip", "install", "--no-cache-dir",
              "transformers", "huggingface_hub", "safetensors", "numpy"]),
]
PROBE = ("import json, importlib.metadata as m\n"
         "out = {}\n"
         "for p in ('torch', 'transformers', 'huggingface_hub', "
         "'safetensors', 'numpy'):\n"
         "    try:\n"
         "        out[p] = m.version(p)\n"
         "    except Exception as e:\n"
         "        out[p] = 'missing: %s' % e\n"
         "print(json.dumps(out))\n")


def main():
    rep = {}
    for name, cmd in STEPS:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=1500)
            rep[name + "_ok"] = p.returncode == 0
            rep[name + "_tail"] = (p.stdout + p.stderr).strip()[-600:]
        except Exception as exc:
            rep[name + "_ok"] = False
            rep[name + "_tail"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        p = subprocess.run([sys.executable, "-c", PROBE], capture_output=True,
                           text=True, timeout=300)
        rep["versions"] = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as exc:
        rep["versions"] = "probe failed: %s" % exc
    with open("setup_report.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps({k: v for k, v in rep.items()
                      if not k.endswith("_tail")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
