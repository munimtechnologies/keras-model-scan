#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: install openvino and numpy (newest releases), record versions
in setup_report.json, and never fail setup (rows that need OpenVINO are then
"not run"). Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.
"""
import json
import subprocess
import sys

PROBE = ("import json, importlib.metadata as m\n"
         "out = {}\n"
         "for p in ('openvino', 'numpy'):\n"
         "    try:\n        out[p] = m.version(p)\n"
         "    except Exception as e:\n        out[p] = 'missing: %s' % e\n"
         "print(json.dumps(out))\n")


def main():
    rep = {}
    try:
        p = subprocess.run([sys.executable, "-m", "pip", "install",
                            "--no-cache-dir", "openvino", "numpy"],
                           capture_output=True, text=True, timeout=1500)
        rep["pip_ok"] = p.returncode == 0
        rep["pip_tail"] = (p.stdout + p.stderr).strip()[-500:]
    except Exception as exc:
        rep["pip_ok"] = False
        rep["pip_tail"] = str(exc)
    try:
        p = subprocess.run([sys.executable, "-c", PROBE], capture_output=True,
                           text=True, timeout=300)
        rep["versions"] = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as exc:
        rep["versions"] = "probe failed: %s" % exc
    with open("setup_report.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps(rep.get("versions")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
