#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step: install onnx (the writer and loader under test) and numpy, and
record the installed versions in setup_report.json. Always exits 0; a failed
install shows up as row W1 failing.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import subprocess
import sys

PKGS = ["onnx==1.23.2", "numpy"]


def main():
    proc = subprocess.run([sys.executable, "-m", "pip", "install",
                           "--no-cache-dir", "--quiet"] + PKGS,
                          capture_output=True, text=True)
    report = {"pip_returncode": proc.returncode,
              "pip_stderr_tail": proc.stderr[-2000:]}
    probe = subprocess.run(
        [sys.executable, "-c",
         "import json, onnx, numpy; print(json.dumps({'onnx': "
         "onnx.__version__, 'numpy': numpy.__version__}))"],
        capture_output=True, text=True)
    try:
        report["versions"] = json.loads(probe.stdout.strip().splitlines()[-1])
    except Exception:
        report["versions"] = None
        report["probe_stderr_tail"] = probe.stderr[-2000:]
    with open("setup_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
