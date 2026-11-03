#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Setup step for job gguf-xtool (research/PREREG_GGUF_XTOOL.md).

Builds two virtual environments, recording every step and never failing the
job (a failed install makes the cases that need it NOT RUN):

  ma_rel   modelaudit 0.2.54 from PyPI (the newest release, 13 October 2026).
  ma_main  modelaudit 0.2.54's dependencies, then promptfoo/modelaudit main at
           commit 415819f installed over it with --no-deps (main needs
           modelaudit-picklescan 0.1.13, which is not on PyPI yet).

It also downloads main's modelaudit/scanners/gguf_scanner.py at the same
commit as ./main_gguf_scanner.py, the fallback named in the
pre-registration (copied over ma_rel's scanner after ma_rel's own scans).

Writes ./setup_report.json. Made with AI agents working in the name of MV2 of
Munim, Inc. Apache-2.0.
"""

import json
import os
import subprocess
import sys
import urllib.request

RELEASE = "0.2.54"
SHA = "415819fa0b58d097dd201c0fa3f41eba33431c78"
MAIN_TGZ = "https://codeload.github.com/promptfoo/modelaudit/tar.gz/" + SHA
SCANNER_URL = ("https://raw.githubusercontent.com/promptfoo/modelaudit/%s/"
               "modelaudit/scanners/gguf_scanner.py" % SHA)


def sh(cmd, report, key, timeout=1500):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        report[key] = {"exit": p.returncode,
                       "tail": (p.stdout + p.stderr).strip()[-1500:]}
        print("$", " ".join(cmd), "->", p.returncode)
        print((p.stdout + p.stderr).strip()[-1500:])
        return p.returncode == 0
    except Exception as exc:  # recorded, never raised
        report[key] = {"exit": None, "tail": "%s: %s" % (
            type(exc).__name__, exc)}
        print("$", " ".join(cmd), "-> exception", exc)
        return False


def main():
    report = {"release": RELEASE, "main_sha": SHA}
    for venv in ("ma_rel", "ma_main"):
        ok = sh([sys.executable, "-m", "venv", venv], report, venv + "_venv")
        if ok:
            pip = os.path.join(venv, "bin", "pip")
            ok = sh([pip, "install", "--no-cache-dir",
                     "modelaudit==" + RELEASE], report, venv + "_release")
        report[venv + "_release_ok"] = ok
    if report.get("ma_main_release_ok"):
        pip = os.path.join("ma_main", "bin", "pip")
        report["ma_main_main_ok"] = sh(
            [pip, "install", "--no-cache-dir", "--no-deps",
             "--force-reinstall", "modelaudit @ " + MAIN_TGZ],
            report, "ma_main_main")
    else:
        report["ma_main_main_ok"] = False
    try:
        data = urllib.request.urlopen(SCANNER_URL, timeout=120).read()
        with open("main_gguf_scanner.py", "wb") as fh:
            fh.write(data)
        report["main_scanner_bytes"] = len(data)
    except Exception as exc:
        report["main_scanner_error"] = "%s: %s" % (type(exc).__name__, exc)
    with open("setup_report.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps({k: v for k, v in report.items()
                      if not isinstance(v, dict)}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
