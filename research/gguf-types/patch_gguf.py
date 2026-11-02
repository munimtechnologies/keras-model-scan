#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Patch gguf_scan.py 0.1.0 -> 0.2.0: accept ggml type ids up to 43.

llama.cpp's ggml (tag b12034, 2 November 2026) defines tensor types up to
GGML_TYPE_F8_E4M3 = 43 (GGML_TYPE_COUNT = 44): NVFP4 = 40, Q1_0 = 41,
Q2_0 = 42, F8_E4M3 = 43. gguf_scan 0.1.0 reports any type id above 39 as
GG010 (MEDIUM), which fails an honest NVFP4 GGUF in CI.

Usage: patch_gguf.py KMS_DIR OUT_DIR NEW_KMS_DIR
- reads KMS_DIR/gguf_scan.py, replaces the `_MAX_GGML_TYPE = 39` line and
  `__version__ = "0.1.0"` (each must occur exactly once), checks that a
  second pass changes nothing and that only those two lines differ;
- writes OUT_DIR/gguf_scan.py and OUT_DIR/gguf_scan.diff;
- copies KMS_DIR to NEW_KMS_DIR with the patched module and this folder's
  test_gguf_scan_types.py, so the unit tests can run against it.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import difflib
import os
import re
import shutil
import sys

CAP_RE = re.compile(r"^_MAX_GGML_TYPE = 39\b[^\n]*$", re.M)
NEW_CAP = ("_MAX_GGML_TYPE = 43  # GGML_TYPE_F8_E4M3; GGML_TYPE_COUNT is 44 "
           "in llama.cpp b12034")
OLD_VER = '__version__ = "0.1.0"'
NEW_VER = '__version__ = "0.2.0"'
HERE = os.path.dirname(os.path.abspath(__file__))


def patch(text):
    notes = []
    caps = CAP_RE.findall(text)
    if caps:
        if len(caps) != 1:
            raise ValueError("expected one _MAX_GGML_TYPE = 39 line, got %d"
                             % len(caps))
        text = CAP_RE.sub(NEW_CAP, text)
        notes.append("cap")
    elif NEW_CAP not in text:
        raise ValueError("no _MAX_GGML_TYPE = 39 line and no patched line")
    nver = text.count(OLD_VER)
    if nver:
        if nver != 1:
            raise ValueError("expected one version line, got %d" % nver)
        text = text.replace(OLD_VER, NEW_VER)
        notes.append("version")
    elif NEW_VER not in text:
        raise ValueError("no 0.1.0 or 0.2.0 version line")
    return text, notes


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    kms, out, new_kms = args
    src = os.path.join(kms, "gguf_scan.py")
    with open(src, encoding="utf-8", newline="") as fh:
        old = fh.read()
    new, notes = patch(old)
    again, notes2 = patch(new)
    old_lines = old.split("\n")
    new_lines = new.split("\n")
    changed = [i for i, (a, b) in enumerate(zip(old_lines, new_lines))
               if a != b]
    diff = "".join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True),
        "a/gguf_scan.py", "b/gguf_scan.py"))
    print("changes:", notes)
    print("second pass changes:", notes2)
    print("line counts: %d -> %d; changed line numbers: %s"
          % (len(old_lines), len(new_lines), [i + 1 for i in changed]))
    print("other lines mentioning 39 (review):")
    for i, ln in enumerate(new_lines):
        if "39" in ln and i not in changed:
            print("  %d: %s" % (i + 1, ln.strip()[:160]))
    print(diff)
    if notes2 or again != new:
        print("FAIL: second pass not a no-op", file=sys.stderr)
        return 5
    if len(old_lines) != len(new_lines) or len(changed) != len(notes):
        print("FAIL: unexpected line changes", file=sys.stderr)
        return 6
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "gguf_scan.py"), "w", encoding="utf-8",
              newline="") as fh:
        fh.write(new)
    with open(os.path.join(out, "gguf_scan.diff"), "w", encoding="utf-8",
              newline="") as fh:
        fh.write(diff)
    shutil.rmtree(new_kms, ignore_errors=True)
    shutil.copytree(kms, new_kms)
    with open(os.path.join(new_kms, "gguf_scan.py"), "w", encoding="utf-8",
              newline="") as fh:
        fh.write(new)
    shutil.copy(os.path.join(HERE, "test_gguf_scan_types.py"),
                os.path.join(new_kms, "test_gguf_scan_types.py"))
    print("wrote %s and %s" % (os.path.join(out, "gguf_scan.py"), new_kms))
    return 0


if __name__ == "__main__":
    sys.exit(main())
