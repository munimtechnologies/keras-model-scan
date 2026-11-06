#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""nemo_container_scan 0.2.0: big checkpoints are checked, not skipped.

Up to 0.1.0 a tar member larger than MAX_MEMBER_BYTES (256 MiB) was skipped
with no finding, and scan_file read the whole .nemo into memory. 0.2.0 opens a
nested torch-save zip in place from the tar member (seekable), reads only the
zip directory and the *.pkl entries, reports NEMO030 (medium) for a pickle
that is still too big to check and NEMO031 (medium) for more members than
MAX_MEMBERS, and streams the tar from disk in scan_file.

Edits (each exactly once, or already in place; a second pass changes nothing):
  nemo_container_scan.py       version 0.2.0; new helpers before scan_bytes;
                               scan_bytes and scan_file replaced whole
  test_nemo_container_scan.py  the exact pin 'assertEqual(scan.__version__,
                               "0.1.0")' becomes a floor (>= 0.2.0)
  NEMO_CONTAINER_SCAN.md       a section before "## Honest limits" (or end)

Only if every file passes are the patched files written to TREE and
OUT/patched (originals go to ORIG_DIR). The new test module is copied too.
Always exits 0: the result is graded as row P1 by nemo_check.py.

Usage: patch_nemo.py TREE OUT ORIG_DIR

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import new_code  # noqa: E402

TEST = "test_nemo_container_scan_big.py"
VER_OLD = '__version__ = "0.1.0"'
VER_NEW = '__version__ = "0.2.0"'


def _block(text, name):
    """The single top-level ``def name(`` block: the def line plus every
    following indented or blank line. Returns (start, body_end, end)."""
    pat = r"(?m)^def %s\(.*\n(?:(?:[ \t]+[^\n]*|[ \t]*)\n)*" % re.escape(name)
    hits = list(re.finditer(pat, text))
    if len(hits) != 1:
        raise ValueError("def %s found %d times" % (name, len(hits)))
    m = hits[0]
    lines = m.group(0).split("\n")
    while lines and lines[-1].strip() == "":
        lines.pop()
    body_end = m.start() + len("\n".join(lines))
    return m.start(), body_end, m.end()


def edit_scanner(text, removed):
    notes = []
    if VER_NEW not in text:
        if text.count(VER_OLD) != 1:
            raise ValueError("version line found %d times" % text.count(VER_OLD))
        text = text.replace(VER_OLD, VER_NEW)
        notes.append("version 0.2.0")
    if "def _scan_tar(" not in text:
        s, b, _e = _block(text, "scan_bytes")
        removed.update(text[s:b].split("\n"))
        text = (text[:s] + new_code.HELPERS + new_code.SCAN_BYTES.rstrip("\n")
                + text[b:])
        notes.append("helpers + scan_bytes")
    if "0.2.0 streams the tar" not in text:
        s, b, _e = _block(text, "scan_file")
        removed.update(text[s:b].split("\n"))
        text = text[:s] + new_code.SCAN_FILE.rstrip("\n") + text[b:]
        notes.append("scan_file streams")
    return text, notes


PIN_RE = r'(?m)^([ \t]*)self\.assertEqual\(scan\.__version__, "0\.1\.0"\)[ \t]*$'
PIN_NEW = ('{i}self.assertGreaterEqual(\n'
           '{i}    tuple(int(p) for p in scan.__version__.split(".")), (0, 2, 0))')


def edit_test(text, removed):
    if "(0, 2, 0))" in text and "scan.__version__.split" in text:
        return text, []
    hits = list(re.finditer(PIN_RE, text))
    if len(hits) != 1:
        raise ValueError("version pin found %d times" % len(hits))
    m = hits[0]
    removed.add(m.group(0))
    return (text[:m.start()] + PIN_NEW.format(i=m.group(1)) + text[m.end():],
            ["version pin -> floor"])


DOC_ANCHOR = "## Honest limits"
DOC_MARK = "<!-- nemo-big -->"
DOC = """<!-- nemo-big -->
## Big checkpoints (v0.2.0, November 2026)

NeMo's `SaveRestoreConnector` writes `model_weights.ckpt` with `torch.save`
and tars the folder uncompressed (`tarfile.open(filename, "w:")`,
`arcname="."`). Most published `.nemo` models have a checkpoint larger than
256 MiB. Up to 0.1.0 this scanner skipped any member larger than
`MAX_MEMBER_BYTES` (256 MiB) **with no finding**, so for those models the
pickle that `restore_from` loads was never checked and the result was clean,
while a smaller honest model got NEMO010. `scan_file` also read the whole
file into memory.

0.2.0 opens a nested torch-save zip in place from the tar member (as a
seekable file) and reads only the zip directory and its `*.pkl` entries, so a
checkpoint of any size is checked. `scan_file` streams the tar from disk. Two
new medium findings replace the silent skips:

| Rule | Severity | When |
|---|---|---|
| NEMO030 | medium | a pickle that is still too big to check: a bare pickle member (protocol 2-5) or a `*.pkl` zip entry larger than `MAX_MEMBER_BYTES` |
| NEMO031 | medium | the container has more members than `MAX_MEMBERS`; the rest were not checked |

For comparison, promptfoo's ModelAudit `nemo_scanner` marks a checkpoint
member above its 50 MB limit (`NEMO_MAX_CHECKPOINT_SCAN_BYTES`) inconclusive
instead of scanning it (main, read 2026-11-06): it fails closed, where 0.1.0
of this scanner failed open.

Pre-registered check on files written by torch and on two published NVIDIA
models: [research/PREREG_NEMO_BIG.md](research/PREREG_NEMO_BIG.md).

"""


def edit_doc(text, removed):
    if DOC_MARK in text:
        return text, []
    n = text.count("\n" + DOC_ANCHOR)
    if n > 1:
        raise ValueError("doc anchor found %d times" % n)
    if n == 0:
        sep = "" if text.endswith("\n\n") else (
            "\n" if text.endswith("\n") else "\n\n")
        return text + sep + DOC.rstrip("\n") + "\n", ["doc section (appended)"]
    i = text.index("\n" + DOC_ANCHOR) + 1
    return text[:i] + DOC + text[i:], ["doc section"]


EDITS = (("nemo_container_scan.py", edit_scanner),
         ("test_nemo_container_scan.py", edit_test),
         ("NEMO_CONTAINER_SCAN.md", edit_doc))


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 0
    tree, out, orig = args
    patched_dir = os.path.join(out, "patched")
    for d in (out, orig, patched_dir):
        os.makedirs(d, exist_ok=True)
    report = {"files": {}, "ok": False}
    new_texts = {}
    try:
        for name, fn in EDITS:
            entry = {}
            try:
                with open(os.path.join(tree, name), encoding="utf-8",
                          newline="") as fh:
                    old = fh.read()
                with open(os.path.join(orig, name), "w", encoding="utf-8",
                          newline="") as fh:
                    fh.write(old)
                if "\r\n" in old:
                    raise ValueError("CRLF")
                removed = set()
                new, notes = fn(old, removed)
                again, notes2 = fn(new, set())
                new_set = set(new.split("\n"))
                lost = [ln for ln in old.split("\n") if ln not in new_set
                        and ln not in removed and ln != VER_OLD]
                compiled = True
                if name.endswith(".py"):
                    try:
                        compile(new, name, "exec")
                    except SyntaxError as exc:
                        compiled = False
                        entry["syntax_error"] = str(exc)
                entry.update({"changes": notes, "second_pass": notes2,
                              "lost": lost[:20], "removed_lines": len(removed),
                              "lines": [old.count("\n"), new.count("\n")],
                              "compiles": compiled,
                              "ok": bool(notes) and not notes2
                              and again == new and not lost and compiled})
                new_texts[name] = new
            except (ValueError, OSError) as exc:
                entry = {"error": "%s: %s" % (type(exc).__name__, exc),
                         "ok": False}
            report["files"][name] = entry
        report["ok"] = all(e.get("ok") for e in report["files"].values()) \
            and len(report["files"]) == len(EDITS)
        if report["ok"]:
            for name, text in new_texts.items():
                for dest in (os.path.join(tree, name),
                             os.path.join(patched_dir, name)):
                    with open(dest, "w", encoding="utf-8", newline="") as fh:
                        fh.write(text)
            for dest in (os.path.join(tree, TEST),
                         os.path.join(patched_dir, TEST)):
                shutil.copyfile(os.path.join(HERE, TEST), dest)
            report["written"] = sorted(list(new_texts) + [TEST])
    except Exception as exc:  # never stop later steps
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
        report["ok"] = False
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
