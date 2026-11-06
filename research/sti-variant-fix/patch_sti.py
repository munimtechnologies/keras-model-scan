#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""model-file-scan 0.12.0 / safetensors_index_scan 0.2.0: variant-named
shard indexes.

transformers and diffusers write save_pretrained(..., variant="fp16") as
model.safetensors.index.fp16.json. That name does not end in ".index.json",
so model-file-scan 0.11.1 routed it to the Keras config scanner and both
directory walks skipped it (REALFILE_CHECK_STI_2026-11.md, rows G1 and G2).

This script patches TREE in place:
  * model_file_scan.py and safetensors_index_scan.py get one helper,
    _is_shard_index(name), matching \\.index(\\.[A-Za-z0-9_-]+)?\\.json$
    (case-insensitive), and every `<expr>.endswith(".index.json")` becomes
    `_is_shard_index(<expr>)`. No quoted ".index.json" may remain.
  * versions: model_file_scan 0.11.1 -> 0.12.0, safetensors_index_scan
    0.1.0 -> 0.2.0, pyproject.toml 0.11.1 -> 0.12.0, and the matching floors
    in test_attribution.py.
  * MODEL_FILE_SCAN.md: the routing rows and the "Formats routed" heading
    (optional; reported, never required).
  * copies test_safetensors_index_variant.py into TREE.

Every edit applies exactly once or is already in place; a second pass must
change nothing, and no line may be lost except the ones replaced. Changed
files and the new test are written to OUT, originals to ORIG_DIR, and the
report to OUT/patch_report.json. Always exits 0; the check grades row P1.

Usage: patch_sti.py TREE OUT ORIG_DIR

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEST = "test_safetensors_index_variant.py"

ENDS = re.compile(r"(?<![\w.)\]])((?:\w+(?:\(\))?\.)*\w+(?:\(\))?)"
                  r"\.endswith\(\s*([\"'])\.index\.json\2\s*\)")
QUOTED = re.compile(r"[\"']\.index\.json[\"']")
MARK = "_SHARD_INDEX_NAME = "
HELPER = '''# Shard-index file names, including weights variants. transformers and
# diffusers write save_pretrained(..., variant="fp16") as
# model.safetensors.index.fp16.json, a name that does not end in .index.json
# (REALFILE_CHECK_STI_2026-11.md).
import re as _shard_re  # noqa: E402

_SHARD_INDEX_NAME = _shard_re.compile(
    r"\\.index(\\.[A-Za-z0-9_\\-]+)?\\.json$", _shard_re.IGNORECASE)


def _is_shard_index(name):
    """True for ``*.index.json`` and ``*.index.<variant>.json`` names."""
    return bool(_SHARD_INDEX_NAME.search(str(name)))


'''

MODULES = {
    "model_file_scan.py": {
        "anchor": re.compile(r"(?m)^def route\("),
        "ver": ('__version__ = "0.11.1"', '__version__ = "0.12.0"'),
        "min_ends": 2,
    },
    "safetensors_index_scan.py": {
        "anchor": re.compile(r"(?m)^def _looks_like_index\("),
        "ver": ('__version__ = "0.1.0"', '__version__ = "0.2.0"'),
        "min_ends": 1,
    },
}
SIMPLE = {
    "pyproject.toml": [('version = "0.11.1"', 'version = "0.12.0"')],
    "test_attribution.py": [
        ("(model_file_scan, (0, 11, 1))", "(model_file_scan, (0, 12, 0))"),
        ("(safetensors_index_scan, (0, 1, 0))",
         "(safetensors_index_scan, (0, 2, 0))"),
    ],
}
DOC = "MODEL_FILE_SCAN.md"
DOC_EDITS = [
    ("## Formats routed in 0.11.1 (release v0.51.0)",
     "## Formats routed in 0.12.0 (release v0.52.0)"),
    ("| `*.index.json` (sharded-model index) |",
     "| `*.index.json` and variant names such as `*.index.fp16.json` "
     "(sharded-model index) |"),
    ("| `*.index.json` (e.g. `model.safetensors.index.json`, "
     "`pytorch_model.bin.index.json`) |",
     "| `*.index.json` (e.g. `model.safetensors.index.json`, "
     "`pytorch_model.bin.index.json`; also variant names such as "
     "`model.safetensors.index.fp16.json`) |"),
]


def apply_module(text, spec):
    notes = []
    n_ends = 0
    if MARK not in text:
        hits = list(spec["anchor"].finditer(text))
        if len(hits) != 1:
            raise ValueError("anchor found %d times" % len(hits))
        text = text[:hits[0].start()] + HELPER + text[hits[0].start():]
        notes.append("helper")
    text, n_ends = ENDS.subn(lambda m: "_is_shard_index(%s)" % m.group(1),
                             text)
    if n_ends:
        notes.append("%d endswith" % n_ends)
    old, new = spec["ver"]
    if new not in text:
        if text.count(old) != 1:
            raise ValueError("version line found %d times" % text.count(old))
        text = text.replace(old, new)
        notes.append("version")
    return text, notes, n_ends


def apply_simple(text, pairs):
    notes = []
    for old, new in pairs:
        if new in text:
            continue
        if text.count(old) != 1:
            raise ValueError("%r found %d times" % (old, text.count(old)))
        text = text.replace(old, new)
        notes.append(new)
    return text, notes


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    tree, out, orig = args
    os.makedirs(out, exist_ok=True)
    os.makedirs(orig, exist_ok=True)
    report = {"files": {}, "ok": False}
    staged = {}
    try:
        for name, spec in MODULES.items():
            old = read(os.path.join(tree, name))
            write(os.path.join(orig, name), old)
            if "\r\n" in old:
                raise ValueError("%s: CRLF" % name)
            new, notes, n_ends = apply_module(old, spec)
            again, notes2, n2 = apply_module(new, spec)
            o, n = old.split("\n"), new.split("\n")
            lost = [ln for ln in o if ln not in n and not ENDS.search(ln)
                    and ln != spec["ver"][0]]
            left = [ln.strip()[:120] for ln in n if QUOTED.search(ln)]
            ok = (again == new and not notes2 and not n2 and not lost
                  and not left and n_ends >= spec["min_ends"])
            report["files"][name] = {
                "changes": notes, "endswith_replaced": n_ends,
                "second_pass": notes2, "lost": lost[:20],
                "quoted_left": left[:20], "lines": [len(o), len(n)],
                "ok": ok}
            if not ok:
                raise ValueError("%s: check failed" % name)
            staged[name] = new
        for name, pairs in SIMPLE.items():
            old = read(os.path.join(tree, name))
            write(os.path.join(orig, name), old)
            new, notes = apply_simple(old, pairs)
            again, notes2 = apply_simple(new, pairs)
            ok = (len(notes) == len(pairs) and not notes2 and again == new
                  and len(old.split("\n")) == len(new.split("\n")))
            report["files"][name] = {"changes": notes, "second_pass": notes2,
                                     "ok": ok}
            if not ok:
                raise ValueError("%s: check failed" % name)
            staged[name] = new
        # Optional doc edits: applied when the anchor is there exactly once.
        try:
            old = read(os.path.join(tree, DOC))
            write(os.path.join(orig, DOC), old)
            new, done, skipped = old, [], []
            for a, b in DOC_EDITS:
                if b in new:
                    continue
                if new.count(a) == 1:
                    new = new.replace(a, b)
                    done.append(b[:60])
                else:
                    skipped.append([a[:60], new.count(a)])
            report["files"][DOC] = {"changes": done, "skipped": skipped,
                                    "optional": True}
            if new != old:
                staged[DOC] = new
        except OSError as exc:
            report["files"][DOC] = {"error": str(exc), "optional": True}
        # Everything checked: write the tree and OUT.
        for name, text in staged.items():
            write(os.path.join(tree, name), text)
            write(os.path.join(out, name), text)
        for dest in (os.path.join(tree, TEST), os.path.join(out, TEST)):
            shutil.copyfile(os.path.join(HERE, TEST), dest)
        report["ok"] = True
        report["written"] = sorted(staged) + [TEST]
    except Exception as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
