#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""pickle_model_scan 0.9.0: raw tensor payloads of a torch.export (.pt2)
archive are treated as data, as torch.export.load treats them.

Job pt2-nest-v1 recorded that v0.58.0 and the 0.8.0 patch both give an
honest .pt2 one PKL000 LOW "could not be fully parsed" note per raw weight
whose first byte is 0x80 (nine on its fixture model_b.pt2). torch.export.save
writes <prefix>/archive_format ("pt2") and, per model,
<prefix>/data/weights/<model>_weights_config.json and
<prefix>/data/constants/<model>_constants_config.json. Each config maps a
tensor to a PayloadMeta whose path_name is a bare file name (weight_0,
tensor_0) and whose use_pickle says how it was stored. torch.export.load
reads a payload with use_pickle false as raw storage
(torch/export/pt2_archive/_package.py: _build_file_map ->
get_storage_from_record) and never unpickles it; a payload with use_pickle
true goes through torch.load.

Edits to pickle_model_scan.py (each exactly once, or already in place; a
second pass changes nothing; no line is lost except the replaced version and
raw_storage lines):
  docstring paragraph; __version__ 0.8.0 -> 0.9.0;
  helper _pt2_raw_payloads(zf, names) before the _ZIP_MAGIC line;
  in scan_zip, raw_storage also holds the members _pt2_raw_payloads returns.
A member is returned only when ALL of these hold: its archive prefix has an
archive_format member whose text is "pt2"; that prefix has no
data/aotinductor/ member (AOTInductor's loader reads weights another way);
a weights or constants config in the same folder names it, as a bare name,
with use_pickle exactly false; and the member exists. Anything else is read
as before. model_file_scan.py and pyproject.toml are not changed (0.14.0).

Copies the new test file into TREE. All-or-nothing: nothing is written unless
every edit checks out. Changed files go to OUT/patched, originals to OUT/orig,
every top-level .py to OUT/tree_py, the report to OUT/patch_report.json.
Always exits 0; the check grades row P1.

Usage: patch_weights.py TREE OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ("test_pickle_model_scan_pt2_weights.py",)

PMS_VER = ('__version__ = "0.8.0"', '__version__ = "0.9.0"')
DOC_ANCHOR = "A flag means a pattern worth human review, not proof of malice."
DOC_MARK = "Since 0.9.0, in a torch.export"
DOC_NEW = (
    "Since 0.9.0, in a torch.export (.pt2) archive, the raw tensor payloads\n"
    "that the archive's own weights or constants config declares with\n"
    "use_pickle false (members such as <prefix>/data/weights/weight_0) are\n"
    "treated as data, as torch.export.load reads them. Up to 0.8.0 such a\n"
    "payload whose first byte was 0x80 was walked as a pickle and got a\n"
    "PKL000 LOW note on honest files. Payloads declared with use_pickle true,\n"
    "payloads no config names, and archives that hold AOTInductor files are\n"
    "read as before.\n"
    "\n")

HELPER_ANCHOR = '_ZIP_MAGIC = b"PK\\x03\\x04"\n'
HELPER_MARK = "def _pt2_raw_payloads("
HELPER_NEW = r'''_PT2_PAYLOAD_DIRS = (("data/weights/", "_weights_config.json"),
                     ("data/constants/", "_constants_config.json"))
_PT2_CONFIG_MAX = 16 * 1024 * 1024


def _pt2_raw_payloads(zf, names):
    """The raw tensor payloads of a torch.export (.pt2) archive.

    torch.export.save writes <prefix>/archive_format ("pt2") and, per model,
    <prefix>/data/weights/<model>_weights_config.json and
    <prefix>/data/constants/<model>_constants_config.json. Each config maps a
    tensor to a PayloadMeta: path_name (a bare file name such as weight_0)
    and use_pickle. torch.export.load reads a payload with use_pickle false
    as raw storage bytes (torch/export/pt2_archive/_package.py,
    _build_file_map -> get_storage_from_record) and never unpickles it.
    Returns those member names. Payloads with use_pickle true or missing,
    payloads no config names, and every payload of a prefix that also holds
    data/aotinductor/ files are not returned, so they are read as before."""
    nameset = set(names)
    prefixes = set()
    for name in names:
        if name == "archive_format" or name.endswith("/archive_format"):
            prefix = name[:-len("archive_format")]
            try:
                if zf.read(name)[:16].strip() == b"pt2":
                    prefixes.add(prefix)
            except Exception:
                continue
    raw = set()
    for prefix in prefixes:
        if any(n.startswith(prefix + "data/aotinductor/") for n in names):
            continue
        for sub, suffix in _PT2_PAYLOAD_DIRS:
            folder = prefix + sub
            for cfg in names:
                if not (cfg.startswith(folder) and cfg.endswith(suffix)
                        and "/" not in cfg[len(folder):]):
                    continue
                try:
                    if zf.getinfo(cfg).file_size > _PT2_CONFIG_MAX:
                        continue
                    doc = json.loads(zf.read(cfg).decode("utf-8"))
                except Exception:
                    continue
                entries = doc.get("config") if isinstance(doc, dict) else None
                if not isinstance(entries, dict):
                    continue
                for meta in entries.values():
                    if (not isinstance(meta, dict)
                            or meta.get("use_pickle") is not False):
                        continue
                    path = meta.get("path_name")
                    if (isinstance(path, str) and path
                            and "/" not in path and "\\" not in path
                            and path not in (".", "..")
                            and folder + path in nameset):
                        raw.add(folder + path)
    return raw


'''

RAW_OLD = "    raw_storage = _torch_storage_members(zf.namelist())\n"
RAW_MARK = "_pt2_raw_payloads(zf, zf.namelist())"
RAW_NEW = ("    raw_storage = (_torch_storage_members(zf.namelist())\n"
           "                   | _pt2_raw_payloads(zf, zf.namelist()))\n")


def once(text, old, new, mark, label, notes):
    if mark in text:
        return text
    n = text.count(old)
    if n != 1:
        raise ValueError("%s: anchor found %d times" % (label, n))
    notes.append(label)
    return text.replace(old, new)


def apply_pms(text):
    notes = []
    text = once(text, DOC_ANCHOR, DOC_NEW + DOC_ANCHOR, DOC_MARK, "docstring",
                notes)
    text = once(text, PMS_VER[0], PMS_VER[1], PMS_VER[1], "version 0.9.0",
                notes)
    text = once(text, HELPER_ANCHOR, HELPER_NEW + HELPER_ANCHOR, HELPER_MARK,
                "helper", notes)
    text = once(text, RAW_OLD, RAW_NEW, RAW_MARK, "scan_zip raw_storage",
                notes)
    return text, notes


PLAN = (("pickle_model_scan.py", apply_pms, 4,
         {PMS_VER[0], RAW_OLD.rstrip("\n")}),)


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 0
    tree, out = args
    pdir = os.path.join(out, "patched")
    orig = os.path.join(out, "orig")
    for d in (out, orig, pdir):
        os.makedirs(d, exist_ok=True)
    report = {"files": {}, "ok": False}
    try:
        for name in ("README.md", "PICKLE_SCAN.md", "MODEL_FILE_SCAN.md",
                     "pyproject.toml", "model_file_scan.py",
                     "pickle_model_scan.py", "test_attribution.py"):
            src = os.path.join(tree, name)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(orig, name))
        allpy = os.path.join(out, "tree_py")
        os.makedirs(allpy, exist_ok=True)
        for entry in sorted(os.listdir(tree)):
            if entry.endswith(".py") and os.path.isfile(
                    os.path.join(tree, entry)):
                shutil.copyfile(os.path.join(tree, entry),
                                os.path.join(allpy, entry))
        report["tree_py"] = sorted(os.listdir(allpy))
        staged = {}
        for name, fn, want, replaced in PLAN:
            old = read(os.path.join(tree, name))
            if "\r\n" in old:
                raise ValueError("%s: CRLF" % name)
            new, notes = fn(old)
            again, notes2 = fn(new)
            o, n = old.split("\n"), new.split("\n")
            nset = set(n)
            lost = [ln for ln in o if ln not in nset and ln not in replaced]
            ok = (len(notes) == want and not notes2 and again == new
                  and not lost)
            report["files"][name] = {"changes": notes, "second_pass": notes2,
                                     "lost": lost[:20],
                                     "lines": [len(o), len(n)], "ok": ok}
            if not ok:
                raise ValueError("%s: check failed" % name)
            compile(new, name, "exec")
            staged[name] = new
        for name, new in staged.items():
            write(os.path.join(tree, name), new)
            write(os.path.join(pdir, name), new)
        for test in TESTS:
            for dest in (os.path.join(tree, test), os.path.join(pdir, test)):
                shutil.copyfile(os.path.join(HERE, test), dest)
        report["ok"] = True
        report["written"] = sorted(staged) + list(TESTS)
    except Exception as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps({k: v for k, v in report.items() if k != "tree_py"},
                     indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
