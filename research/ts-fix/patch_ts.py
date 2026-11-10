#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""model-file-scan 0.14.0 + pickle_model_scan 0.7.0: TorchScript files.

Job torchscript-v1 (research/PREREG_TORCHSCRIPT.md) held 10 of 10 rows:
  W2  a folder walk skips .ptl, .torchscript and .pt2 files;
  D1  an honest TorchScript archive gets one PKL003 MEDIUM per __torch__ class;
  G1  every unknown global in those pickles is a __torch__ name;
  L1  torch.load hands a TorchScript zip to torch.jit.load.
PyTorch's SECURITY.md says to treat TorchScript models like locally executable
code from an unknown source, so the severity stays MEDIUM.

Edits (each exactly once, or already in place; a second pass changes nothing;
no line is lost except the replaced version lines):
  model_file_scan.py   __version__ 0.13.2 -> 0.14.0; ".ptl", ".torchscript",
                       ".pt2" added to _MODEL_EXTS (the folder walk)
  pyproject.toml       version 0.13.2 -> 0.14.0 (test_attribution)
  pickle_model_scan.py docstring paragraph; __version__ 0.6.0 -> 0.7.0;
                       helpers _torchscript_prefixes / _collapse_torchscript
                       before scan_zip; scan_zip ends by replacing the
                       __torch__ PKL003 findings of data.pkl, constants.pkl
                       and bytecode.pkl in a TorchScript archive with ONE
                       PKL040 MEDIUM per archive. Every other finding,
                       including PKL003 for any non-__torch__ import, is kept.
and copies the two new test files into TREE. All-or-nothing: nothing is
written unless every edit checks out. Changed files go to OUT/patched,
originals to OUT/orig, the report to OUT/patch_report.json. Always exits 0;
the check grades row P1.

Usage: patch_ts.py TREE OUT

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = ("test_model_file_scan_torchscript_walk.py",
         "test_pickle_model_scan_torchscript.py")

MFS_VER = ('__version__ = "0.13.2"', '__version__ = "0.14.0"')
MFS_EXT_OLD = '    ".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin",\n'
MFS_EXT_MARK = '".ptl", ".torchscript", ".pt2",'
MFS_EXT_NEW = (MFS_EXT_OLD +
               '    ".ptl", ".torchscript", ".pt2",  # TorchScript, PyTorch'
               ' mobile, torch.export (0.14.0)\n')

PYP_VER = ('version = "0.13.2"', 'version = "0.14.0"')

PMS_VER = ('__version__ = "0.6.0"', '__version__ = "0.7.0"')
DOC_ANCHOR = "A flag means a pattern worth human review, not proof of malice."
DOC_MARK = "Since 0.7.0, a TorchScript archive"
DOC_NEW = (
    "Since 0.7.0, a TorchScript archive (torch.jit.save or the PyTorch mobile\n"
    "lite-interpreter writer: <prefix>/data.pkl next to a <prefix>/code/ folder\n"
    "or a <prefix>/bytecode.pkl) gets ONE finding, PKL040 MEDIUM \"TorchScript\n"
    "archive: treat as executable code\", instead of one PKL003 per __torch__\n"
    "class. torch.jit.load builds those classes from the code stored in the\n"
    "archive; they are not Python imports. PyTorch's SECURITY.md says to treat\n"
    "TorchScript models like locally executable code from an unknown source, so\n"
    "the severity stays MEDIUM. Any other import keeps its usual rule.\n"
    "\n")

HELPER_ANCHOR = "def scan_zip(data, source):\n"
HELPER_MARK = "def _torchscript_prefixes("
HELPER_NEW = r'''_TS_IMPORT = "Pickle imports __torch__."
_TS_MEMBERS = frozenset({"data.pkl", "constants.pkl", "bytecode.pkl"})


def _torchscript_prefixes(names):
    """Prefixes of the TorchScript archives inside a zip.

    torch.jit.save writes <prefix>/data.pkl next to a <prefix>/code/ folder
    of TorchScript source; the lite-interpreter writer also adds
    <prefix>/bytecode.pkl. torch.jit.load compiles that stored code and
    builds every __torch__.* class from it; it never imports a Python module
    of that name. Returns the prefixes (e.g. "model/") that have a data.pkl
    and either a code/ folder or a bytecode.pkl."""
    data_prefixes, marked = set(), set()
    for name in names:
        parts = name.split("/")
        last = parts[-1]
        if last == "data.pkl":
            data_prefixes.add(name[:-len(last)])
        elif last == "bytecode.pkl":
            marked.add(name[:-len(last)])
        acc = ""
        for part in parts[:-1]:
            if part == "code":
                marked.add(acc)
            acc += part + "/"
    return data_prefixes & marked


def _collapse_torchscript(findings, prefixes, source):
    """One PKL040 per TorchScript archive instead of one PKL003 per class.

    Only a PKL003 that names a __torch__ class AND sits in the archive's own
    data.pkl, constants.pkl or bytecode.pkl is folded in. Every other finding
    (any other rule, any non-__torch__ import, any other member) is kept
    unchanged, so the highest severity of a file never goes down."""
    head = f"{source}!"
    kept, classes = [], {}
    for f in findings:
        prefix = None
        if (f.rule == "PKL003" and f.detail.startswith(_TS_IMPORT)
                and f.location.startswith(head)):
            member = f.location[len(head):].rsplit(" @ byte ", 1)[0]
            folder, _sep, base = member.rpartition("/")
            folder = folder + "/" if _sep else ""
            if base in _TS_MEMBERS and folder in prefixes:
                prefix = folder
        if prefix is None:
            kept.append(f)
        else:
            ref = f.detail[len("Pickle imports "):].split(",", 1)[0]
            classes.setdefault(prefix, set()).add(ref)
    out = []
    for prefix in sorted(prefixes):
        refs = sorted(classes.get(prefix, ()))
        if refs:
            shown = ", ".join(refs[:3])
            if len(refs) > 3:
                shown += f" and {len(refs) - 3} more"
            what = (f"Its {len(refs)} TorchScript class name(s) ({shown}) are "
                    "built by torch.jit.load from the code stored in the "
                    "archive, not imported from Python.")
        else:
            what = ("Its TorchScript code is stored in the archive and is "
                    "compiled by torch.jit.load.")
        out.append(Finding(
            "PKL040", "MEDIUM", "TorchScript archive: treat as executable code",
            "This zip is a TorchScript program (torch.jit.save, or the PyTorch "
            f"mobile lite-interpreter writer). {what} PyTorch's security "
            "policy (SECURITY.md) says to treat TorchScript models like "
            "locally executable code from an unknown source: load it only "
            "from a provider you trust. Other imports in the archive are "
            "reported by their usual rules.", f"{head}{prefix}data.pkl"))
    return out + kept


'''

SZ_OLD = r'''        elif (ext in PICKLE_EXTS or base == "data.pkl"
              or (member[:1] == b"\x80" and name not in raw_storage)):
            findings += scan_pickle_bytes(member, member_src)
    return findings
'''
SZ_MARK = "ts_prefixes = _torchscript_prefixes(zf.namelist())"
SZ_NEW = r'''        elif (ext in PICKLE_EXTS or base == "data.pkl"
              or (member[:1] == b"\x80" and name not in raw_storage)):
            findings += scan_pickle_bytes(member, member_src)
    ts_prefixes = _torchscript_prefixes(zf.namelist())
    if ts_prefixes:
        findings = _collapse_torchscript(findings, ts_prefixes, source)
    return findings
'''


def once(text, old, new, mark, label, notes):
    if mark in text:
        return text
    n = text.count(old)
    if n != 1:
        raise ValueError("%s: anchor found %d times" % (label, n))
    notes.append(label)
    return text.replace(old, new)


def apply_mfs(text):
    notes = []
    text = once(text, MFS_VER[0], MFS_VER[1], MFS_VER[1], "version 0.14.0",
                notes)
    text = once(text, MFS_EXT_OLD, MFS_EXT_NEW, MFS_EXT_MARK, "walk exts",
                notes)
    return text, notes


def apply_pyp(text):
    notes = []
    text = once(text, PYP_VER[0], PYP_VER[1], PYP_VER[1], "version 0.14.0",
                notes)
    return text, notes


def apply_pms(text):
    notes = []
    text = once(text, DOC_ANCHOR, DOC_NEW + DOC_ANCHOR, DOC_MARK, "docstring",
                notes)
    text = once(text, PMS_VER[0], PMS_VER[1], PMS_VER[1], "version 0.7.0",
                notes)
    text = once(text, HELPER_ANCHOR, HELPER_NEW + HELPER_ANCHOR, HELPER_MARK,
                "helpers", notes)
    text = once(text, SZ_OLD, SZ_NEW, SZ_MARK, "scan_zip", notes)
    return text, notes


PLAN = (("model_file_scan.py", apply_mfs, 2, {MFS_VER[0]}),
        ("pyproject.toml", apply_pyp, 1, {PYP_VER[0]}),
        ("pickle_model_scan.py", apply_pms, 4, {PMS_VER[0]}))


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
        # verbatim originals for the next run's doc edits
        for name in ("README.md", "PICKLE_SCAN.md", "MODEL_FILE_SCAN.md",
                     "pyproject.toml", "model_file_scan.py",
                     "pickle_model_scan.py", "test_attribution.py"):
            src = os.path.join(tree, name)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(orig, name))
        # every top-level module of v0.57.0, so the release's test_first
        # scratch copy can import whatever model_file_scan imports
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
            if name.endswith(".py"):
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
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
