#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""onnx_external_data_scan 0.2.0 and onnx_external_data_key_scan 0.2.0.

Both 0.1.0 scanners walk only ModelProto.graph (field 7). onnx's own loader
also loads external data for attribute tensors inside the model's local
functions (ModelProto.functions, field 25), and onnx.save_model(...,
convert_attribute=True) writes them there. training_info graphs (field 20)
were not walked either. onnx_external_data_scan also stopped reading at
256 MiB, so in an honest inline model between 256 MiB and protobuf's 2 GiB
limit nothing past the first 256 MiB was checked, and the result was clean.

Edits (each exactly once, or already in place; a second pass changes nothing):
  onnx_external_data_scan.py      field constants, _walk_function,
                                  _walk_training_info, scan_bytes walks 25/20,
                                  memoryview (no slice copies), MAX_BYTES 2 GiB,
                                  OED006 MEDIUM when a file exceeds it, 0.2.0
  onnx_external_data_key_scan.py  field constants, _walk_function,
                                  _walk_training_info, scan_bytes walks 25/20,
                                  0.2.0
  ONNX_EXTERNAL_DATA_SCAN.md      a section before "## Honest limits"
  ONNX_EXTERNAL_DATA_KEY_SCAN.md  a section before "## Honest limits" (or end)

Only if every file passes are the patched files written to TREE and
OUT/patched (originals go to ORIG_DIR). The new test module is copied too.
Always exits 0: the result is graded as row P1 by oed_check.py.

Usage: patch_oed.py TREE OUT ORIG_DIR

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEST = "test_onnx_external_data_functions.py"


def _once(pattern, text, what):
    hits = list(re.finditer(pattern, text))
    if len(hits) != 1:
        raise ValueError("%s found %d times" % (what, len(hits)))
    return hits[0]


# ---------------------------------------------------------------- oed scanner
OED_VER_OLD = '__version__ = "0.1.0"'
OED_VER_NEW = '__version__ = "0.2.0"'
OED_MAX_RE = r'(?m)^MAX_BYTES = 256 \* 1024 \* 1024[^\n]*$'
OED_MAX_NEW = ("MAX_BYTES = 2 * 1024 * 1024 * 1024  # protobuf's own 2 GiB "
               "message limit")
OED_CONST_RE = r'(?m)^_F_SSE_VALUE = 2[^\n]*$'
OED_CONST_MARK = "_F_MODEL_FUNCTIONS = 25"
OED_CONSTS = """
_F_MODEL_TRAINING = 20             # ModelProto.training_info (TrainingInfoProto)
_F_MODEL_FUNCTIONS = 25            # ModelProto.functions (FunctionProto)
_F_TRAIN_INIT = 1                  # TrainingInfoProto.initialization (GraphProto)
_F_TRAIN_ALGO = 2                  # TrainingInfoProto.algorithm (GraphProto)
_F_FUNC_NODE = 7                   # FunctionProto.node (repeated NodeProto)
_F_FUNC_ATTR = 11                  # FunctionProto.attribute_proto (AttributeProto)"""
OED_TEXT_OLD = '    return b.decode("utf-8", "surrogateescape")'
OED_TEXT_NEW = '    return bytes(b).decode("utf-8", "surrogateescape")'
OED_GRAPH_END_RE = (r'(?m)^        elif field == _F_GRAPH_NODE:\n'
                    r'            _walk_node\(val, loc, findings, seen, depth\)'
                    r'[ \t]*$')
OED_FUNCS_MARK = "def _walk_function("
OED_FUNCS = '''


def _walk_function(buf, loc: str, findings: list, seen: set,
                   depth: int) -> None:
    """FunctionProto: onnx's loader reads external data for these tensors."""
    if depth > MAX_DEPTH:
        return
    for field, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if field == _F_FUNC_NODE:
            _walk_node(val, loc, findings, seen, depth)
        elif field == _F_FUNC_ATTR:
            _walk_attribute(val, loc, findings, seen, depth)


def _walk_training_info(buf, loc: str, findings: list, seen: set,
                        depth: int) -> None:
    for field, wt, val in _iter_fields(buf):
        if wt == 2 and field in (_F_TRAIN_INIT, _F_TRAIN_ALGO):
            _walk_graph(val, loc, findings, seen, depth + 1)'''
OED_TOP_RE = r'(?m)^([ \t]*)_walk_graph\(val, loc, findings, seen, 0\)[ \t]*$'
OED_TOP_MARK = "field == _F_MODEL_FUNCTIONS:"
OED_TOP_NEW = ("\n{o}elif wt == 2 and field == _F_MODEL_FUNCTIONS:\n"
               "{i}_walk_function(val, loc, findings, seen, 0)\n"
               "{o}elif wt == 2 and field == _F_MODEL_TRAINING:\n"
               "{i}_walk_training_info(val, loc, findings, seen, 0)")
OED_MV_RE = r'(?m)^    found_graph = False[ \t]*$'
OED_MV_MARK = "    data = memoryview(data)"
OED_SF_RE = (r'(?m)^def scan_file\(path: str\) -> list:\n'
             r'    with open\(path, "rb"\) as fh:\n'
             r'        data = fh\.read\(MAX_BYTES\)\n'
             r'    return scan_bytes\(data, path\)\n')
OED_SF_MARK = '"OED006"'
OED_SF_NEW = '''def scan_file(path: str) -> list:
    # Read in 16 MiB chunks: read(MAX_BYTES + 1) would reserve 2 GiB up front.
    data = bytearray()
    with open(path, "rb") as fh:
        while len(data) <= MAX_BYTES:
            chunk = fh.read(min(16 * 1024 * 1024, MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    if len(data) <= MAX_BYTES:
        return scan_bytes(data, path)
    findings = scan_bytes(memoryview(data)[:MAX_BYTES], path)
    findings.append(Finding(
        "OED006", "MEDIUM", "File larger than the scan limit",
        "only the first %d bytes were checked; a single ONNX protobuf "
        "cannot exceed 2 GiB, so this file is not a plain .onnx model or "
        "is malformed" % MAX_BYTES, path, ""))
    return findings
'''


def edit_oed(text):
    notes = []
    if OED_VER_NEW not in text:
        if text.count(OED_VER_OLD) != 1:
            raise ValueError("oed version line found %d times"
                             % text.count(OED_VER_OLD))
        text = text.replace(OED_VER_OLD, OED_VER_NEW)
        notes.append("version 0.2.0")
    if OED_MAX_NEW not in text:
        m = _once(OED_MAX_RE, text, "MAX_BYTES line")
        text = text[:m.start()] + OED_MAX_NEW + text[m.end():]
        notes.append("MAX_BYTES 2 GiB")
    if OED_CONST_MARK not in text:
        m = _once(OED_CONST_RE, text, "_F_SSE_VALUE line")
        text = text[:m.end()] + OED_CONSTS + text[m.end():]
        notes.append("field constants")
    if OED_TEXT_NEW not in text:
        if text.count(OED_TEXT_OLD) != 1:
            raise ValueError("_as_text return found %d times"
                             % text.count(OED_TEXT_OLD))
        text = text.replace(OED_TEXT_OLD, OED_TEXT_NEW)
        notes.append("_as_text accepts memoryview")
    if OED_FUNCS_MARK not in text:
        m = _once(OED_GRAPH_END_RE, text, "_walk_graph node branch")
        text = text[:m.end()] + OED_FUNCS + text[m.end():]
        notes.append("_walk_function/_walk_training_info")
    if OED_TOP_MARK not in text:
        m = _once(OED_TOP_RE, text, "scan_bytes graph call")
        ind = m.group(1)
        if len(ind) < 4:
            raise ValueError("unexpected indent %r" % ind)
        text = (text[:m.end()] + OED_TOP_NEW.format(o=ind[:-4], i=ind)
                + text[m.end():])
        notes.append("scan_bytes walks functions/training_info")
    if OED_MV_MARK not in text:
        m = _once(OED_MV_RE, text, "found_graph line")
        text = text[:m.end()] + "\n" + OED_MV_MARK + text[m.end():]
        notes.append("scan_bytes uses memoryview")
    if OED_SF_MARK not in text:
        m = _once(OED_SF_RE, text, "scan_file block")
        text = text[:m.start()] + OED_SF_NEW + text[m.end():]
        notes.append("scan_file OED006")
    return text, notes


OED_LOST = {OED_VER_OLD, OED_TEXT_OLD,
            "MAX_BYTES = 256 * 1024 * 1024      # read at most 256 MiB of a file",
            "        data = fh.read(MAX_BYTES)",
            "    return scan_bytes(data, path)"}


def oed_lost_ok(line):
    return line in OED_LOST or line.startswith("MAX_BYTES = 256 * 1024 * 1024")


# ---------------------------------------------------------------- key scanner
OEK_CONST_RE = r'(?m)^_SSE_VALUE = 2[^\n]*$'
OEK_CONST_MARK = "_MODEL_FUNCTIONS = 25"
OEK_CONSTS = """
_MODEL_TRAINING_INFO = 20  # ModelProto.training_info (TrainingInfoProto)
_MODEL_FUNCTIONS = 25  # ModelProto.functions (FunctionProto)
_TRAINING_INITIALIZATION = 1  # TrainingInfoProto.initialization (GraphProto)
_TRAINING_ALGORITHM = 2  # TrainingInfoProto.algorithm (GraphProto)
_FUNCTION_NODE = 7  # FunctionProto.node
_FUNCTION_ATTRIBUTE_PROTO = 11  # FunctionProto.attribute_proto"""
OEK_FUNCS_RE = r'(?m)^def scan_bytes\('
OEK_FUNCS_MARK = "def _walk_function("
OEK_FUNCS = '''def _walk_function(buf: bytes, path: str, findings: list[Finding],
                   depth: int) -> None:
    """FunctionProto: onnx's loader reads external data for these tensors."""
    if depth > _MAX_DEPTH:
        return
    for fn, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if fn == _FUNCTION_NODE:
            _walk_node(val, path + ".node", findings, depth + 1)
        elif fn == _FUNCTION_ATTRIBUTE_PROTO:
            _walk_attribute(val, path + ".attribute_proto", findings,
                            depth + 1)


def _walk_training_info(buf: bytes, path: str, findings: list[Finding],
                        depth: int) -> None:
    if depth > _MAX_DEPTH:
        return
    for fn, wt, val in _iter_fields(buf):
        if wt != 2:
            continue
        if fn == _TRAINING_INITIALIZATION:
            _walk_graph(val, path + ".initialization", findings, depth + 1)
        elif fn == _TRAINING_ALGORITHM:
            _walk_graph(val, path + ".algorithm", findings, depth + 1)


'''
OEK_TOP_RE = (r'(?m)^([ \t]*)_walk_graph\(val, source \+ ":graph", findings, '
              r'depth=0\)[ \t]*$')
OEK_TOP_MARK = "fn == _MODEL_FUNCTIONS:"
OEK_TOP_NEW = ("\n{o}elif wt == 2 and fn == _MODEL_FUNCTIONS:\n"
               "{i}_walk_function(val, source + \":functions\", findings, "
               "depth=0)\n"
               "{o}elif wt == 2 and fn == _MODEL_TRAINING_INFO:\n"
               "{i}_walk_training_info(val, source + \":training_info\", "
               "findings, depth=0)")


def edit_oek(text):
    notes = []
    if OED_VER_NEW not in text:
        if text.count(OED_VER_OLD) != 1:
            raise ValueError("oek version line found %d times"
                             % text.count(OED_VER_OLD))
        text = text.replace(OED_VER_OLD, OED_VER_NEW)
        notes.append("version 0.2.0")
    if OEK_CONST_MARK not in text:
        m = _once(OEK_CONST_RE, text, "_SSE_VALUE line")
        text = text[:m.end()] + OEK_CONSTS + text[m.end():]
        notes.append("field constants")
    if OEK_FUNCS_MARK not in text:
        m = _once(OEK_FUNCS_RE, text, "def scan_bytes")
        text = text[:m.start()] + OEK_FUNCS + text[m.start():]
        notes.append("_walk_function/_walk_training_info")
    if OEK_TOP_MARK not in text:
        m = _once(OEK_TOP_RE, text, "scan_bytes graph call")
        ind = m.group(1)
        if len(ind) < 4:
            raise ValueError("unexpected indent %r" % ind)
        text = (text[:m.end()] + OEK_TOP_NEW.format(o=ind[:-4], i=ind)
                + text[m.end():])
        notes.append("scan_bytes walks functions/training_info")
    return text, notes


# ---------------------------------------------------------------- docs
DOC_ANCHOR = "## Honest limits"
OED_DOC_MARK = "<!-- oed-functions -->"
OED_DOC = """<!-- oed-functions -->
## Local functions, training graphs and big files (v0.2.0, November 2026)

onnx's loader loads external data for every tensor that
`external_data_helper._get_all_tensors` returns. That includes tensors in node
attributes of the model's local functions (`ModelProto.functions`), and
`onnx.save_model(..., save_as_external_data=True, convert_attribute=True)`
writes those tensors as external data. Up to 0.1.0 this scanner walked only
`ModelProto.graph`, so a location in a function never reached the checks.
0.2.0 also walks function nodes, function default attributes
(`attribute_proto`) and both `training_info` graphs (initialization and
algorithm). onnx itself does not walk `training_info`, but other tools may.

0.1.0 also read at most 256 MiB of a file. In an honest inline model above
that size (most of the file is weights), the graph field ran past the read
and nothing was checked, so the result was clean. 0.2.0 reads up to 2 GiB,
protobuf's own limit for one message, without copying slices. A file larger
than that cannot be a single ONNX protobuf, so it gets OED006 (MEDIUM,
"file larger than the scan limit") instead of a silent clean result.

Pre-registered check on files written by onnx's own writer:
[research/PREREG_OED_FUNCTIONS.md](research/PREREG_OED_FUNCTIONS.md).

"""
OEK_DOC_MARK = "<!-- oek-functions -->"
OEK_DOC = """<!-- oek-functions -->
## Local functions and training graphs (v0.2.0, November 2026)

Up to 0.1.0 this scanner walked only `ModelProto.graph`. onnx's loader also
loads external data for attribute tensors in the model's local functions
(`ModelProto.functions`), so their `external_data` entries reach the same
`ExternalDataInfo` code. 0.2.0 also walks function nodes, function default
attributes (`attribute_proto`) and both `training_info` graphs. Pre-registered
check: [research/PREREG_OED_FUNCTIONS.md](research/PREREG_OED_FUNCTIONS.md).

"""


def _doc_editor(mark, section):
    def edit(text):
        if mark in text:
            return text, []
        n = text.count("\n" + DOC_ANCHOR)
        if n > 1:
            raise ValueError("doc anchor found %d times" % n)
        if n == 0:
            sep = "" if text.endswith("\n\n") else (
                "\n" if text.endswith("\n") else "\n\n")
            return text + sep + section.rstrip("\n") + "\n", \
                ["doc section (appended)"]
        i = text.index("\n" + DOC_ANCHOR) + 1
        return text[:i] + section + text[i:], ["doc section"]
    return edit


EDITS = (
    ("onnx_external_data_scan.py", edit_oed, oed_lost_ok),
    ("onnx_external_data_key_scan.py", edit_oek,
     lambda ln: ln == OED_VER_OLD),
    ("ONNX_EXTERNAL_DATA_SCAN.md", _doc_editor(OED_DOC_MARK, OED_DOC),
     lambda ln: False),
    ("ONNX_EXTERNAL_DATA_KEY_SCAN.md", _doc_editor(OEK_DOC_MARK, OEK_DOC),
     lambda ln: False),
)


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
        for name, fn, lost_ok in EDITS:
            entry = {}
            try:
                path = os.path.join(tree, name)
                with open(path, encoding="utf-8", newline="") as fh:
                    old = fh.read()
                with open(os.path.join(orig, name), "w", encoding="utf-8",
                          newline="") as fh:
                    fh.write(old)
                if "\r\n" in old:
                    raise ValueError("CRLF")
                new, notes = fn(old)
                again, notes2 = fn(new)
                o, n = old.split("\n"), new.split("\n")
                new_set = set(n)
                lost = [ln for ln in o if ln not in new_set and not lost_ok(ln)]
                compiled = True
                if name.endswith(".py"):
                    try:
                        compile(new, name, "exec")
                    except SyntaxError as exc:
                        compiled = False
                        entry["syntax_error"] = str(exc)
                entry.update({"changes": notes, "second_pass": notes2,
                              "lost": lost, "lines": [len(o), len(n)],
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
