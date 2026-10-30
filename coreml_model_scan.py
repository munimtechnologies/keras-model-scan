#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""coreml_model_scan - static scanner for Core ML model files.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

A Core ML ``.mlmodel`` is a ``CoreML.Specification.Model`` protobuf
(coremltools ``mlmodel/format/Model.proto``). An ``.mlpackage`` is a folder:
``Manifest.json`` lists items whose ``path`` is relative to ``Data/``, and the
root item is the ``model.mlmodel`` spec; ML Program weights sit beside it in
``weights/weight.bin``. Several parts of a model make Core ML reach outside the
file itself, and a CI gate should see them:

- ``customModel`` (Model field 555) and a ``custom`` layer (NeuralNetworkLayer
  field 500) name an app class (``MLCustomModel`` / ``MLCustomLayer``) that
  Core ML instantiates and runs. Custom layers can sit inside ``branch``
  (field 605) and ``loop`` (field 615) layers, nested to any depth.
- ``linkedModel`` (field 556) loads another compiled model by file name and a
  ``:``-separated search path; entries may be absolute, relative, or start
  with ``$BUNDLE_MAIN`` / ``$BUNDLE_IDENTIFIER(id)``.
- an ML Program (field 502) refers to weights by ``BlobFileValue.fileName``,
  written by coremltools as ``@model_path/weights/weight.bin``.
- ``Manifest.json`` item paths and any symbolic links under ``Data/``.

This module decodes the protobuf with the Python standard library (no
coremltools, no protobuf package) and reports:

- CML001 high   CWE-829  A customModel or custom layer (at any nesting depth,
                         including branch/loop bodies and pipeline members)
                         names an app class that Core ML would run.
- CML002 high   CWE-73   A linkedModel file name or search-path entry leaves
                         the model's own location: absolute, ``~``, a ``..``
                         segment, or a ``$`` variable other than the two
                         bundle prefixes.
- CML003 high   CWE-22   An ML Program weight file reference escapes the
                         model package (absolute, ``~``, URL, or ``..``).
- CML004 high   CWE-22   An .mlpackage Manifest.json item path escapes
                         ``Data/`` (absolute, ``~``, ``..``) or a symbolic link
                         under ``Data/`` points outside the package.
- CML005 medium CWE-693  Not a parseable Core ML spec or manifest, the root
                         item missing, nesting too deep, or findings capped.

Static review only: nothing is loaded, compiled or executed.
"""

import json
import os
import re
import sys

__version__ = "0.1.0"

MAX_FINDINGS = 1000
MAX_DEPTH = 32
MAX_FIELDS = 200000
MAX_STRINGS = 200000
_SPEC_MAX = 10000
_PRINTABLE_MAX = 4096

_RULES = {
    "CML001": ("high", "CWE-829"),
    "CML002": ("high", "CWE-73"),
    "CML003": ("high", "CWE-22"),
    "CML004": ("high", "CWE-22"),
    "CML005": ("medium", "CWE-693"),
}

# Model.Type oneof members (Model.proto) this scanner descends into.
_PIPELINE_WRAPPED = (200, 201)      # PipelineClassifier/Regressor: pipeline = 1
_PIPELINE = 202                     # Pipeline: repeated Model models = 1
_NEURAL_NETWORKS = (303, 403, 500)  # NeuralNetworkRegressor/Classifier/NeuralNetwork
_ML_PROGRAM = 502
_CUSTOM_MODEL = 555                 # CustomModel: className = 10
_LINKED_MODEL = 556                 # LinkedModel: linkedModelFile = 1

# NeuralNetworkLayer oneof members (NeuralNetwork.proto).
_LAYER_CUSTOM = 500                 # CustomLayerParams: className = 10
_LAYER_BRANCH = 605                 # BranchLayerParams: ifBranch = 1, elseBranch = 2
_LAYER_LOOP = 615                   # LoopLayerParams: conditionNetwork = 3, bodyNetwork = 4

_MODEL_PATH = "@model_path/"
_DRIVE = re.compile(r"^[A-Za-z]:")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_BUNDLE_ID = re.compile(r"^\$BUNDLE_IDENTIFIER\([^)]*\)")
_SEP = re.compile(r"[\\/]+")


class _Bad(Exception):
    pass


def _ascii(value, limit=300):
    text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit] + "..."


class _Findings(object):
    def __init__(self):
        self.items = []
        self._seen = {}
        self.capped = False

    def add(self, rule, message, evidence, key=None):
        if key is not None and key in self._seen:
            self._seen[key][1] += 1
            return
        if len(self.items) >= MAX_FINDINGS:
            self.capped = True
            return
        severity, cwe = _RULES[rule]
        item = {"rule": rule, "severity": severity, "cve": "", "cwe": cwe,
                "message": _ascii(message), "evidence": _ascii(evidence)}
        self.items.append(item)
        if key is not None:
            self._seen[key] = [item, 1]

    def result(self):
        for item, count in self._seen.values():
            if count > 1:
                item["evidence"] += "; %d in total" % count
        if self.capped:
            severity, cwe = _RULES["CML005"]
            self.items.append({
                "rule": "CML005", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


# -- protobuf wire format -----------------------------------------------------

def _varint(buf, pos, end):
    result = 0
    shift = 0
    while True:
        if pos >= end:
            raise _Bad("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise _Bad("varint too long")


def _fields(buf):
    """Decode one message into (field, wire, value) tuples. Length-delimited
    values are memoryview slices; fixed-width values are skipped as None."""
    pos = 0
    end = len(buf)
    out = []
    while pos < end:
        key, pos = _varint(buf, pos, end)
        field, wire = key >> 3, key & 7
        if field == 0:
            raise _Bad("field number 0")
        if wire == 0:
            value, pos = _varint(buf, pos, end)
        elif wire == 1:
            if end - pos < 8:
                raise _Bad("truncated fixed64")
            value, pos = None, pos + 8
        elif wire == 2:
            length, pos = _varint(buf, pos, end)
            if length > end - pos:
                raise _Bad("length-delimited field runs past the end")
            value, pos = buf[pos:pos + length], pos + length
        elif wire == 5:
            if end - pos < 4:
                raise _Bad("truncated fixed32")
            value, pos = None, pos + 4
        else:
            raise _Bad("unsupported wire type %d" % wire)
        out.append((field, wire, value))
        if len(out) > MAX_FIELDS:
            raise _Bad("more than %d fields in one message" % MAX_FIELDS)
    return out


def _first(fields, number):
    for field, wire, value in fields:
        if field == number and wire == 2:
            return value
    return None


def _string(view):
    return bytes(view).decode("utf-8", "replace")


def _string_field(view, number):
    value = _first(_fields(view), number)
    return "" if value is None else _string(value)


# -- path checks --------------------------------------------------------------

def _escape_reason(path):
    """Why a path meant to be relative would leave its base, or None."""
    p = str(path)
    if p.startswith("~"):
        return "starts with ~ (a home directory)"
    if _SCHEME.match(p):
        return "is a URL"
    if p.startswith("/") or p.startswith("\\") or _DRIVE.match(p):
        return "is an absolute path"
    if ".." in _SEP.split(p):
        return "has a .. segment"
    return None


def _search_path_reason(entry):
    if entry.startswith("$BUNDLE_MAIN"):
        rest = entry[len("$BUNDLE_MAIN"):]
    else:
        match = _BUNDLE_ID.match(entry)
        if match:
            rest = entry[match.end():]
        elif entry.startswith("$"):
            return "uses a $ variable other than $BUNDLE_MAIN / $BUNDLE_IDENTIFIER()"
        else:
            return _escape_reason(entry)
    if ".." in _SEP.split(rest):
        return "has a .. segment after the bundle prefix"
    return None


def _inside(base, target):
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    try:
        return os.path.commonpath([base, target]) == base
    except ValueError:
        return False


# -- model spec ---------------------------------------------------------------

def _too_deep(where, out):
    out.add("CML005", "nesting is deeper than %d levels; deeper parts were "
            "not checked" % MAX_DEPTH, where, key=("CML005", "depth"))


def _class_name(view):
    value = _first(_fields(view), 10)
    return _string(value) if value is not None else ""


def _walk_model(view, depth, where, out):
    if depth > MAX_DEPTH:
        _too_deep(where, out)
        return
    for field, wire, value in _fields(view):
        if wire != 2:
            continue
        if field in _PIPELINE_WRAPPED:
            inner = _first(_fields(value), 1)
            if inner is not None:
                _walk_pipeline(inner, depth + 1, where, out)
        elif field == _PIPELINE:
            _walk_pipeline(value, depth + 1, where, out)
        elif field in _NEURAL_NETWORKS:
            _walk_network(value, depth + 1, where, out)
        elif field == _ML_PROGRAM:
            _check_program(value, where, out)
        elif field == _CUSTOM_MODEL:
            name = _class_name(value)
            out.add("CML001", "the model is a customModel: Core ML runs the "
                    "app class it names (MLCustomModel)",
                    "%s: className %s" % (where, _ascii(name or "(none)", 120)),
                    key=("CML001", "model", name))
        elif field == _LINKED_MODEL:
            _check_linked(value, where, out)


def _walk_pipeline(view, depth, where, out):
    if depth > MAX_DEPTH:
        _too_deep(where, out)
        return
    index = 0
    for field, wire, value in _fields(view):
        if field == 1 and wire == 2:
            _walk_model(value, depth + 1,
                        "%s > pipeline model %d" % (where, index), out)
            index += 1


def _walk_network(view, depth, where, out):
    if depth > MAX_DEPTH:
        _too_deep(where, out)
        return
    for field, wire, value in _fields(view):
        if field != 1 or wire != 2:
            continue
        layer = _fields(value)
        name = _first(layer, 1)
        lwhere = "%s > layer %s" % (
            where, _ascii(_string(name) if name is not None else "?", 80))
        for lfield, lwire, lvalue in layer:
            if lwire != 2:
                continue
            if lfield == _LAYER_CUSTOM:
                cls = _class_name(lvalue)
                out.add("CML001", "a custom layer: Core ML runs the app class "
                        "it names (MLCustomLayer)",
                        "%s: className %s" % (lwhere,
                                              _ascii(cls or "(none)", 120)),
                        key=("CML001", "layer", cls))
            elif lfield == _LAYER_BRANCH:
                for bfield, bwire, bvalue in _fields(lvalue):
                    if bfield in (1, 2) and bwire == 2:
                        _walk_network(bvalue, depth + 1, lwhere + (
                            " (if)" if bfield == 1 else " (else)"), out)
            elif lfield == _LAYER_LOOP:
                for bfield, bwire, bvalue in _fields(lvalue):
                    if bfield in (3, 4) and bwire == 2:
                        _walk_network(bvalue, depth + 1, lwhere + (
                            " (condition)" if bfield == 3 else " (body)"), out)


def _check_linked(view, where, out):
    for field, wire, value in _fields(view):
        if field != 1 or wire != 2:
            continue  # LinkedModel.linkedModelFile = 1
        link = _fields(value)
        name_v = _first(link, 1)    # StringParameter linkedModelFileName
        path_v = _first(link, 2)    # StringParameter linkedModelSearchPath
        name = _string_field(name_v, 1) if name_v is not None else ""
        search = _string_field(path_v, 1) if path_v is not None else ""
        reason = _escape_reason(name) if name else None
        if reason:
            out.add("CML002", "a linkedModel file name %s" % reason,
                    "%s: linkedModelFileName %s" % (where, _ascii(name, 200)),
                    key=("CML002", "name", name))
        for entry in search.split(":"):
            reason = _search_path_reason(entry)
            if reason:
                out.add("CML002", "a linkedModel search path entry %s" % reason,
                        "%s: linkedModelSearchPath entry %s"
                        % (where, _ascii(entry, 200)),
                        key=("CML002", "path", entry))


def _collect_strings(view, depth, found, budget):
    """Collect printable length-delimited leaves of an unknown message tree."""
    if depth > MAX_DEPTH:
        return
    try:
        fields = _fields(view)
    except _Bad:
        return
    for field, wire, value in fields:
        if wire != 2 or budget[0] <= 0:
            continue
        budget[0] -= 1
        if 0 < len(value) <= _PRINTABLE_MAX:
            raw = bytes(value)
            if all(0x20 <= c < 0x7F for c in raw):
                found.append(raw.decode("ascii"))
                continue
        _collect_strings(value, depth + 1, found, budget)


def _check_program(view, where, out):
    found = []
    _collect_strings(view, 0, found, [MAX_STRINGS])
    for text in found:
        if text.startswith(_MODEL_PATH):
            reason = _escape_reason(text[len(_MODEL_PATH):].lstrip("/"))
        elif text.lower().endswith(".bin"):
            reason = _escape_reason(text)
        else:
            continue
        if reason:
            out.add("CML003", "an ML Program weight file reference %s, so it "
                    "points outside the model package" % reason,
                    "%s: %s" % (where, _ascii(text, 200)),
                    key=("CML003", text))


def _scan_model(data, where, out):
    view = memoryview(data)
    try:
        fields = _fields(view)
    except _Bad as exc:
        out.add("CML005", "not a parseable Core ML protobuf", _ascii(exc))
        return
    spec = [value for field, wire, value in fields if field == 1 and wire == 0]
    if not spec or not 1 <= spec[0] <= _SPEC_MAX:
        out.add("CML005", "no plausible specificationVersion; not a Core ML "
                "model spec", _ascii(where, 200))
        return
    _walk_model(view, 0, where, out)


# -- .mlpackage -----------------------------------------------------------------

def _scan_manifest(data, out, package_dir=None):
    """Check Manifest.json item paths. Returns the root item's path or None."""
    try:
        manifest = json.loads(bytes(data).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        out.add("CML005", "Manifest.json is not valid JSON", _ascii(exc))
        return None
    entries = manifest.get("itemInfoEntries") \
        if isinstance(manifest, dict) else None
    if not isinstance(entries, dict):
        out.add("CML005", "Manifest.json has no itemInfoEntries object", "")
        return None
    data_dir = os.path.join(package_dir, "Data") if package_dir else None
    unsafe = set()
    for ident, entry in entries.items():
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str):
            out.add("CML005", "a Manifest.json item has no path string",
                    "item %s" % _ascii(ident, 80), key=("CML005", "path", ident))
            unsafe.add(ident)
            continue
        reason = _escape_reason(path)
        if reason is None and data_dir is not None and \
                not _inside(data_dir, os.path.join(data_dir, path)):
            reason = "resolves through a symbolic link"
        if reason:
            out.add("CML004", "a Manifest.json item path %s, so it points "
                    "outside the package's Data/ folder" % reason,
                    "item %s: %s" % (_ascii(ident, 80), _ascii(path, 200)),
                    key=("CML004", "item", ident))
            unsafe.add(ident)
    root = manifest.get("rootModelIdentifier")
    if not isinstance(root, str) or root not in entries:
        out.add("CML005", "rootModelIdentifier does not name an item in "
                "itemInfoEntries", _ascii(root, 80))
        return None
    if root in unsafe:
        return None
    return entries[root]["path"]


def _scan_links(data_dir, out):
    if not os.path.isdir(data_dir):
        return
    for base, dirs, files in os.walk(data_dir):
        for name in dirs + files:
            full = os.path.join(base, name)
            if os.path.islink(full) and not _inside(data_dir, full):
                out.add("CML004", "a symbolic link inside Data/ points outside "
                        "the package", _ascii(os.path.relpath(full, data_dir),
                                              200),
                        key=("CML004", "link", full))


def _scan_package(path, out):
    manifest_path = os.path.join(path, "Manifest.json")
    if not os.path.isfile(manifest_path):
        out.add("CML005", "no Manifest.json; not a Core ML .mlpackage",
                _ascii(path, 200))
        return
    with open(manifest_path, "rb") as handle:
        root = _scan_manifest(handle.read(), out, package_dir=path)
    data_dir = os.path.join(path, "Data")
    _scan_links(data_dir, out)
    if root is None:
        return
    model_path = os.path.join(data_dir, root)
    if not os.path.isfile(model_path):
        out.add("CML005", "the root model named by Manifest.json is missing",
                _ascii(root, 200))
        return
    with open(model_path, "rb") as handle:
        _scan_model(handle.read(), root, out)


def _scan_blob(data, where, out):
    if bytes(data[:64]).lstrip().startswith(b"{"):
        _scan_manifest(data, out)
    else:
        _scan_model(data, where, out)


def _guard(out, func, *args):
    """Run func(*args, out), turning a parser crash into a CML005 finding."""
    try:
        func(*args, out)
    except OSError:
        raise
    except Exception as exc:  # hostile input must never crash the scan
        out.add("CML005", "the model could not be parsed; findings before "
                "this point are kept",
                "%s: %s" % (type(exc).__name__, _ascii(exc)))


def scan_bytes(data, name=""):
    """Scan an in-memory .mlmodel spec or Manifest.json. Returns findings."""
    out = _Findings()
    _guard(out, _scan_blob, data, name or "model")
    return out.result()


def scan_file(path):
    """Scan a .mlmodel file, a Manifest.json, or an .mlpackage directory."""
    out = _Findings()
    if os.path.isdir(path):
        _guard(out, _scan_package, path)
    elif os.path.basename(path) == "Manifest.json":
        _guard(out, _scan_package, os.path.dirname(os.path.abspath(path)))
    else:
        with open(path, "rb") as handle:
            data = handle.read()
        _guard(out, _scan_model, data, os.path.basename(path))
    return out.result()


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python coreml_model_scan.py MODEL.mlmodel|MODEL.mlpackage "
              "[...]", file=sys.stderr)
        return 2
    failed = high = False
    for path in args:
        try:
            findings = scan_file(path)
        except OSError as exc:
            print("%s: cannot read: %s" % (path, exc), file=sys.stderr)
            failed = True
            continue
        if not findings:
            print("%s: no findings" % path)
        for item in findings:
            print("%s: %s %s: %s [%s]" % (path, item["rule"], item["severity"],
                                          item["message"], item["evidence"]))
            high = high or item["severity"] == "high"
    if failed:
        return 2
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
