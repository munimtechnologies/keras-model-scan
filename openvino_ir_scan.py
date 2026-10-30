#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""openvino_ir_scan - static scanner for OpenVINO IR model files.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

An OpenVINO Intermediate Representation model is a pair: an ``.xml`` graph and
a ``.bin`` weights file. A ``Const`` layer carries a ``<data>`` child whose
``offset`` and ``size`` attributes name a byte range inside the ``.bin``; the
runtime maps that range as the constant's tensor. The runtime reads the IR
with ``XmlDeserializer`` (``src/core/xml_util/src/xml_deserialize_util.cpp``):
``set_constant_num_buffer`` bounds-checks the range with
``is_valid_weights_range(weights_size, offset, size)`` and rejects a declared
``size`` smaller than ``element_type`` times ``shape``. Two gaps in that path
are worth a static gate:

- the string-tensor branch (``element::string``) calls ``make_region(offset,
  size)`` **without** ``is_valid_weights_range``, so a string ``Const`` with a
  range past the end of the ``.bin`` is read unchecked; and
- the consistency check multiplies ``shape_size(shape) * bitwidth`` in 64-bit
  arithmetic, so a shape whose element count times bitwidth overflows can let a
  far-too-small ``size`` pass (the overflow class addressed in openvino
  PR #39082).

This module parses the ``.xml`` with the Python standard library (no
``openvino``, no ``defusedxml``) and the matching ``.bin`` by its size alone:

- OVI001 high   CWE-611  The IR XML declares a DOCTYPE or ENTITY. A valid IR
                         has neither; a declared entity is an XML
                         external-entity / expansion surface. Parsing is
                         refused.
- OVI002 high   CWE-829  A layer brings external or application code: op type
                         ``python`` or ``custom``, or a ``library`` /
                         ``implementation`` attribute that names a native
                         library (.so/.dll/.dylib/.lib) or a filesystem path.
- OVI003 high   CWE-125  A Const's weights range (offset, size) falls outside
                         the .bin, or a string Const whose range the runtime's
                         string path does not bounds-check.
- OVI004 high   CWE-190  A Const whose element count times element bitwidth
                         overflows 64-bit size arithmetic, or a shape with a
                         negative dimension.
- OVI005 medium CWE-693  A Const declaring fewer bytes than its shape and
                         element_type need (the runtime rejects it at load),
                         the weights .bin missing so ranges cannot be checked,
                         the file not being well-formed OpenVINO IR, or
                         findings capped.

Static review only: nothing is loaded or executed. The .xml is parsed, but no
DOCTYPE/entity document is ever handed to the XML parser.
"""

import os
import re
import sys
import xml.etree.ElementTree as ET

__version__ = "0.1.0"

MAX_FINDINGS = 1000
MAX_EXAMPLES = 3
_U64 = 1 << 64
_SNIFF = 1 << 16

_RULES = {
    "OVI001": ("high", "CWE-611"),
    "OVI002": ("high", "CWE-829"),
    "OVI003": ("high", "CWE-125"),
    "OVI004": ("high", "CWE-190"),
    "OVI005": ("medium", "CWE-693"),
}

_TALLY = {
    "OVI003": "constant weights ranges that fall outside the .bin: %d",
    "OVI004": "constant sizes that overflow or use a negative dimension: %d",
}

# ov::element::Type bit widths. element::string is handled separately.
_BITWIDTH = {
    "f64": 64, "f32": 32, "f16": 16, "bf16": 16,
    "f8e4m3": 8, "f8e5m2": 8, "f8e8m0": 8, "f4e2m1": 4,
    "i64": 64, "i32": 32, "i16": 16, "i8": 8, "i4": 4,
    "u64": 64, "u32": 32, "u16": 16, "u8": 8, "u4": 4, "u2": 2, "u1": 1,
    "nf4": 4, "boolean": 8,
}

_LIB_SUFFIX = re.compile(r"\.(?:so(?:\.\d+)*|dll|dylib|lib)$", re.IGNORECASE)


def _ascii(value, limit=300):
    text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit] + "..."


def _localname(tag):
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def _is_lib_ref(value):
    v = str(value).strip()
    if _LIB_SUFFIX.search(v):
        return True
    return "/" in v or "\\" in v


def _parse_uint(text):
    if text is None:
        return None
    try:
        value = int(str(text).strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _parse_shape(text):
    """Comma-separated integer dims, as the runtime reads the shape attribute.

    Returns a list of ints (a negative dim is kept so it can be flagged), or
    None when a token is not an integer.
    """
    dims = []
    for part in str(text).split(","):
        part = part.strip()
        if part == "":
            continue
        try:
            dims.append(int(part))
        except ValueError:
            return None
    return dims


def _valid_range(weights_size, offset, size):
    """The runtime's is_valid_weights_range, overflow-safe (no offset+size)."""
    return offset <= weights_size and size <= weights_size - offset


class _Findings(object):
    def __init__(self):
        self.items = []
        self._seen = {}
        self.capped = False
        self.counts = {}
        self.examples = {}

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

    def note(self, rule, text):
        """Count one OVI003/OVI004 problem; each rule reports once with examples."""
        self.counts[rule] = self.counts.get(rule, 0) + 1
        examples = self.examples.setdefault(rule, [])
        if len(examples) < MAX_EXAMPLES:
            examples.append(text)

    def result(self):
        for item, count in self._seen.values():
            if count > 1:
                item["evidence"] += "; %d in total" % count
        for rule in sorted(self.counts):
            severity, cwe = _RULES[rule]
            self.items.append({
                "rule": rule, "severity": severity, "cve": "", "cwe": cwe,
                "message": _TALLY[rule] % self.counts[rule],
                "evidence": _ascii("; ".join(self.examples[rule]))})
        if self.capped:
            severity, cwe = _RULES["OVI005"]
            self.items.append({
                "rule": "OVI005", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


def _layer_where(layer):
    lid = layer.get("id")
    name = layer.get("name")
    where = "layer %s" % _ascii(lid if lid is not None else "?")
    if name:
        where += " (%s)" % _ascii(name, 80)
    return where


def _scan_const(layer, where, bin_size, out):
    """Inspect a Const layer's <data> range. Returns 1 if it is bin-backed."""
    dn = None
    for child in layer:
        if _localname(child.tag) == "data":
            dn = child
            break
    if dn is None:
        return 0
    size_attr = dn.get("size")
    if size_attr is None:
        return 0  # an inline value constant, not backed by the .bin
    size = _parse_uint(size_attr)
    offset_attr = dn.get("offset")
    offset = 0 if offset_attr is None else _parse_uint(offset_attr)
    if size is None or offset is None:
        out.add("OVI005", "a Const has an unparsable offset or size",
                "%s: offset=%s size=%s" % (where, _ascii(offset_attr),
                                            _ascii(size_attr)),
                key=("OVI005", "parse", where))
        return 1
    et = (dn.get("element_type") or "").strip().lower()
    is_string = et == "string"

    shape_attr = dn.get("shape")
    dims = _parse_shape(shape_attr) if shape_attr is not None else None
    if dims is not None and any(d < 0 for d in dims):
        out.note("OVI004", "%s: shape %s has a negative dimension"
                 % (where, _ascii(shape_attr, 80)))

    if bin_size is not None and not _valid_range(bin_size, offset, size):
        if is_string:
            out.note("OVI003", "%s: string Const range offset %d size %d is "
                     "outside the %d-byte .bin, and the runtime's string path "
                     "does not bounds-check it"
                     % (where, offset, size, bin_size))
        else:
            out.note("OVI003", "%s: Const range offset %d size %d is outside "
                     "the %d-byte .bin" % (where, offset, size, bin_size))

    if dims is not None and all(d >= 0 for d in dims) and et in _BITWIDTH:
        count = 1
        for d in dims:
            count *= d
        product = count * _BITWIDTH[et]
        if product >= _U64:
            out.note("OVI004", "%s: element count %d x %d-bit overflows 64-bit "
                     "size arithmetic" % (where, count, _BITWIDTH[et]))
        else:
            needed = (product + 7) >> 3
            if size < needed:
                out.add("OVI005", "a Const declares fewer bytes than its shape "
                        "and element_type need; the runtime rejects it at load",
                        "%s: size %d, needs %d (%s %s)"
                        % (where, size, needed, et, _ascii(shape_attr or "", 80)),
                        key=("OVI005", "small", where))
    return 1


def _scan_layer(layer, bin_size, out):
    where = _layer_where(layer)
    op_type = layer.get("type") or ""
    if op_type.lower() in ("python", "custom"):
        out.add("OVI002", "a layer runs application-registered code: op type "
                "'%s'" % _ascii(op_type, 40), where,
                key=("OVI002", "type", op_type.lower()))
    for element in layer.iter():
        for attr, val in element.attrib.items():
            if _localname(attr) in ("library", "implementation") and \
                    _is_lib_ref(val):
                out.add("OVI002", "a layer references an external native library "
                        "or path via %s=" % _localname(attr),
                        "%s: %s" % (where, _ascii(val, 200)),
                        key=("OVI002", "lib", _ascii(val, 200)))
    if op_type == "Const":
        return _scan_const(layer, where, bin_size, out)
    return 0


def _scan_xml(data, bin_size, out):
    raw = bytes(data) if not isinstance(data, bytes) else data
    if b"<!doctype" in raw[:_SNIFF].lower() or \
            b"<!entity" in raw[:_SNIFF].lower():
        out.add("OVI001", "the IR XML declares a DOCTYPE or ENTITY; a valid "
                "OpenVINO IR has neither, and a declared entity is an XML "
                "external-entity / expansion surface", "parsing refused")
        return
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        out.add("OVI005", "not a well-formed XML document", _ascii(exc))
        return
    if _localname(root.tag) not in ("net", "model"):
        out.add("OVI005", "root element is <%s>, not an OpenVINO IR <net> or "
                "<model>" % _ascii(_localname(root.tag) or "?", 40), "")
        return
    bin_backed = 0
    for element in root.iter():
        if _localname(element.tag) == "layer":
            bin_backed += _scan_layer(element, bin_size, out)
    if bin_size is None and bin_backed:
        out.add("OVI005", "the weights .bin was not found, so %d Const "
                "offset/size range(s) were not checked against it" % bin_backed,
                "")


def _scan(data, bin_size):
    out = _Findings()
    try:
        _scan_xml(data, bin_size, out)
    except Exception as exc:  # hostile input must never crash the scan
        out.add("OVI005", "the IR could not be parsed; findings before this "
                "point are kept", "%s: %s" % (type(exc).__name__, _ascii(exc)))
    return out.result()


def scan_bytes(data, name="", bin_size=None):
    """Scan an in-memory IR .xml. ``bin_size`` is the matching .bin's length
    (None when it is unknown). Returns a list of finding dicts."""
    return _scan(data, bin_size)


def scan_file(path):
    """Scan an IR .xml on disk, locating the sibling .bin by name for its size."""
    with open(path, "rb") as handle:
        data = handle.read()
    bin_size = None
    stem, ext = os.path.splitext(path)
    if ext.lower() == ".xml":
        candidate = stem + ".bin"
        if os.path.isfile(candidate):
            try:
                bin_size = os.path.getsize(candidate)
            except OSError:
                bin_size = None
    return scan_bytes(data, name=path, bin_size=bin_size)


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python openvino_ir_scan.py MODEL.xml [...]",
              file=sys.stderr)
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
