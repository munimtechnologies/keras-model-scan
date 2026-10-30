#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""tflite_model_scan - static scanner for TensorFlow Lite (LiteRT) .tflite files.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

A .tflite file is a FlatBuffer (identifier ``TFL3``). Built-in operators run
TFLite's own kernels. Custom operators run whatever the application registered
under their ``custom_code``; a custom op whose ``custom_code`` starts with
``Flex`` is claimed by the Flex delegate (select TF ops), which builds and runs
a full TensorFlow op. The delegate takes that op from the operator's
``custom_options`` (a FlexBuffer vector of an op name and a serialized
NodeDef), not from ``custom_code``, so ``custom_code`` is only a label.

This module parses the FlatBuffer itself (no ``tensorflow``, ``tflite`` or
``flatbuffers`` import), decodes each Flex operator's FlexBuffer and NodeDef,
and reports:

- TFL001 high   CWE-829  Flex operator whose TensorFlow op reads or writes
                         files, dumps tensors, or calls back into Python.
- TFL002 high   CWE-436  Flex operator whose labels disagree: the custom_code
                         suffix, the op name in the options and the NodeDef op
                         are not all the same. A converter writes them equal.
- TFL003 medium CWE-829  Any other Flex operator (full TensorFlow runtime), or
                         a non-Flex custom operator (application native code).
- TFL004 medium CWE-129  Out-of-range references: opcode, tensor or buffer
                         index past its table, buffer data outside the file,
                         or a shape dimension below -1.
- TFL005 medium CWE-693  Not a well-formed TFLite FlatBuffer, Flex options
                         that do not decode, or findings capped.

Static review only: nothing is loaded, converted or executed.
"""

import mmap
import struct
import sys

__version__ = "0.1.0"

FILE_IDENTIFIER = b"TFL3"
FLEX_PREFIX = b"Flex"
BUILTIN_CUSTOM = 32
MAX_FINDINGS = 1000
MAX_EXAMPLES = 3

_RULES = {
    "TFL001": ("high", "CWE-829"),
    "TFL002": ("high", "CWE-436"),
    "TFL003": ("medium", "CWE-829"),
    "TFL004": ("medium", "CWE-129"),
    "TFL005": ("medium", "CWE-693"),
}

_READS = "reads files named by its inputs or attributes"
_WRITES = "writes files named by its inputs or attributes"
_DUMPS = "copies tensors to the debug URLs named in its attributes"
_PYTHON = "calls back into the Python process that runs the model"

_RISKY_OPS = {}
for _name in ("ReadFile", "MatchingFiles", "ImmutableConst", "WholeFileReader",
              "WholeFileReaderV2", "TextLineReader", "TextLineReaderV2",
              "FixedLengthRecordReader", "FixedLengthRecordReaderV2",
              "TFRecordReader", "TFRecordReaderV2", "LMDBReader", "Restore",
              "RestoreSlice", "RestoreV2", "TextLineDataset", "TFRecordDataset",
              "TFRecordDatasetV2", "FixedLengthRecordDataset",
              "FixedLengthRecordDatasetV2", "LMDBDataset",
              "ExperimentalLMDBDataset", "CSVDataset", "CSVDatasetV2",
              "ExperimentalCSVDataset", "LoadDataset",
              "InitializeTableFromTextFile", "InitializeTableFromTextFileV2"):
    _RISKY_OPS[_name] = _READS
for _name in ("WriteFile", "Save", "SaveSlices", "SaveV2", "MergeV2Checkpoints",
              "SaveDataset", "SaveDatasetV2", "DatasetToTFRecord",
              "ExperimentalDatasetToTFRecord", "CreateSummaryFileWriter",
              "CreateSummaryDbWriter"):
    _RISKY_OPS[_name] = _WRITES
for _name in ("DebugIdentity", "DebugIdentityV2", "DebugNanCount",
              "DebugNumericSummary", "DebugNumericSummaryV2"):
    _RISKY_OPS[_name] = _DUMPS
for _name in ("PyFunc", "PyFuncStateless", "EagerPyFunc"):
    _RISKY_OPS[_name] = _PYTHON
del _name

# FlexBuffer value types (flatbuffers/flexbuffers.h).
_FBT_KEY = 4
_FBT_STRING = 5
_FBT_MAP = 9
_FBT_VECTOR = 10


class _Malformed(Exception):
    pass


def _ascii(value, limit=300):
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("ascii", "backslashreplace")
    else:
        text = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return text if len(text) <= limit else text[:limit] + "..."


def _text(value):
    return bytes(value).decode("ascii", "backslashreplace")


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
                item["evidence"] += "; %d operators in total" % count
        if self.capped:
            severity, cwe = _RULES["TFL005"]
            self.items.append({
                "rule": "TFL005", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


class _Buf(object):
    """Bounds-checked reads over bytes, a memoryview or an mmap."""

    def __init__(self, data):
        self.data = data
        self.n = len(data)

    def need(self, pos, size):
        if pos < 0 or size < 0 or pos + size > self.n:
            raise _Malformed("%d bytes at offset %d lie outside the %d-byte file"
                             % (size, pos, self.n))

    def read(self, fmt, pos):
        self.need(pos, struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.data, pos)[0]

    def deref(self, pos):
        return pos + self.read("<I", pos)

    def field(self, table, slot):
        """Absolute position of field `slot` of the table at `table`, or None."""
        vtable = table - self.read("<i", table)
        vsize = self.read("<H", vtable)
        tsize = self.read("<H", vtable + 2)
        if vsize < 4 or vsize % 2 or tsize < 4:
            raise _Malformed("vtable at offset %d is malformed" % vtable)
        self.need(vtable, vsize)
        self.need(table, tsize)
        entry = 4 + 2 * slot
        if entry >= vsize:
            return None
        offset = self.read("<H", vtable + entry)
        if not offset:
            return None
        if offset >= tsize:
            raise _Malformed("field %d of the table at offset %d is past its end"
                             % (slot, table))
        return table + offset

    def vector(self, pos, size):
        start = self.deref(pos)
        length = self.read("<I", start)
        self.need(start + 4, length * size)
        return start + 4, length


def _scalar(buf, table, slot, fmt, default):
    pos = buf.field(table, slot)
    return default if pos is None else buf.read(fmt, pos)


def _string(buf, table, slot):
    pos = buf.field(table, slot)
    if pos is None:
        return None
    start, length = buf.vector(pos, 1)
    return bytes(buf.data[start:start + length])


def _ints(buf, table, slot):
    pos = buf.field(table, slot)
    if pos is None:
        return []
    start, length = buf.vector(pos, 4)
    return list(struct.unpack_from("<%di" % length, buf.data, start))


def _tables(buf, table, slot):
    pos = buf.field(table, slot)
    if pos is None:
        return []
    start, length = buf.vector(pos, 4)
    return [buf.deref(start + 4 * i) for i in range(length)]


def _flex_uint(data, pos, width):
    if pos < 0 or pos + width > len(data):
        raise _Malformed("FlexBuffer read at %d is outside the %d-byte options"
                         % (pos, len(data)))
    return int.from_bytes(data[pos:pos + width], "little")


def _flex_string(data, pos, parent_width, packed):
    kind = packed >> 2
    target = pos - _flex_uint(data, pos, parent_width)
    if kind == _FBT_KEY:
        end = data.find(b"\0", max(target, 0))
        if target < 0 or end < 0:
            raise _Malformed("FlexBuffer key runs past the options")
        return data[target:end]
    if kind != _FBT_STRING:
        raise _Malformed("FlexBuffer element is type %d, not a string" % kind)
    width = 1 << (packed & 3)
    length = _flex_uint(data, target - width, width)
    if target + length > len(data):
        raise _Malformed("FlexBuffer string runs past the options")
    return data[target:target + length]


def _flex_pair(data):
    """Elements 0 and 1 of the FlexBuffer root vector, as the delegate reads."""
    if len(data) < 3:
        raise _Malformed("%d bytes of options; a FlexBuffer root needs 3"
                         % len(data))
    root_width = data[-1]
    if root_width not in (1, 2, 4, 8):
        raise _Malformed("FlexBuffer root width %d" % root_width)
    packed = data[-2]
    if packed >> 2 not in (_FBT_MAP, _FBT_VECTOR):
        raise _Malformed("FlexBuffer root is type %d, not a vector" % (packed >> 2))
    root = len(data) - 2 - root_width
    vector = root - _flex_uint(data, root, root_width)
    width = 1 << (packed & 3)
    size = _flex_uint(data, vector - width, width)
    if size < 2:
        raise _Malformed("FlexBuffer root vector has %d elements, not 2" % size)
    types = vector + size * width
    if types + 2 > len(data):
        raise _Malformed("FlexBuffer root vector runs past the options")
    return [_flex_string(data, vector + i * width, width, data[types + i])
            for i in range(2)]


def _varint(data, pos):
    value = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise _Malformed("NodeDef varint is truncated")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _nodedef_op(data):
    """NodeDef.op (field 2); the last occurrence wins, as in protobuf."""
    pos, op = 0, None
    while pos < len(data):
        key, pos = _varint(data, pos)
        field, wire = key >> 3, key & 7
        if not field:
            raise _Malformed("NodeDef has field number 0")
        if wire == 0:
            _, pos = _varint(data, pos)
        elif wire == 1:
            pos += 8
        elif wire == 5:
            pos += 4
        elif wire == 2:
            length, pos = _varint(data, pos)
            if pos + length > len(data):
                raise _Malformed("NodeDef field %d runs past its end" % field)
            if field == 2:
                op = data[pos:pos + length]
            pos += length
        else:
            raise _Malformed("NodeDef uses wire type %d" % wire)
        if pos > len(data):
            raise _Malformed("NodeDef is truncated")
    if not op:
        raise _Malformed("NodeDef has no op")
    return op


def _custom_options(buf, op):
    pos = buf.field(op, 5)
    if pos is not None:
        start, length = buf.vector(pos, 1)
        return bytes(buf.data[start:start + length])
    offset = _scalar(buf, op, 9, "<Q", 0)
    size = _scalar(buf, op, 10, "<Q", 0)
    if size:
        buf.need(offset, size)
        return bytes(buf.data[offset:offset + size])
    raise _Malformed("no custom options")


def _check_custom(buf, op, custom, where, out):
    label = _text(custom)
    if not custom.startswith(FLEX_PREFIX):
        out.add("TFL003", "custom operator %s has no built-in kernel; it runs "
                "only if the application registers native code under that name"
                % label, where, key=("TFL003", custom))
        return
    try:
        name, nodedef = _flex_pair(_custom_options(buf, op))
        op_name = _nodedef_op(nodedef)
    except _Malformed as exc:
        out.add("TFL005", "Flex operator %s: custom options do not decode to the "
                "op name and NodeDef the Flex delegate reads" % label,
                "%s: %s" % (where, exc))
        return
    mismatch = len({custom[len(FLEX_PREFIX):], name, op_name}) > 1
    if mismatch:
        out.add("TFL002", "Flex operator labels disagree; the Flex delegate takes "
                "the op from the custom options, not from custom_code",
                "%s: custom_code %s, options name %s, NodeDef op %s"
                % (where, label, _text(name), _text(op_name)))
    risky = [_text(n) for n in (op_name, name) if _text(n) in _RISKY_OPS]
    if risky:
        out.add("TFL001", "Flex operator runs TensorFlow op %s, which %s"
                % (risky[0], _RISKY_OPS[risky[0]]), where,
                key=("TFL001", risky[0]))
    elif not mismatch:
        out.add("TFL003", "Flex operator runs TensorFlow op %s through the full "
                "TensorFlow runtime (select TF ops)" % _text(op_name), where,
                key=("TFL003", custom))


def _scan_subgraph(buf, index, subgraph, codes, nbuffers, out):
    count = [0]
    examples = []

    def note(text):
        count[0] += 1
        if len(examples) < MAX_EXAMPLES:
            examples.append(text)

    def check(indices, what, ntensors):
        for value in indices:
            if value < -1 or value >= ntensors:
                note("%s: tensor index %d of %d" % (what, value, ntensors))

    try:
        tensors = _tables(buf, subgraph, 0)
        ntensors = len(tensors)
        for t, tensor in enumerate(tensors):
            buffer = _scalar(buf, tensor, 2, "<I", 0)
            if buffer and buffer >= nbuffers:
                note("tensor %d: buffer index %d of %d" % (t, buffer, nbuffers))
            for dim in _ints(buf, tensor, 0):
                if dim < -1:
                    note("tensor %d: shape dimension %d" % (t, dim))
                    break
        check(_ints(buf, subgraph, 1), "subgraph inputs", ntensors)
        check(_ints(buf, subgraph, 2), "subgraph outputs", ntensors)
        for o, op in enumerate(_tables(buf, subgraph, 3)):
            check(_ints(buf, op, 1), "operator %d inputs" % o, ntensors)
            check(_ints(buf, op, 2), "operator %d outputs" % o, ntensors)
            check(_ints(buf, op, 8), "operator %d intermediates" % o, ntensors)
            opcode = _scalar(buf, op, 0, "<I", 0)
            if opcode >= len(codes):
                note("operator %d: opcode_index %d of %d"
                     % (o, opcode, len(codes)))
                continue
            builtin, custom = codes[opcode]
            if builtin == BUILTIN_CUSTOM:
                _check_custom(buf, op, custom or b"",
                              "subgraph %d operator %d" % (index, o), out)
    finally:
        if count[0]:
            out.add("TFL004", "subgraph %d has %d out-of-range references or "
                    "invalid shapes" % (index, count[0]), "; ".join(examples))


def _scan_model(buf, out):
    if buf.n < 8:
        raise _Malformed("%d bytes; a FlatBuffer header needs 8" % buf.n)
    ident = bytes(buf.data[4:8])
    if ident != FILE_IDENTIFIER:
        raise _Malformed("file identifier is %r, not 'TFL3'" % ident)
    root = buf.deref(0)
    codes = []
    for table in _tables(buf, root, 1):
        deprecated = _scalar(buf, table, 0, "<b", 0)
        builtin = _scalar(buf, table, 3, "<i", 0)
        codes.append((max(deprecated, builtin), _string(buf, table, 1)))
    buffers = _tables(buf, root, 4)
    for i, table in enumerate(buffers):
        offset = _scalar(buf, table, 1, "<Q", 0)
        size = _scalar(buf, table, 2, "<Q", 0)
        if offset > 1 and size and offset + size > buf.n:
            out.add("TFL004", "buffer data lies outside the file",
                    "buffer %d: offset %d + size %d > file size %d"
                    % (i, offset, size, buf.n))
    for index, subgraph in enumerate(_tables(buf, root, 2)):
        _scan_subgraph(buf, index, subgraph, codes, len(buffers), out)


def _scan(data):
    out = _Findings()
    try:
        _scan_model(_Buf(data), out)
    except _Malformed as exc:
        out.add("TFL005", "not a well-formed TFLite FlatBuffer; findings before "
                "this point are kept", str(exc))
    except Exception as exc:  # hostile input must never crash the scan
        out.add("TFL005", "not a well-formed TFLite FlatBuffer; findings before "
                "this point are kept", "%s: %s" % (type(exc).__name__, exc))
    return out.result()


def scan_bytes(data, name=""):
    """Scan an in-memory .tflite file. Returns a list of finding dicts."""
    return _scan(data)


def scan_file(path):
    """Scan a .tflite file on disk, memory-mapped when possible."""
    with open(path, "rb") as handle:
        try:
            view = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            return _scan(handle.read())
        try:
            return _scan(view)
        finally:
            view.close()


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] in ("-h", "--help"):
        print("usage: python tflite_model_scan.py MODEL.tflite [...]",
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
