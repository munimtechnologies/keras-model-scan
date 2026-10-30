#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""executorch_pte_scan - static scanner for ExecuTorch .pte program files.

Part of the open-source keras-model-scan toolkit. Made with AI agents working
in the name of MV2 of Munim, Inc. Apache-2.0.

A .pte file is a FlatBuffer (identifier ``ET12``, schema/program.fbs). When
the program has data segments, an ``eh00`` extended header at offset 8 gives
the program size and where the segment data starts; constant weights,
mutable initial state, named data and backend delegate blobs then live in
those segments. The runtime trusts the sizes, offsets and indexes it reads:
ExecuTorch fixed a series of loader memory-safety bugs on malformed programs
in 0.7.0 (CVE-2025-30402, -30404, -30405, -54949, -54950, -54951, -54952).

This module parses the FlatBuffer itself (no ``executorch`` or
``flatbuffers`` import), recomputes every tensor's byte size the way the
runtime does, and checks each reference against the region it points into:

- PTE001 high   CWE-190  Sizes that are negative or overflow: a tensor
                         dimension below 0, a tensor of 2**63 bytes or more,
                         a negative planned-buffer size, or segment
                         arithmetic past 64 bits.
- PTE002 high   CWE-125  Data references outside their region: a segment
                         past the segment data, segment data inside the
                         program, a constant or mutable tensor past its
                         segment or buffer, or a planned tensor past its
                         memory-planned buffer.
- PTE003 medium CWE-829  Backend delegates: an ahead-of-time compiled blob
                         that the named backend's native code parses at load
                         and this scanner cannot read inside.
- PTE004 medium CWE-129  Out-of-range indexes: operator, delegate, value,
                         instruction, segment, memory_id, data_buffer_idx,
                         dtype or delegate data index past its table.
- PTE005 medium CWE-693  Not a well-formed ET12 program, a file shorter
                         than its extended header says, segments without a
                         segment base offset, or findings capped.

Static review only: nothing is loaded or executed.
"""

import mmap
import struct
import sys

__version__ = "0.1.0"

FILE_IDENTIFIER = b"ET12"
HEADER_MAGIC = b"eh00"
HEADER_MIN_LENGTH = 24
MAX_FINDINGS = 1000
MAX_EXAMPLES = 3

_U64 = 1 << 64
_I64 = 1 << 63

_RULES = {
    "PTE001": ("high", "CWE-190"),
    "PTE002": ("high", "CWE-125"),
    "PTE003": ("medium", "CWE-829"),
    "PTE004": ("medium", "CWE-129"),
    "PTE005": ("medium", "CWE-693"),
}

_TALLY = {
    "PTE001": "sizes that are negative or overflow 64-bit arithmetic: %d",
    "PTE002": "data references that point outside their region: %d",
    "PTE004": "indexes that are out of range: %d",
}

# Element sizes by ScalarType (schema/scalar_type.fbs).
_ELEMENT_SIZE = {0: 1, 1: 1, 2: 2, 3: 4, 4: 8, 5: 2, 6: 4, 7: 8, 11: 1, 12: 1,
                 13: 1, 14: 4, 15: 2, 16: 1, 17: 1, 22: 2, 23: 1, 24: 1, 25: 1,
                 26: 1, 27: 2, 28: 4, 29: 8}

# Union type tags; FlatBuffers numbers union members from 1 (0 is NONE).
_TENSOR = 5
_TENSOR_LIST = 10
_OPTIONAL_TENSOR_LIST = 11
_KERNEL_CALL = 1
_DELEGATE_CALL = 2
_MOVE_CALL = 3
_JUMP_FALSE_CALL = 4
_FREE_CALL = 5

# DataLocation and TensorDataLocation.
_INLINE = 0
_SEGMENT = 1
_EXTERNAL = 1


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
        """Count one PTE001/PTE002/PTE004 problem; each rule reports once."""
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
            severity, cwe = _RULES["PTE005"]
            self.items.append({
                "rule": "PTE005", "severity": severity, "cve": "", "cwe": cwe,
                "message": "more than %d findings; the rest are not listed"
                           % MAX_FINDINGS,
                "evidence": ""})
        return self.items


class _Buf(object):
    """Bounds-checked reads over the first `size` bytes of `data`."""

    def __init__(self, data, size=None):
        self.data = data
        self.n = len(data) if size is None else min(size, len(data))

    def need(self, pos, size):
        if pos < 0 or size < 0 or pos + size > self.n:
            raise _Malformed("%d bytes at offset %d lie outside the %d-byte "
                             "program" % (size, pos, self.n))

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


def _vector(buf, table, slot, code):
    """A vector of scalars (struct code such as "i" or "Q"), [] when absent."""
    pos = buf.field(table, slot)
    if pos is None:
        return []
    start, length = buf.vector(pos, struct.calcsize("<" + code))
    return list(struct.unpack_from("<%d%s" % (length, code), buf.data, start))


def _length(buf, table, slot, size):
    pos = buf.field(table, slot)
    return 0 if pos is None else buf.vector(pos, size)[1]


def _table(buf, table, slot):
    pos = buf.field(table, slot)
    return None if pos is None else buf.deref(pos)


def _tables(buf, table, slot):
    pos = buf.field(table, slot)
    if pos is None:
        return []
    start, length = buf.vector(pos, 4)
    return [buf.deref(start + 4 * i) for i in range(length)]


def _header(buf):
    """(program_size, segment_base_offset, segment_data_size), or None."""
    if buf.n < 16 or bytes(buf.data[8:12]) != HEADER_MAGIC:
        return None
    length = buf.read("<I", 12)
    if length < HEADER_MIN_LENGTH:
        raise _Malformed("extended header length %d is below %d"
                         % (length, HEADER_MIN_LENGTH))
    program_size = buf.read("<Q", 16)
    base = buf.read("<Q", 24)
    data_size = buf.read("<Q", 32) if length >= 32 else 0
    return program_size, base, data_size


class _Program(object):

    def __init__(self, buf, out):
        self.buf = buf
        self.out = out
        self.segments = []
        self.constant = None
        self.constant_buffer = []
        self.mutable = []
        self.inline = []

    def indexes(self, values, n, what, low=0):
        for value in values:
            if value < low or value >= n:
                self.out.note("PTE004", "%s: index %d of %d" % (what, value, n))

    def subsegment(self, table, what):
        """(offsets, segment size or None) of a SubsegmentOffsets table."""
        buf = self.buf
        index = _scalar(buf, table, 0, "<I", 0)
        offsets = _vector(buf, table, 1, "Q")
        if index >= len(self.segments):
            self.out.note("PTE004", "%s: segment_index %d of %d"
                          % (what, index, len(self.segments)))
            return offsets, None
        size = self.segments[index][1]
        for i, offset in enumerate(offsets):
            if offset > size:
                self.out.note("PTE002", "%s: offset[%d] %d is past the %d-byte "
                              "segment %d" % (what, i, offset, size, index))
        return offsets, size

    def data(self, index, nbytes, sub, what, where):
        if sub is None:
            self.out.note("PTE004", "%s: data_buffer_idx %d but the program has "
                          "no %s" % (where, index, what))
            return
        offsets, size = sub
        if index >= len(offsets):
            self.out.note("PTE004", "%s: data_buffer_idx %d of %d %s offsets"
                          % (where, index, len(offsets), what))
        elif size is not None and offsets[index] + nbytes > size:
            self.out.note("PTE002", "%s: %d bytes at offset %d of the %d-byte "
                          "%s segment" % (where, nbytes, offsets[index], size,
                                          what))

    def tensor(self, table, sizes, where):
        buf, out = self.buf, self.out
        dtype = _scalar(buf, table, 0, "<b", 0)
        dims = _vector(buf, table, 2, "i")
        index = _scalar(buf, table, 5, "<I", 0)
        alloc = _table(buf, table, 6)
        extra = _table(buf, table, 9)
        external = (extra is not None
                    and _scalar(buf, extra, 2, "<b", 0) == _EXTERNAL)
        element = _ELEMENT_SIZE.get(dtype)
        if element is None:
            out.note("PTE004", "%s: scalar_type %d is not an ExecuTorch dtype"
                     % (where, dtype))
            return
        nbytes = element
        for dim in dims:
            if dim < 0:
                out.note("PTE001", "%s: dimension %d" % (where, dim))
                return
            nbytes *= dim
            if nbytes >= _I64:
                out.note("PTE001", "%s: dimensions %s of a %d-byte dtype need "
                         "2**63 bytes or more" % (where, dims[:8], element))
                return
        if alloc is not None:
            memory_id = _scalar(buf, alloc, 0, "<I", 0)
            offset = (_scalar(buf, alloc, 1, "<I", 0)
                      | _scalar(buf, alloc, 2, "<I", 0) << 32)
            if memory_id < 1 or memory_id >= len(sizes):
                out.note("PTE004", "%s: memory_id %d; non_const_buffer_sizes has "
                         "%d entries and entry 0 is reserved"
                         % (where, memory_id, len(sizes)))
            elif sizes[memory_id] >= 0 and offset + nbytes > sizes[memory_id]:
                out.note("PTE002", "%s: %d bytes at offset %d of planned buffer "
                         "%d (%d bytes)" % (where, nbytes, offset, memory_id,
                                            sizes[memory_id]))
            if index and not external:
                mutable = self.mutable[0] if self.mutable else None
                self.data(index, nbytes, mutable, "mutable_data_segments[0]",
                          where)
        elif index and not external:
            if self.constant is not None:
                self.data(index, nbytes, self.constant, "constant_segment", where)
            elif index >= len(self.constant_buffer):
                out.note("PTE004", "%s: data_buffer_idx %d of %d constant buffers"
                         % (where, index, len(self.constant_buffer)))
            elif nbytes > self.constant_buffer[index]:
                out.note("PTE002", "%s: %d bytes from the %d-byte constant buffer "
                         "%d" % (where, nbytes, self.constant_buffer[index],
                                 index))

    def delegates(self, p, tables):
        buf, out = self.buf, self.out
        for d, delegate in enumerate(tables):
            where = "plan %d delegate %d" % (p, d)
            name = _string(buf, delegate, 0) or b""
            ref = _table(buf, delegate, 1)
            specs = _length(buf, delegate, 2, 4)
            blob = "no readable blob"
            if ref is None:
                out.note("PTE004", "%s: no processed data reference" % where)
            else:
                location = _scalar(buf, ref, 0, "<b", 0)
                index = _scalar(buf, ref, 1, "<I", 0)
                if location == _INLINE:
                    pool, kind = self.inline, "inline blob"
                elif location == _SEGMENT:
                    pool, kind = [s[1] for s in self.segments], "segment"
                else:
                    pool, kind = None, None
                    out.note("PTE004", "%s: data location %d" % (where, location))
                if pool is not None and index >= len(pool):
                    out.note("PTE004", "%s: %s index %d of %d"
                             % (where, kind, index, len(pool)))
                elif pool is not None:
                    blob = "%s %d, %d bytes" % (kind, index, pool[index])
            out.add("PTE003", "backend delegate %s: that backend's native code "
                    "parses an ahead-of-time compiled blob at load; this scanner "
                    "cannot read inside it" % _text(name),
                    "%s: %s, %d compile specs" % (where, blob, specs),
                    key=("PTE003", name))
        return len(tables)

    def chain(self, where, chain, nvalues, nops, ndelegates):
        buf = self.buf
        self.indexes(_vector(buf, chain, 0, "i"), nvalues, where + " inputs")
        self.indexes(_vector(buf, chain, 1, "i"), nvalues, where + " outputs")
        instructions = _tables(buf, chain, 2)
        for i, instruction in enumerate(instructions):
            at = "%s instruction %d" % (where, i)
            kind = _scalar(buf, instruction, 0, "<B", 0)
            args = _table(buf, instruction, 1)
            if args is None or not _KERNEL_CALL <= kind <= _FREE_CALL:
                self.out.note("PTE004", "%s: instruction type %d" % (at, kind))
                continue
            first = _scalar(buf, args, 0, "<i", 0)
            if kind == _KERNEL_CALL:
                self.indexes([first], nops, at + " op_index")
                self.indexes(_vector(buf, args, 1, "i"), nvalues, at + " args")
            elif kind == _DELEGATE_CALL:
                self.indexes([first], ndelegates, at + " delegate_index")
                self.indexes(_vector(buf, args, 1, "i"), nvalues, at + " args")
            elif kind == _MOVE_CALL:
                self.indexes([first, _scalar(buf, args, 1, "<i", 0)], nvalues,
                             at + " move")
            elif kind == _JUMP_FALSE_CALL:
                self.indexes([first], nvalues, at + " cond_value_index")
                self.indexes([_scalar(buf, args, 1, "<i", 0)],
                             len(instructions) + 1,
                             at + " destination_instruction")
            else:
                self.indexes([first], nvalues, at + " value_index")

    def plan(self, p, plan):
        buf, out = self.buf, self.out
        where = "plan %d" % p
        values = _tables(buf, plan, 2)
        nvalues = len(values)
        sizes = _vector(buf, plan, 8, "q")
        for i, size in enumerate(sizes):
            if size < 0:
                out.note("PTE001", "%s: non_const_buffer_sizes[%d] is %d"
                         % (where, i, size))
        self.indexes(_vector(buf, plan, 3, "i"), nvalues, where + " inputs")
        self.indexes(_vector(buf, plan, 4, "i"), nvalues, where + " outputs")
        for v, value in enumerate(values):
            kind = _scalar(buf, value, 0, "<B", 0)
            table = _table(buf, value, 1)
            if table is None:
                continue
            at = "%s value %d" % (where, v)
            if kind == _TENSOR:
                self.tensor(table, sizes, at)
            elif kind == _TENSOR_LIST:
                self.indexes(_vector(buf, table, 0, "i"), nvalues, at + " items")
            elif kind == _OPTIONAL_TENSOR_LIST:
                self.indexes(_vector(buf, table, 0, "i"), nvalues, at + " items",
                             low=-1)
        ndelegates = self.delegates(p, _tables(buf, plan, 7))
        nops = _length(buf, plan, 6, 4)
        for c, chain in enumerate(_tables(buf, plan, 5)):
            self.chain("%s chain %d" % (where, c), chain, nvalues, nops,
                       ndelegates)

    def scan(self, root, region):
        buf, out = self.buf, self.out
        for table in _tables(buf, root, 4):
            self.segments.append((_scalar(buf, table, 0, "<Q", 0),
                                  _scalar(buf, table, 1, "<Q", 0)))
        if self.segments and region is None:
            out.add("PTE005", "the program lists data segments but no extended "
                    "header gives a segment base offset",
                    "%d segments" % len(self.segments))
        elif region is not None:
            base, end = region
            for i, (offset, size) in enumerate(self.segments):
                stop = base + offset + size
                if stop >= _U64:
                    out.note("PTE001", "segment %d: base %d + offset %d + size "
                             "%d overflows 64 bits" % (i, base, offset, size))
                elif stop > end:
                    out.note("PTE002", "segment %d: bytes %d to %d, segment data "
                             "ends at %d" % (i, base + offset, stop, end))
        self.constant_buffer = [_length(buf, table, 0, 1)
                                for table in _tables(buf, root, 2)]
        self.inline = [_length(buf, table, 0, 1)
                       for table in _tables(buf, root, 3)]
        constant = _table(buf, root, 5)
        if constant is not None and len(_vector(buf, constant, 1, "Q")) > 1:
            self.constant = self.subsegment(constant, "constant_segment")
        for i, table in enumerate(_tables(buf, root, 6)):
            self.mutable.append(self.subsegment(
                table, "mutable_data_segments[%d]" % i))
        for i, table in enumerate(_tables(buf, root, 7)):
            index = _scalar(buf, table, 1, "<I", 0)
            if index >= len(self.segments):
                out.note("PTE004", "named_data[%d] %s: segment_index %d of %d"
                         % (i, _text(_string(buf, table, 0) or b""), index,
                            len(self.segments)))
        for p, plan in enumerate(_tables(buf, root, 1)):
            self.plan(p, plan)


def _scan_program(data, out):
    whole = _Buf(data)
    if whole.n < 8:
        raise _Malformed("%d bytes; a FlatBuffer header needs 8" % whole.n)
    ident = bytes(data[4:8])
    if ident != FILE_IDENTIFIER:
        raise _Malformed("file identifier is %r, not 'ET12'" % ident)
    header = _header(whole)
    buf, region = whole, None
    if header is not None:
        program_size, base, data_size = header
        if program_size < 16:
            raise _Malformed("extended header program_size %d is too small"
                             % program_size)
        if max(program_size, base + data_size) > whole.n:
            out.add("PTE005", "the file is shorter than its extended header "
                    "says; it may be truncated",
                    "program_size %d, segment_base_offset %d, segment_data_size "
                    "%d, file size %d" % (program_size, base, data_size, whole.n))
        if base + data_size >= _U64:
            out.note("PTE001", "segment_base_offset %d + segment_data_size %d "
                     "overflows 64 bits" % (base, data_size))
        if base:
            if base < program_size:
                out.note("PTE002", "segment_base_offset %d lies inside the "
                         "%d-byte program" % (base, program_size))
            region = (base, base + data_size if data_size else whole.n)
        buf = _Buf(data, program_size)
    root = buf.deref(0)
    if root < 8:
        raise _Malformed("root table offset %d is inside the file header" % root)
    _Program(buf, out).scan(root, region)


def _scan(data):
    out = _Findings()
    try:
        _scan_program(data, out)
    except _Malformed as exc:
        out.add("PTE005", "not a well-formed ExecuTorch program; findings before "
                "this point are kept", str(exc))
    except Exception as exc:  # hostile input must never crash the scan
        out.add("PTE005", "not a well-formed ExecuTorch program; findings before "
                "this point are kept", "%s: %s" % (type(exc).__name__, exc))
    return out.result()


def scan_bytes(data, name=""):
    """Scan an in-memory .pte file. Returns a list of finding dicts."""
    return _scan(data)


def scan_file(path):
    """Scan a .pte file on disk, memory-mapped when possible."""
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
        print("usage: python executorch_pte_scan.py PROGRAM.pte [...]",
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
