#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Self-contained tests for r_serialized_scan. Standard library only.

Items are built as token lists, then written in R's XDR, native binary or
ascii format, so every case can be checked in each of them.
"""

import bz2
import gzip
import lzma
import os
import shutil
import struct
import tempfile
import unittest

import r_serialized_scan as rs


def _i(n):
    return [("i", n)]


def _fl(kind, attr=False, tag=False, levels=0):
    return _i(kind | (attr << 9) | (tag << 10) | (levels << 12))


NIL = _i(254)
GLOBAL = _i(253)
UNBOUND = _i(252)
MISSING = _i(251)


def _chr(text):
    raw = text.encode("utf-8")
    return _fl(9, levels=64) + _i(len(raw)) + [("s", raw)]


def _sym(name):
    return _fl(1) + _chr(name)


def _ref(index):
    return _i((index << 8) | 255)


def _str(*texts):
    return _fl(16) + _i(len(texts)) + sum((_chr(t) for t in texts), [])


def _ints(*values):
    return _fl(13) + _i(len(values)) + [("i", v) for v in values]


def _reals(*values):
    return _fl(14) + _i(len(values)) + [("d", v) for v in values]


def _vec(*items):
    return _fl(19) + _i(len(items)) + sum(items, [])


def _call(head, *args):
    out = _fl(6) + head
    for arg in args:
        out += _fl(2) + arg
    return out + NIL


def _plain(*items):
    out = []
    for item in items:
        out += _fl(2) + item
    return out + NIL


def _pairs(*pairs):
    out = []
    for name, value in pairs:
        out += _fl(2, tag=True) + _sym(name) + value
    return out + NIL


def _closure(formals, body, env=GLOBAL):
    return _fl(3, tag=True) + env + formals + body


def _promise(value, code, env=GLOBAL):
    if env is None:                      # an evaluated promise has no env
        return _fl(5) + value + code
    return _fl(5, tag=True) + env + value + code


def _env(frame, enclos=GLOBAL):
    return _fl(4) + _i(0) + enclos + frame + NIL + NIL


def _namespace(*names):
    return _i(249) + _i(0) + _i(len(names)) + sum((_chr(n) for n in names), [])


def _altrep(cls, pkg):
    info = _plain(_sym(cls), _sym(pkg), _ints(13))
    return _i(238) + info + _reals(10.0, 1.0, 1.0) + NIL


def _bc_call(head, *args):
    # ReadBCLang: type, tag item, CAR, CDR; a non-cell is a 0 pad + item.
    out = _i(6) + NIL + _i(0) + head
    for arg in args:
        out += _i(2) + NIL + _i(0) + arg
    return out + _i(0) + NIL


def _bytecode(*consts):
    # BCODESXP: shared-cell table size, instructions, constants.
    return _fl(21) + _i(0) + _ints(12, 1) + _i(len(consts)) + sum(consts, [])


_NAMED = {10: b"\\n", 9: b"\\t", 11: b"\\v", 8: b"\\b", 13: b"\\r",
          12: b"\\f", 7: b"\\a", 92: b"\\\\", 63: b"\\?", 39: b"\\'",
          34: b'\\"'}


def _escape(raw):
    out = bytearray()
    for c in raw:
        if c in _NAMED:
            out += _NAMED[c]
        elif c <= 32 or c > 126:
            out += b"\\%03o" % c
        else:
            out.append(c)
    return bytes(out)


def _encode(tokens, fmt):
    order = ">" if fmt == "X" else "<"
    out = bytearray()
    for kind, value in tokens:
        if fmt == "A":
            if kind == "i":
                out += b"%d\n" % value
            elif kind == "d":
                out += ("%.16g\n" % value).encode("ascii")
            else:
                out += _escape(value) + b"\n"
        elif kind == "i":
            out += struct.pack(order + "i", value)
        elif kind == "d":
            out += struct.pack(order + "d", value)
        else:
            out += value
    return bytes(out)


def _rds(item, fmt="X", workspace=b""):
    head = _i(3) + _i(263425) + _i(197888) + _i(5) + [("s", b"UTF-8")]
    return workspace + fmt.encode("ascii") + b"\n" + _encode(head + item, fmt)


def _rules(findings):
    return [f["rule"] for f in findings]


def _scan(item, fmt="X"):
    return rs.scan_bytes(_rds(item, fmt))


def _system_closure():
    return _closure(_pairs(("cmd", MISSING)),
                    _call(_sym("system"), _sym("cmd")))


def _data_frame():
    return (_fl(19, attr=True) + _i(2) + _reals(1.5, 2.0) + _str("a", "b")
            + _pairs(("names", _str("x", "s")),
                     ("class", _str("data.frame")),
                     ("row.names", _ints(-2147483648, -2))))


class RSerializedScanTests(unittest.TestCase):

    def test_version(self):
        self.assertEqual(rs.__version__, "0.1.0")

    def test_data_frame_is_clean_in_every_format(self):
        for fmt in ("X", "B", "A"):
            self.assertEqual(_scan(_data_frame(), fmt), [], fmt)

    def test_model_language_objects_are_clean(self):
        # Reference table: 1 lm, 2 ~, 3 y, 4 x, 5 list, 6 mu, 7 .Call.
        formula = _call(_sym("~"), _sym("y"), _sym("x"))
        model = _vec(_call(_sym("lm"), formula),
                     _call(_sym("list"), _ref(3), _ref(4)),
                     _closure(_pairs(("mu", MISSING)),
                              _call(_sym(".Call"), _sym("C_logit_link"),
                                    _ref(6))))
        self.assertEqual(_scan(model), [])

    def test_closure_calling_system_is_rds002(self):
        findings = _scan(_system_closure())
        self.assertEqual(_rules(findings), ["RDS002"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("calls system()", findings[0]["evidence"])
        self.assertIn("> function", findings[0]["evidence"])

    def test_every_format_and_compression(self):
        item = _system_closure()
        blobs = [_rds(item, fmt) for fmt in ("X", "B", "A")]
        plain = _rds(item)
        blobs += [gzip.compress(plain), bz2.compress(plain),
                  lzma.compress(plain)]
        for blob in blobs:
            self.assertEqual(_rules(rs.scan_bytes(blob)), ["RDS002"], blob[:8])

    def test_rdata_workspace(self):
        frame = _pairs(("df", _data_frame()), ("f", _system_closure()))
        for fmt, head in (("X", b"RDX3\n"), ("A", b"RDA3\n"), ("B", b"RDB3\n")):
            findings = rs.scan_bytes(gzip.compress(_rds(frame, fmt, head)))
            self.assertEqual(_rules(findings), ["RDS002"], fmt)
            self.assertIn("object$f > function", findings[0]["evidence"])

    def test_ascii_escapes_keep_the_stream_in_step(self):
        item = _vec(_str("a b\t\"c\\dé?\n"), _sym("x y"),
                    _call(_sym("system"), _str("id")))
        self.assertEqual(_rules(_scan(item, "A")), ["RDS002"])

    def test_unevaluated_promise_with_call_is_rds001(self):
        frame = _pairs(("x", _promise(UNBOUND, _call(_sym("Sys.time")))))
        findings = _scan(_env(frame))
        self.assertEqual(_rules(findings), ["RDS001"])
        self.assertIn("env$x: promise calls Sys.time()",
                      findings[0]["evidence"])

    def test_promise_calling_system_is_rds001_and_rds002(self):
        frame = _pairs(("x", _promise(UNBOUND,
                                      _call(_sym("system"), _str("id")))))
        self.assertEqual(sorted(_rules(_scan(_env(frame)))),
                         ["RDS001", "RDS002"])

    def test_evaluated_and_constant_promises_are_clean(self):
        # binomial() leaves its default link as a promise of "logit".
        frame = _pairs(
            ("link", _promise(UNBOUND, _str("logit"))),
            ("done", _promise(_str("logit"),
                              _call(_sym("make.link"), _str("logit")),
                              env=None)),
            ("sym", _promise(UNBOUND, _sym("link"))))
        self.assertEqual(_scan(_env(frame)), [])

    def test_active_binding_is_rds001(self):
        cell = (_fl(2, tag=True, levels=1 << 15) + _sym("x")
                + _closure(NIL, _call(_sym("Sys.time"))))
        findings = _scan(_env(cell + NIL))
        self.assertEqual(_rules(findings), ["RDS001"])
        self.assertIn("env$x: active binding", findings[0]["evidence"])

    def test_locked_binding_is_clean(self):
        cell = _fl(2, tag=True, levels=1 << 14) + _sym("x") + _ints(1)
        self.assertEqual(_scan(_env(cell + NIL)), [])

    def test_symbol_reference_names_the_call(self):
        item = _vec(_sym("system"), _call(_ref(1), _str("id")))
        findings = _scan(item)
        self.assertEqual(_rules(findings), ["RDS002"])
        self.assertIn("system()", findings[0]["evidence"])

    def test_qualified_and_indirect_calls(self):
        cases = (
            (_call(_call(_sym("::"), _sym("base"), _sym("system")),
                   _str("id")), "calls system()"),
            (_call(_sym("do.call"), _str("system"),
                   _call(_sym("list"), _str("id"))),
             "calls system() through do.call()"),
            (_call(_sym("get"), _sym("eval")), "calls eval() through get()"),
        )
        for item, needle in cases:
            findings = _scan(item)
            self.assertEqual(_rules(findings), ["RDS002"], needle)
            self.assertIn(needle, findings[0]["evidence"])

    def test_benign_indirect_calls_are_clean(self):
        item = _vec(_call(_sym("do.call"), _str("rbind"), _sym("parts")),
                    _call(_sym("get"), _str("mean")),
                    _call(_sym("match.fun"), _sym("FUN")))
        self.assertEqual(_scan(item), [])

    def test_bytecode_body_is_checked(self):
        body = _bytecode(_bc_call(_sym("system"), _str("id")))
        findings = _scan(_closure(_pairs(("cmd", MISSING)), body))
        self.assertEqual(_rules(findings), ["RDS002"])
        self.assertIn("> function: calls system()", findings[0]["evidence"])

    def test_benign_bytecode_with_nested_constants_is_clean(self):
        # A constant is its type, then the full item (ReadBCConsts).
        inner = _i(21) + _ints(12) + _i(1) + _i(14) + _reals(1.0)
        body = _bytecode(_bc_call(_sym("+"), _sym("x"), _reals(1.0)),
                         inner, _i(13) + _ints(4),
                         _i(244) + _i(0) + _i(6) + NIL + _i(0) + _sym("f")
                         + _i(0) + NIL,
                         _i(243) + _i(0))
        self.assertEqual(_scan(_closure(_pairs(("x", MISSING)), body)), [])

    def test_promise_with_bytecode_is_rds001(self):
        frame = _pairs(("x", _promise(UNBOUND,
                                      _bytecode(_i(14) + _reals(1.0)))))
        findings = _scan(_env(frame))
        self.assertEqual(_rules(findings), ["RDS001"])
        self.assertIn("byte-compiled", findings[0]["evidence"])

    def test_same_call_reported_once_with_count(self):
        body = _call(_sym("{"), _call(_sym("system"), _str("a")),
                     _call(_sym("system"), _str("b")))
        findings = _scan(_closure(NIL, body))
        self.assertEqual(_rules(findings), ["RDS002"])
        self.assertIn("2 in total", findings[0]["evidence"])

    def test_altrep_and_namespaces(self):
        self.assertEqual(_scan(_altrep("compact_intseq", "base")), [])
        self.assertEqual(_scan(_env(NIL, enclos=_namespace("stats",
                                                           "4.5.1"))), [])
        findings = _scan(_altrep("vroom_dbl", "vroom"))
        self.assertEqual(_rules(findings), ["RDS003"])
        self.assertIn("class vroom_dbl from package vroom",
                      findings[0]["evidence"])
        findings = _scan(_env(NIL, enclos=_namespace("evilpkg", "1.0")))
        self.assertEqual(_rules(findings), ["RDS003"])
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("namespace evilpkg 1.0", findings[0]["evidence"])

    def test_namespace_reference_counts_once(self):
        ns = _namespace("rpart", "4.1.24")
        item = _vec(_env(NIL, enclos=ns), _env(NIL, enclos=_ref(2)))
        findings = _scan(item)
        self.assertEqual(_rules(findings), ["RDS003"])

    def test_persistent_reference_is_rds003(self):
        self.assertEqual(_rules(_scan(_i(247) + _i(0) + _i(1)
                                      + _chr("key1"))), ["RDS003"])

    def test_long_pairlist_is_read_without_recursion(self):
        frame = _pairs(*[("v%d" % n, _ints(n)) for n in range(5000)])
        self.assertEqual(_scan(_env(frame)), [])

    def test_not_r_or_broken_is_rds004(self):
        good = _rds(_system_closure())
        cases = [b"", b"hello world", good[:-3], good[:9],
                 b"X\n" + _encode(_i(4), "X"),
                 _rds(_i(30)), _rds(_ref(7)), _rds(_i(246)),
                 b"\x28\xb5\x2f\xfd" + b"\x00" * 8,
                 b"\x1f\x8bjunk", b"BZhjunk",
                 _rds(_i(238) + _ints(1) + NIL + NIL)]
        for raw in cases:
            findings = rs.scan_bytes(raw)
            self.assertIn("RDS004", _rules(findings), raw[:12])
            for f in findings:
                self.assertNotIn("could not be parsed", f["message"], raw[:12])

    def test_deep_nesting_stops_with_rds004(self):
        item = _fl(19) + _i(1)
        item = item * 300 + NIL
        findings = _scan(item)
        self.assertEqual(_rules(findings), ["RDS004"])
        self.assertIn("nesting deeper", findings[0]["evidence"])

    def test_output_is_ascii_with_fixed_keys(self):
        findings = _scan(_env(NIL, enclos=_namespace("pké", "1")))
        self.assertTrue(findings)
        for f in findings:
            self.assertEqual(set(f), {"rule", "severity", "cve", "cwe",
                                      "message", "evidence"})
            self.assertTrue(all(ord(c) < 128 for c in f["message"]))
            self.assertTrue(all(ord(c) < 128 for c in f["evidence"]))

    def test_scan_file_and_main_exit_codes(self):
        root = tempfile.mkdtemp()
        try:
            clean = os.path.join(root, "clean.rds")
            with open(clean, "wb") as handle:
                handle.write(gzip.compress(_rds(_data_frame())))
            bad = os.path.join(root, "bad.rds")
            with open(bad, "wb") as handle:
                handle.write(gzip.compress(_rds(_system_closure())))
            ns = os.path.join(root, "ns.rds")
            with open(ns, "wb") as handle:
                handle.write(_rds(_env(NIL, enclos=_namespace("x", "1"))))
            self.assertEqual(rs.scan_file(clean), [])
            findings = rs.scan_file(bad)
            self.assertEqual(_rules(findings), ["RDS002"])
            self.assertIn("bad.rds > function", findings[0]["evidence"])
            self.assertEqual(rs.main([clean]), 0)
            self.assertEqual(rs.main([bad]), 1)
            self.assertEqual(rs.main([ns]), 0)
            self.assertEqual(rs.main([os.path.join(root, "nope.rds")]), 2)
            self.assertEqual(rs.main([]), 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
