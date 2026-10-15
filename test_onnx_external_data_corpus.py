"""Tests for onnx_external_data_corpus.

These tests import only the new module and the standard library. They decode the
generated protobufs with an INDEPENDENT minimal reader (not the module's encoders),
so a passing test proves each crafted .onnx file is well-formed AND carries the
intended malicious ``location`` string back out again.

Made with AI by MV2 of Munim, Inc. Licensed under the Apache License, Version 2.0.
"""

import json
import os
import tempfile
import unittest

import onnx_external_data_corpus as corp


# --- independent protobuf wire reader (does not use the module's helpers) --------
def _read_varint(data, i):
    shift = 0
    result = 0
    while True:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7


def _iter_fields(data):
    i = 0
    n = len(data)
    while i < n:
        tag, i = _read_varint(data, i)
        field_no = tag >> 3
        wire = tag & 7
        if wire == 0:
            val, i = _read_varint(data, i)
            yield field_no, wire, val
        elif wire == 2:
            ln, i = _read_varint(data, i)
            yield field_no, wire, data[i:i + ln]
            i += ln
        elif wire == 5:
            yield field_no, wire, data[i:i + 4]
            i += 4
        elif wire == 1:
            yield field_no, wire, data[i:i + 8]
            i += 8
        else:
            raise ValueError("unexpected wire type %d" % wire)


def _extract_locations(model_bytes):
    """Pull out every external_data 'location' value, independently of the module."""
    locs = []
    for f, w, v in _iter_fields(model_bytes):
        if f == 7 and w == 2:  # ModelProto.graph
            for gf, gw, gv in _iter_fields(v):
                if gf == 5 and gw == 2:  # GraphProto.initializer
                    _collect_tensor_locations(gv, locs)
    return locs


def _collect_tensor_locations(tensor_bytes, locs):
    data_location = None
    entries = []
    for tf, tw, tv in _iter_fields(tensor_bytes):
        if tf == 14 and tw == 0:  # data_location
            data_location = tv
        elif tf == 13 and tw == 2:  # external_data entry
            key = value = None
            for ef, ew, ev in _iter_fields(tv):
                if ef == 1 and ew == 2:
                    key = ev.decode("utf-8", "surrogatepass")
                elif ef == 2 and ew == 2:
                    value = ev.decode("utf-8", "surrogatepass")
            entries.append((key, value))
    if data_location == 1:  # EXTERNAL
        for key, value in entries:
            if key == "location" and value is not None:
                locs.append(value)


class TestBuildModel(unittest.TestCase):
    def test_roundtrip_every_case(self):
        for c in corp.CASES:
            model = corp.build_model(c.location)
            locs = _extract_locations(model)
            self.assertEqual(locs, [c.location],
                             "location did not round-trip for case %s" % c.name)

    def test_build_corpus_keys(self):
        corpus = corp.build_corpus()
        self.assertEqual(len(corpus), len(corp.CASES))
        for c in corp.CASES:
            self.assertIn(c.filename, corpus)
            self.assertTrue(corpus[c.filename], "empty model for %s" % c.name)

    def test_nul_and_control_bytes_survive(self):
        # NUL and control bytes must be preserved exactly in the location field.
        nul = [c for c in corp.CASES if c.name == "nul_byte"][0]
        self.assertIn("\x00", _extract_locations(corp.build_model(nul.location))[0])
        ctrl = [c for c in corp.CASES if c.name == "control_byte"][0]
        self.assertIn("\x07", _extract_locations(corp.build_model(ctrl.location))[0])


class TestCaseConsistency(unittest.TestCase):
    def test_exactly_one_clean_control(self):
        clean = [c for c in corp.CASES if not c.malicious]
        self.assertEqual(len(clean), 1)
        self.assertEqual(clean[0].location, "weights.bin")
        self.assertEqual(clean[0].rules, [])

    def test_malicious_cases_have_rules_and_cwe(self):
        for c in corp.CASES:
            if c.malicious:
                self.assertTrue(c.rules, "malicious case %s has no rule" % c.name)
                for r in c.rules:
                    self.assertTrue(r.startswith("OED"))
                self.assertIn(c.severity, ("high", "medium"))

    def test_unique_names(self):
        names = [c.name for c in corp.CASES]
        self.assertEqual(len(names), len(set(names)))

    def test_covers_all_five_rules(self):
        seen = set()
        for c in corp.CASES:
            seen.update(c.rules)
        self.assertEqual(seen, {"OED001", "OED002", "OED003", "OED004", "OED005"})


class TestManifest(unittest.TestCase):
    def test_manifest_matches_cases(self):
        man = corp.manifest()
        self.assertEqual(len(man), len(corp.CASES))
        by_file = {m["file"]: m for m in man}
        for c in corp.CASES:
            m = by_file[c.filename]
            self.assertEqual(m["location"], c.location)
            self.assertEqual(m["malicious"], c.malicious)
            self.assertEqual(m["rules"], c.rules)
            self.assertEqual(m["cwe"], "CWE-22" if c.malicious else None)


class TestWriteCorpus(unittest.TestCase):
    def test_write_corpus_to_disk(self):
        with tempfile.TemporaryDirectory() as d:
            written = corp.write_corpus(d)
            self.assertEqual(len(written), len(corp.CASES) + 1)  # + manifest.json
            self.assertIn("manifest.json", written)
            for c in corp.CASES:
                path = os.path.join(d, c.filename)
                self.assertTrue(os.path.exists(path))
                self.assertGreater(os.path.getsize(path), 0)
                with open(path, "rb") as fh:
                    locs = _extract_locations(fh.read())
                self.assertEqual(locs, [c.location])
            with open(os.path.join(d, "manifest.json"), encoding="utf-8") as fh:
                man = json.load(fh)
            self.assertEqual(man["cwe"], "CWE-22")
            self.assertEqual(len(man["cases"]), len(corp.CASES))


if __name__ == "__main__":
    unittest.main()
