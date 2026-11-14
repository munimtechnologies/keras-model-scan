# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for vendor_check.py (job pte-dtype-v2, row U1).

The macro text below is hand-written in the same shape as an X-macro list
whose long entries are wrapped with a backslash continuation between the C
type and the name (the case job pte-dtype-v1's grader skipped). It is not
copied from any project.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vendor_check as vc  # noqa: E402

WRAPPED = (
    "// header text\n"
    "#define ET_FORALL_SCALAR_TYPES(_)                 \\\n"
    "  _(uint8_t, Byte) /* 0 */                        \\\n"
    "  _(::ns::inner::complex<::other::Half>,          \\\n"
    "    ComplexHalf) /* 1 */                          \\\n"
    "  _(::ns::inner::complex<float>, ComplexFloat) /* 2 */ \\\n"
    "  _(::ns::inner::unused_dtype::Float8_e5m2,       \\\n"
    "    Float8_e5m2) /* 3 */                          \\\n"
    "  _(uint64_t, UInt64) /* 4 */\n"
    "\n"
    "#define SOMETHING_ELSE(_) _(int32_t, Other) /* 9 */\n"
)

# The v1 entry regex, applied without joining continuations (the defect).
V1_ENTRY_RX = re.compile(r"_\(\s*([^,()]+?)\s*,\s*(\w+)\s*\)"
                         r"(?:\s*/\*\s*(\d+)\s*\*/)?")


def block_of(text):
    return vc.macro_block(text, "ET_FORALL_SCALAR_TYPES")


class MacroBlock(unittest.TestCase):

    def test_block_stops_at_the_last_continued_line(self):
        block = block_of(WRAPPED)
        self.assertIn("UInt64", block)
        self.assertNotIn("SOMETHING_ELSE", block)
        self.assertNotIn("header text", block)

    def test_missing_macro(self):
        self.assertIsNone(vc.macro_block("int x;\n", "ET_FORALL_SCALAR_TYPES"))


class ParseEntries(unittest.TestCase):

    def test_wrapped_entries_are_parsed_in_order(self):
        entries = vc.parse_entries(block_of(WRAPPED))
        self.assertEqual([e["name"] for e in entries],
                         ["Byte", "ComplexHalf", "ComplexFloat",
                          "Float8_e5m2", "UInt64"])
        self.assertEqual([e["comment"] for e in entries], [0, 1, 2, 3, 4])
        self.assertEqual([e["index"] for e in entries], [0, 1, 2, 3, 4])

    def test_sizes(self):
        entries = vc.parse_entries(block_of(WRAPPED))
        self.assertEqual([e["size"] for e in entries], [1, 4, 8, 1, 8])

    def test_v1_regex_skips_wrapped_entries(self):
        # Documents the v1 defect: the two wrapped entries are lost.
        names = [n for _, n, _ in V1_ENTRY_RX.findall(block_of(WRAPPED))]
        self.assertEqual(names, ["Byte", "ComplexFloat", "UInt64"])

    def test_crlf_continuations(self):
        crlf = WRAPPED.replace("\n", "\r\n")
        entries = vc.parse_entries(block_of(crlf))
        self.assertEqual(len(entries), 5)
        self.assertEqual(entries[1]["name"], "ComplexHalf")


class Completeness(unittest.TestCase):

    def test_complete_block_has_no_problems(self):
        block = block_of(WRAPPED)
        problems, counts = vc.completeness(block, vc.parse_entries(block))
        self.assertEqual(problems, [])
        self.assertEqual(counts, {"starts": 5, "parsed": 5, "comments": 5})

    def test_an_unparseable_entry_is_reported(self):
        # An entry whose C type has parentheses cannot be parsed; V3 must
        # report the mismatch instead of grading a shorter list.
        text = WRAPPED.replace("_(uint64_t, UInt64) /* 4 */",
                               "_(decltype(x), Weird) /* 4 */")
        block = block_of(text)
        problems, counts = vc.completeness(block, vc.parse_entries(block))
        self.assertTrue(problems)
        self.assertEqual(counts["starts"], 5)
        self.assertEqual(counts["parsed"], 4)

    def test_out_of_order_comments_are_reported(self):
        text = WRAPPED.replace("/* 3 */", "/* 7 */")
        block = block_of(text)
        problems, _ = vc.completeness(block, vc.parse_entries(block))
        self.assertTrue(any("0..N-1" in p for p in problems))

    def test_missing_comment_is_reported(self):
        text = WRAPPED.replace(" /* 2 */", "")
        block = block_of(text)
        problems, _ = vc.completeness(block, vc.parse_entries(block))
        self.assertTrue(problems)


class Compare(unittest.TestCase):

    def setUp(self):
        self.entries = vc.parse_entries(block_of(WRAPPED))

    def test_equal_table(self):
        table = {0: 1, 1: 4, 2: 8, 3: 1, 4: 8}
        self.assertEqual(vc.compare(self.entries, table), [])

    def test_wrong_size(self):
        table = {0: 1, 1: 2, 2: 8, 3: 1, 4: 8}
        problems = vc.compare(self.entries, table)
        self.assertEqual(problems, ["dtype 1: table 2, runtime 4"])

    def test_missing_key(self):
        table = {0: 1, 2: 8, 3: 1, 4: 8}
        problems = vc.compare(self.entries, table)
        self.assertEqual(problems,
                         ["keys differ: table only [], runtime only [1]"])

    def test_unknown_ctype(self):
        text = WRAPPED.replace("uint64_t, UInt64", "mystery_t, UInt64")
        entries = vc.parse_entries(block_of(text))
        problems = vc.compare(entries, {0: 1, 1: 4, 2: 8, 3: 1, 4: 8})
        self.assertIn("UInt64: unknown C type mystery_t", problems)


if __name__ == "__main__":
    unittest.main()
