#!/usr/bin/env python3
# Copyright 2026 MV2, Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run step for job pte-dtype-v1: build the candidate fix
(executorch_pte_scan 0.1.1) from the released v0.60.0 tree.

Usage: patch_pte.py TREE PATCHED OUT

Copies TREE's executorch_pte_scan.py, test_executorch_pte_scan.py and
EXECUTORCH_PTE_SCAN.md to PATCHED and applies these edits, each of which
must match exactly once (row P1):

1. The element-size table follows the runtime's ScalarType list
   (ET_FORALL_SCALAR_TYPES, values 0-29) instead of schema/scalar_type.fbs,
   adding ComplexHalf/ComplexFloat/ComplexDouble (8-10) and
   Bits1x8..Bits8 (18-21). The old table must equal OLD_TABLE.
2. __version__ 0.1.0 -> 0.1.1; the module docstring says where dtypes come
   from.
3. test_unknown_dtype uses 30 (Undefined in the runtime enum) instead of 9;
   test_version expects 0.1.1.
4. EXECUTORCH_PTE_SCAN.md gets a "Changes in 0.1.1" section at the end.

Also copies test_executorch_pte_dtypes.py (new tests) into PATCHED, then
copies every PATCHED file to OUT/patched and writes OUT/patch_report.json.
Always exits 0; the report is graded.

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.
"""
import ast
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

OLD_TABLE = {0: 1, 1: 1, 2: 2, 3: 4, 4: 8, 5: 2, 6: 4, 7: 8, 11: 1, 12: 1,
             13: 1, 14: 4, 15: 2, 16: 1, 17: 1, 22: 2, 23: 1, 24: 1, 25: 1,
             26: 1, 27: 2, 28: 4, 29: 8}

TABLE_RX = re.compile(r"# Element sizes by ScalarType[^\n]*\n"
                      r"_ELEMENT_SIZE = (\{[^}]*\})\n")

NEW_TABLE = '''# Element sizes by ScalarType, as the runtime computes them. elementSize()
# (runtime/core/exec_aten/util/scalar_type_util.h) is sizeof() over
# ET_FORALL_SCALAR_TYPES (runtime/core/portable_type/scalar_type.h), and the
# tensor parser accepts every value isValid() accepts: 0 to 29. The schema
# (schema/scalar_type.fbs) lists ComplexHalf, ComplexFloat, ComplexDouble
# (8-10) and Bits1x8..Bits8 (18-21) only as comments, but published programs
# use them (ComplexFloat in audio preprocessors), so they are listed here.
_ELEMENT_SIZE = {0: 1, 1: 1, 2: 2, 3: 4, 4: 8, 5: 2, 6: 4, 7: 8, 8: 4, 9: 8,
                 10: 16, 11: 1, 12: 1, 13: 1, 14: 4, 15: 2, 16: 1, 17: 1,
                 18: 1, 19: 1, 20: 1, 21: 1, 22: 2, 23: 1, 24: 1, 25: 1,
                 26: 1, 27: 2, 28: 4, 29: 8}
'''

MODULE_EDITS = [
    ('__version__ = "0.1.0"\n', '__version__ = "0.1.1"\n'),
    ('Static review only: nothing is loaded or executed.\n',
     'Dtypes follow the runtime\'s ScalarType list (0-29), which includes the\n'
     'complex and bits types that schema/scalar_type.fbs lists only as\n'
     'comments; a value outside it is PTE004.\n'
     '\n'
     'Static review only: nothing is loaded or executed.\n'),
]

TEST_EDITS = [
    ('        values = [_tensor(dtype=9), _tensor()]\n'
     '        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))\n'
     '        self.assertEqual(_rules(findings), ["PTE004"])\n'
     '        self.assertIn("scalar_type 9", findings[0]["evidence"])\n',
     '        # 30 is Undefined in the runtime enum; 0-29 are valid dtypes.\n'
     '        values = [_tensor(dtype=30), _tensor()]\n'
     '        findings = pte.scan_bytes(_pte(plan=_plan(values=values)))\n'
     '        self.assertEqual(_rules(findings), ["PTE004"])\n'
     '        self.assertIn("scalar_type 30", findings[0]["evidence"])\n'),
    ('        self.assertEqual(pte.__version__, "0.1.0")\n',
     '        self.assertEqual(pte.__version__, "0.1.1")\n'),
]

DOC_SECTION = '''
## Changes in 0.1.1

- Dtypes now follow the runtime's `ScalarType` list (values 0-29,
  `ET_FORALL_SCALAR_TYPES` in `runtime/core/portable_type/scalar_type.h`),
  which is what the runtime's tensor parser accepts (`isValid`). 0.1.0
  followed `schema/scalar_type.fbs`, which lists `ComplexHalf`,
  `ComplexFloat`, `ComplexDouble` (8-10) and `Bits1x8`..`Bits8` (18-21) only
  as comments, so it raised PTE004 on honest programs: 15 of 450 published
  `.pte` files in the November 2026 Hub census, all for `ComplexFloat` (9),
  mostly audio preprocessors
  ([RESULTS_PTE_CENSUS_2026-11.md](RESULTS_PTE_CENSUS_2026-11.md)). The
  statement above that a genuine export never contains an integrity finding
  was wrong for those dtypes. Such tensors now get the same size checks as
  any other; a value outside 0-29 is still PTE004. Checked on published files
  before release
  ([research/PREREG_PTE_DTYPE_FIX.md](research/PREREG_PTE_DTYPE_FIX.md)).
'''


def edit_once(text, old, new, name, rep):
    n = text.count(old)
    rep["edits"].append({"file": name, "anchor": old[:60], "matches": n})
    if n != 1:
        rep["ok"] = False
        return text
    return text.replace(old, new, 1)


def main():
    tree, patched, out = (os.path.abspath(a) for a in sys.argv[1:4])
    rep = {"ok": True, "edits": [], "error": None}
    try:
        shutil.rmtree(patched, ignore_errors=True)
        os.makedirs(patched)
        with open(os.path.join(tree, "executorch_pte_scan.py"),
                  encoding="utf-8") as fh:
            mod = fh.read()
        found = TABLE_RX.findall(mod)
        rep["edits"].append({"file": "executorch_pte_scan.py",
                             "anchor": "_ELEMENT_SIZE table",
                             "matches": len(found)})
        if len(found) != 1 or ast.literal_eval(found[0]) != OLD_TABLE:
            rep["ok"] = False
            rep["old_table_matches"] = (len(found) == 1 and
                                        ast.literal_eval(found[0]) == OLD_TABLE)
        else:
            mod = TABLE_RX.sub(lambda m: NEW_TABLE, mod, count=1)
            rep["old_table_matches"] = True
        for old, new in MODULE_EDITS:
            mod = edit_once(mod, old, new, "executorch_pte_scan.py", rep)
        with open(os.path.join(patched, "executorch_pte_scan.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(mod)

        with open(os.path.join(tree, "test_executorch_pte_scan.py"),
                  encoding="utf-8") as fh:
            test = fh.read()
        for old, new in TEST_EDITS:
            test = edit_once(test, old, new, "test_executorch_pte_scan.py", rep)
        with open(os.path.join(patched, "test_executorch_pte_scan.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(test)

        with open(os.path.join(tree, "EXECUTORCH_PTE_SCAN.md"),
                  encoding="utf-8") as fh:
            doc = fh.read()
        if "## Changes in 0.1.1" in doc:
            rep["ok"] = False
            rep["edits"].append({"file": "EXECUTORCH_PTE_SCAN.md",
                                 "anchor": "already has 0.1.1", "matches": 1})
        doc = doc.rstrip("\n") + "\n" + DOC_SECTION
        with open(os.path.join(patched, "EXECUTORCH_PTE_SCAN.md"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(doc)

        shutil.copy(os.path.join(HERE, "test_executorch_pte_dtypes.py"),
                    os.path.join(patched, "test_executorch_pte_dtypes.py"))
        dest = os.path.join(out, "patched")
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(patched, dest)
        # The unpatched originals, for the record.
        orig = os.path.join(out, "orig")
        os.makedirs(orig, exist_ok=True)
        for name in ("executorch_pte_scan.py", "test_executorch_pte_scan.py",
                     "EXECUTORCH_PTE_SCAN.md"):
            shutil.copy(os.path.join(tree, name), os.path.join(orig, name))
    except Exception as exc:
        rep["ok"] = False
        rep["error"] = "%s: %s" % (type(exc).__name__, exc)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "patch_report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1)
    print(json.dumps(rep, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
