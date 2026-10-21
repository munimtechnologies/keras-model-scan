# test_pickle_eval_global_scan.py - local, no-network regression test.
# Hand-crafted pickle bytes (no numpy import needed). Apache-2.0.
# Made with AI agents working in the name of MV2, Munim, Inc.
import os
import pickle
import tempfile
import unittest

import pickle_eval_global_scan as m


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


# proto-2 GLOBAL + empty-tuple + REDUCE -> numpy.testing._private.utils.runstring
_RUNSTRING_REDUCE = b"\x80\x02cnumpy.testing._private.utils\nrunstring\n)R."
# proto-4 STACK_GLOBAL + empty-tuple + REDUCE -> numpy.f2py.crackfortran.myeval
_F2PY_STACK_GLOBAL = (
    b"\x80\x04\x8c\x17numpy.f2py.crackfortran\x8c\x06myeval\x93)R."
)


class TestPickleEvalGlobalScan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def _p(self, n):
        return os.path.join(self.d, n)

    def test_runstring_global_reduce_is_peg001(self):
        p = self._p("rs.pkl")
        _write(p, _RUNSTRING_REDUCE)
        f = m.scan(p)
        self.assertIn("PEG001", {x["rule"] for x in f})
        hit = [x for x in f if x["rule"] == "PEG001"][0]
        self.assertEqual(hit["cve"], "CVE-2025-71355")

    def test_f2py_stack_global_reduce_is_peg001(self):
        p = self._p("f2py.pkl")
        _write(p, _F2PY_STACK_GLOBAL)
        f = m.scan(p)
        self.assertIn("PEG001", {x["rule"] for x in f})
        hit = [x for x in f if x["rule"] == "PEG001"][0]
        self.assertEqual(hit["cve"], "CVE-2025-71365")

    def test_benign_numpy_global_not_flagged(self):
        p = self._p("ok.pkl")
        _write(p, b"\x80\x02cnumpy.core.multiarray\n_reconstruct\n)R.")
        rules = {x["rule"] for x in m.scan(p)}
        self.assertNotIn("PEG001", rules)
        self.assertNotIn("PEG002", rules)

    def test_plain_object_no_findings(self):
        p = self._p("plain.pkl")
        _write(p, pickle.dumps({"a": [1, 2, 3], "b": "x"}))
        self.assertEqual(m.scan(p), [])

    def test_pydoc_is_peg002(self):
        p = self._p("pydoc.pkl")
        _write(p, b"\x80\x02cpydoc\npipepager\n)R.")
        self.assertIn("PEG002", {x["rule"] for x in m.scan(p)})

    def test_runstring_without_exec_is_peg003(self):
        p = self._p("noexec.pkl")
        _write(p, b"\x80\x02cnumpy.testing._private.utils\nrunstring\n.")
        rules = {x["rule"] for x in m.scan(p)}
        self.assertIn("PEG003", rules)
        self.assertNotIn("PEG001", rules)

    def test_malformed_is_peg000(self):
        p = self._p("bad.pkl")
        _write(p, b"\x80\x02\xff\xff\xff")
        self.assertIn("PEG000", {x["rule"] for x in m.scan(p)})


if __name__ == "__main__":
    unittest.main(verbosity=2)
