"""Tests for torch_storage_scan (CVE-2026-24747 static detector).

Fixtures are built with the standard library only: a stub ``torch`` module is
registered so that storage persistent_id tuples pickle their storage type as a
GLOBAL('torch', '<Name>Storage'), exactly as a real torch checkpoint does, and
the ``data/<key>`` members are written with chosen sizes to exercise the
size-mismatch logic. No torch, no network, no unpickling of fixtures.
"""

import io
import os
import pickle
import sys
import tempfile
import types
import unittest
import zipfile

import torch_storage_scan as T


# ---- stub torch storage classes so pickle emits GLOBAL('torch', 'FloatStorage')
_torch = types.ModuleType("torch")
for _nm in ("FloatStorage", "DoubleStorage", "LongStorage", "ByteStorage"):
    _cls = type(_nm, (), {})
    _cls.__module__ = "torch"
    _cls.__qualname__ = _nm
    setattr(_torch, _nm, _cls)
sys.modules["torch"] = _torch
import torch as torch_stub  # noqa: E402  (the stub registered above)


class _StorageStub:
    def __init__(self, type_cls, key, numel):
        self.type_cls = type_cls
        self.key = key
        self.numel = numel


class _StoragePickler(pickle.Pickler):
    def persistent_id(self, obj):
        if isinstance(obj, _StorageStub):
            return ("storage", obj.type_cls, obj.key, "cpu", obj.numel)
        return None


def _make_data_pkl(state):
    buf = io.BytesIO()
    _StoragePickler(buf, protocol=2).dump(state)
    return buf.getvalue()


def _make_checkpoint(storages, data_sizes, prefix="archive"):
    """Build a torch-style zip. ``storages`` maps a name to a _StorageStub;
    ``data_sizes`` maps storage key -> bytes to write for data/<key> (omit a key
    to leave its member absent)."""
    pkl = _make_data_pkl(storages)
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr(prefix + "/data.pkl", pkl)
        zf.writestr(prefix + "/version", b"3\n")
        for key, nbytes in data_sizes.items():
            zf.writestr(prefix + "/data/" + str(key), b"\x00" * nbytes)
    return zbuf.getvalue()


def _rules(findings):
    return [f["rule"] for f in findings]


class TorchStorageScanTest(unittest.TestCase):

    def test_clean_checkpoint_green(self):
        # FloatStorage, numel 16 -> 64 bytes declared, 64 bytes backing.
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.FloatStorage, "0", 16)},
            {"0": 64},
        )
        out = T.scan_bytes(data)
        self.assertEqual(_rules(out), ["TWS000"])
        self.assertEqual(out[0]["detail"]["storages_checked"], 1)

    def test_two_clean_storages(self):
        data = _make_checkpoint(
            {"w": _StorageStub(torch_stub.FloatStorage, "0", 4),
             "b": _StorageStub(torch_stub.LongStorage, "1", 2)},
            {"0": 16, "1": 16},
        )
        out = T.scan_bytes(data)
        self.assertEqual(_rules(out), ["TWS000"])
        self.assertEqual(out[0]["detail"]["storages_checked"], 2)

    def test_storage_size_mismatch_tws001(self):
        # Declares 16 floats = 64 bytes but backs it with only 16 bytes.
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.FloatStorage, "0", 16)},
            {"0": 16},
        )
        out = T.scan_bytes(data)
        self.assertIn("TWS001", _rules(out))
        hit = [f for f in out if f["rule"] == "TWS001"][0]
        self.assertEqual(hit["severity"], "HIGH")
        self.assertEqual(hit["detail"]["declared_bytes"], 64)
        self.assertEqual(hit["detail"]["actual_bytes"], 16)

    def test_double_storage_mismatch(self):
        # DoubleStorage elem size 8; numel 10 -> 80 declared, 8 backing.
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.DoubleStorage, "0", 10)},
            {"0": 8},
        )
        out = T.scan_bytes(data)
        self.assertIn("TWS001", _rules(out))
        self.assertEqual(
            [f for f in out if f["rule"] == "TWS001"][0]["detail"]["elem_size"], 8)

    def test_missing_backing_member_tws002(self):
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.FloatStorage, "0", 16)},
            {},  # no data/0 written
        )
        out = T.scan_bytes(data)
        self.assertIn("TWS002", _rules(out))
        self.assertEqual(
            [f for f in out if f["rule"] == "TWS002"][0]["severity"], "MEDIUM")

    def test_exact_fit_is_clean(self):
        # numel 0 -> 0 bytes declared, empty member is fine.
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.FloatStorage, "0", 0)},
            {"0": 0},
        )
        out = T.scan_bytes(data)
        self.assertEqual(_rules(out), ["TWS000"])

    def test_larger_backing_is_not_flagged(self):
        # Declared 64 bytes, backing 128 bytes: not the OOB-read direction.
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.FloatStorage, "0", 16)},
            {"0": 128},
        )
        out = T.scan_bytes(data)
        self.assertEqual(_rules(out), ["TWS000"])

    def test_setitem_on_list_tws003_raw_pickle(self):
        # PROTO2, EMPTY_LIST, BININT1 0, BININT1 1, SETITEM, STOP
        payload = b"\x80\x02]K\x00K\x01s."
        out = T.scan_bytes(payload)
        self.assertIn("TWS003", _rules(out))
        self.assertEqual(
            [f for f in out if f["rule"] == "TWS003"][0]["severity"], "HIGH")

    def test_setitem_on_list_inside_zip(self):
        payload = b"\x80\x02]K\x00K\x01s."
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("archive/data.pkl", payload)
        out = T.scan_bytes(zbuf.getvalue())
        self.assertIn("TWS003", _rules(out))

    def test_benign_dict_pickle_no_tws003(self):
        payload = pickle.dumps({"a": 1, "b": 2, "c": [1, 2, 3]}, protocol=2)
        out = T.scan_bytes(payload)
        self.assertNotIn("TWS003", _rules(out))
        self.assertEqual(_rules(out), ["TWS010"])  # legacy pickle, clean

    def test_reduce_import_not_flagged_here(self):
        # A dangerous-import pickle is pickle_model_scan's job, not ours: this
        # scanner must parse it without crashing and raise no storage/opcode flag.
        payload = pickle.dumps(os.system)  # GLOBAL os.system (no call)
        out = T.scan_bytes(payload)
        self.assertNotIn("TWS001", _rules(out))
        self.assertNotIn("TWS003", _rules(out))

    def test_non_torch_zip_tws010(self):
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("readme.txt", b"hello")
        out = T.scan_bytes(zbuf.getvalue())
        self.assertEqual(_rules(out), ["TWS010"])

    def test_random_bytes_tws010(self):
        out = T.scan_bytes(b"this is not a pickle and not a zip")
        self.assertEqual(_rules(out), ["TWS010"])

    def test_unknown_storage_type_skipped(self):
        # A storage type we don't size-map must not produce TWS001/002.
        class WeirdStorage:
            pass
        WeirdStorage.__module__ = "torch"
        WeirdStorage.__qualname__ = "WeirdStorage"
        setattr(torch_stub, "WeirdStorage", WeirdStorage)
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.WeirdStorage, "0", 999)},
            {"0": 4},
        )
        out = T.scan_bytes(data)
        self.assertEqual(_rules(out), ["TWS000"])

    def test_scan_file(self):
        data = _make_checkpoint(
            {"weight": _StorageStub(torch_stub.FloatStorage, "0", 16)},
            {"0": 16},
        )
        fd, path = tempfile.mkstemp(suffix=".pth")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            out = T.scan_file(path)
            self.assertIn("TWS001", _rules(out))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
