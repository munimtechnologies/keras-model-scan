import io
import os
import struct
import tempfile
import unittest
import zipfile

import hdf5_virtual_dataset_scan as m


def _hdf5(version, layout_class, with_gcol=True):
    # Build a minimal HDF5 blob: signature + a v0 superblock (size-of-offsets = 8) +
    # one v1 object-header Data Layout message (type 0x0008) with the given version /
    # layout-class body, followed by an 8-byte global-heap address and (optionally) a
    # GCOL collection for the address to resolve to.
    buf = bytearray()
    buf += m.HDF5_SIGNATURE            # bytes 0..7
    sb = bytearray(24)                 # bytes 8..31
    sb[0] = 0                          # index 8:  superblock version 0
    sb[5] = 8                          # index 13: size of offsets
    sb[6] = 8                          # index 14: size of lengths
    buf += sb
    buf += b"\x08\x00"                 # Data Layout message type (0x0008)
    buf += b"\x20\x00"                 # message size (arbitrary)
    buf += b"\x00"                     # flags
    buf += b"\x00\x00\x00"             # reserved
    buf += bytes([version, layout_class])   # body: version, layout class
    addr_off = len(buf)
    buf += b"\x00" * 8                 # global-heap address placeholder
    if with_gcol:
        gcol_off = len(buf)
        buf += b"GCOL" + b"\x00" * 12
        struct.pack_into("<Q", buf, addr_off, gcol_off)
    else:
        struct.pack_into("<Q", buf, addr_off, 0xFFFFFFFFFFFFFFFF)  # undefined
    return bytes(buf)


class Hdf5VirtualDatasetScanTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def test_virtual_layout_with_gcol_is_high(self):
        f = m.scan_bytes(_hdf5(4, 3, with_gcol=True), name="v.h5")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "HVD001")
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["cve"], "CVE-2026-12480")
        self.assertEqual(f[0]["cwe"], "CWE-73")

    def test_virtual_layout_unresolved_is_info(self):
        f = m.scan_bytes(_hdf5(4, 3, with_gcol=False), name="v.h5")
        self.assertEqual(f[0]["rule"], "HVD002")
        self.assertEqual(f[0]["severity"], "info")

    def test_chunked_layout_clean(self):
        self.assertEqual(m.scan_bytes(_hdf5(4, 2), name="c.h5"), [])

    def test_contiguous_layout_clean(self):
        self.assertEqual(m.scan_bytes(_hdf5(4, 1), name="c.h5"), [])

    def test_version3_class3_not_flagged(self):
        # version 3 Data Layout messages do not define a virtual class; 03 03 is not
        # the version-4/class-3 marker, so it must not match.
        self.assertEqual(m.scan_bytes(_hdf5(3, 3), name="x.h5"), [])

    def test_non_hdf5_is_info(self):
        f = m.scan_bytes(b"not an hdf5 file at all", name="plain.bin")
        self.assertEqual(f[0]["rule"], "HVD010")
        self.assertEqual(f[0]["severity"], "info")

    def test_empty_is_info(self):
        self.assertEqual(m.scan_bytes(b"", name="empty")[0]["rule"], "HVD010")

    def test_keras_zip_member_vds_is_high(self):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w") as zf:
            zf.writestr("config.json", "{}")
            zf.writestr("model.weights.h5", _hdf5(4, 3, with_gcol=True))
        f = m.scan_bytes(blob.getvalue(), name="model.keras")
        self.assertTrue(any(x["rule"] == "HVD001" for x in f))
        self.assertTrue(any("model.weights.h5" in x["evidence"] for x in f))

    def test_keras_zip_no_hdf5_clean(self):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w") as zf:
            zf.writestr("config.json", "{}")
        self.assertEqual(m.scan_bytes(blob.getvalue(), name="model.keras"), [])

    def test_scan_file_reads_from_disk(self):
        path = os.path.join(self.tmp, "v.h5")
        with open(path, "wb") as fh:
            fh.write(_hdf5(4, 3, with_gcol=True))
        self.assertEqual(m.scan_file(path)[0]["rule"], "HVD001")


if __name__ == "__main__":
    unittest.main()
