"""Tests for hdf5_external_storage_scan. The main fixtures are built from bytes so
the suite runs with the standard library only (no h5py, no Keras): a version 0
superblock, a version-0 local heap holding external file names, and External
Data Files / external link messages laid out the way libhdf5 decodes them.
RealH5pyFilesTest repeats the checks on files written by h5py/libhdf5 itself and
runs only where h5py is installed.

Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""

import importlib.util
import io
import os
import struct
import tempfile
import unittest
import zipfile

import hdf5_external_storage_scan as hes

SIG = b"\x89HDF\r\n\x1a\n"
UNDEF = 0xFFFFFFFFFFFFFFFF
HEAP_AT = 256  # relative address of the local heap in every fixture


def superblock(base=0):
    """Superblock version 0 with 8-byte offsets and lengths (56 bytes)."""
    return (SIG + bytes([0, 0, 0, 0, 0, 8, 8, 0]) + struct.pack("<HHI", 4, 16, 0)
            + struct.pack("<QQQQ", base, UNDEF, 4096, UNDEF))


def local_heap(names):
    """Version-0 local heap at HEAP_AT whose data segment follows its 32-byte
    header. Offset 0 holds the empty string, as in libhdf5. Returns the heap
    bytes and each name's offset in the segment."""
    seg = bytearray(8)
    offsets = {}
    for name in names:
        offsets[name] = len(seg)
        seg += name + b"\x00"
    while len(seg) % 8:
        seg += b"\x00"
    hdr = b"HEAP" + b"\x00" * 4 + struct.pack("<QQQ", len(seg), 1, HEAP_AT + 32)
    return hdr + bytes(seg), offsets


def efl_body(slots, heap_at=HEAP_AT, nalloc=None, reserved=b"\x00\x00\x00"):
    nused = len(slots)
    body = b"\x01" + reserved + struct.pack(
        "<HHQ", nused if nalloc is None else nalloc, nused, heap_at)
    for name_off, offset, size in slots:
        body += struct.pack("<QQQ", name_off, offset, size)
    return body


def v1_msg(mtype, body, reserved=b"\x00\x00\x00"):
    while len(body) % 8:
        body += b"\x00"
    return struct.pack("<HHB", mtype, len(body), 0) + reserved + body


def v2_msg(mtype, body):
    return struct.pack("<BHB", mtype, len(body), 0) + body


def link_body(name, target_file, target_obj, flags=0x08):
    body = bytes([1, flags, 64])
    if flags & 0x04:
        body += struct.pack("<q", 3)
    if flags & 0x10:
        body += b"\x01"
    body += len(name).to_bytes(1 << (flags & 0x03), "little") + name
    udata = b"\x00" + target_file + b"\x00" + target_obj + b"\x00"
    return body + struct.pack("<H", len(udata)) + udata


def h5_image(messages=b"", heap=b"", userblock=0):
    """userblock + superblock + local heap at HEAP_AT + messages at 512."""
    img = bytearray(userblock) + superblock(base=userblock)
    img += bytes(userblock + HEAP_AT - len(img))
    img += heap
    img += bytes(userblock + 512 - len(img))
    img += messages
    img += bytes(64)
    return bytes(img)


PASSWD_HEAP, PASSWD_OFFS = local_heap([b"/etc/passwd"])
PASSWD_EFL = efl_body([(PASSWD_OFFS[b"/etc/passwd"], 0, 4096)])


def rules(findings):
    return {f["rule"] for f in findings}


def keras_zip(weights):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", "{}")
        zf.writestr("metadata.json", "{}")
        zf.writestr("model.weights.h5", weights)
    return buf.getvalue()


class ExternalStorageTest(unittest.TestCase):
    def test_v1_external_storage_is_high(self):
        findings = hes.scan_bytes(h5_image(v1_msg(7, PASSWD_EFL), PASSWD_HEAP))
        self.assertEqual(rules(findings), {"HES001"})
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["cve"], "CVE-2026-1669")
        self.assertEqual(f["cwe"], "CWE-73")
        self.assertIn("/etc/passwd", f["evidence"])
        self.assertIn("size=4096", f["evidence"])
        self.assertIn("(absolute path)", f["message"])

    def test_v2_message_header_is_found(self):
        findings = hes.scan_bytes(h5_image(v2_msg(7, PASSWD_EFL), PASSWD_HEAP))
        self.assertEqual(rules(findings), {"HES001"})

    def test_nonzero_reserved_bytes_do_not_evade(self):
        # libhdf5 skips both reserved fields without checking them.
        body = efl_body([(8, 0, 4096)], reserved=b"\xaa\xbb\xcc")
        msg = v1_msg(7, body, reserved=b"\xff\xff\xff")
        self.assertEqual(rules(hes.scan_bytes(h5_image(msg, PASSWD_HEAP))), {"HES001"})

    def test_userblock_offsets_are_relative_to_base(self):
        image = h5_image(v1_msg(7, PASSWD_EFL), PASSWD_HEAP, userblock=512)
        self.assertEqual(rules(hes.scan_bytes(image)), {"HES001"})

    def test_traversal_and_several_slots(self):
        heap, offs = local_heap([b"../../.ssh/id_rsa", b"part2.bin"])
        body = efl_body([(offs[b"../../.ssh/id_rsa"], 0, 64), (offs[b"part2.bin"], 0, 64)])
        findings = hes.scan_bytes(h5_image(v1_msg(7, body), heap))
        self.assertEqual(len(findings), 1)
        self.assertIn("(parent-directory traversal)", findings[0]["message"])
        self.assertIn("part2.bin", findings[0]["evidence"])
        self.assertIn("2 slot(s)", findings[0]["evidence"])

    def test_no_local_heap_is_silent(self):
        self.assertEqual(hes.scan_bytes(h5_image(v1_msg(7, PASSWD_EFL))), [])

    def test_heap_address_must_match_a_heap(self):
        body = efl_body([(8, 0, 4096)], heap_at=HEAP_AT + 8)
        self.assertEqual(hes.scan_bytes(h5_image(v1_msg(7, body), PASSWD_HEAP)), [])

    def test_used_slots_above_allocated_is_rejected(self):
        body = efl_body([(8, 0, 4096)], nalloc=0)
        self.assertEqual(hes.scan_bytes(h5_image(v1_msg(7, body), PASSWD_HEAP)), [])

    def test_empty_name_is_rejected(self):
        body = efl_body([(0, 0, 4096)])
        self.assertEqual(hes.scan_bytes(h5_image(v1_msg(7, body), PASSWD_HEAP)), [])

    def test_symbol_table_message_is_silent(self):
        # Ordinary groups also point at a local heap (message type 0x11).
        stab = v1_msg(0x11, struct.pack("<QQ", 1024, HEAP_AT))
        self.assertEqual(hes.scan_bytes(h5_image(stab, PASSWD_HEAP)), [])


class ExternalLinkTest(unittest.TestCase):
    def test_external_link_is_high(self):
        msg = v1_msg(6, link_body(b"dense", b"secrets.h5", b"/data"))
        findings = hes.scan_bytes(h5_image(msg))
        self.assertEqual(rules(findings), {"HES002"})
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["cve"], "CVE-2026-1669")
        self.assertIn("file 'secrets.h5'", f["evidence"])
        self.assertIn("object '/data'", f["evidence"])

    def test_creation_order_charset_and_wide_name_length(self):
        for flags in (0x0D, 0x1D, 0x0B):
            body = link_body(b"layer_0", b"/tmp/other.h5", b"/vars/0", flags=flags)
            findings = hes.scan_bytes(h5_image(v2_msg(6, body)))
            self.assertEqual(rules(findings), {"HES002"}, hex(flags))

    def test_hard_and_soft_links_are_silent(self):
        hard = bytes([1, 0x00, 5]) + b"dense" + struct.pack("<Q", 1024)
        soft = bytes([1, 0x08, 1, 5]) + b"dense" + struct.pack("<H", 5) + b"/vars"
        image = h5_image(v1_msg(6, hard) + v1_msg(6, soft))
        self.assertEqual(hes.scan_bytes(image), [])

    def test_unprintable_target_is_rejected(self):
        msg = v1_msg(6, link_body(b"dense", b"\x01\x02", b"/data"))
        self.assertEqual(hes.scan_bytes(h5_image(msg)), [])


class ContainerTest(unittest.TestCase):
    def test_keras_archive_member_is_scanned(self):
        data = keras_zip(h5_image(v1_msg(7, PASSWD_EFL), PASSWD_HEAP))
        findings = hes.scan_bytes(data, name="model.keras")
        self.assertEqual(rules(findings), {"HES001"})
        self.assertIn("model.keras!model.weights.h5", findings[0]["evidence"])

    def test_clean_keras_archive_is_silent(self):
        self.assertEqual(hes.scan_bytes(keras_zip(h5_image(heap=PASSWD_HEAP))), [])

    def test_oversized_member_is_reported_not_read(self):
        data = keras_zip(h5_image(v1_msg(7, PASSWD_EFL), PASSWD_HEAP))
        self.assertEqual(rules(hes.scan_bytes(data, max_member_bytes=16)), {"HES011"})

    def test_not_hdf5_is_info(self):
        self.assertEqual(rules(hes.scan_bytes(b"plain text, not hdf5")), {"HES010"})

    def test_clean_hdf5_is_silent(self):
        self.assertEqual(hes.scan_bytes(h5_image(heap=PASSWD_HEAP)), [])


class CliTest(unittest.TestCase):
    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.weights.h5")
            clean = os.path.join(tmp, "clean.weights.h5")
            with open(bad, "wb") as fh:
                fh.write(h5_image(v1_msg(7, PASSWD_EFL), PASSWD_HEAP))
            with open(clean, "wb") as fh:
                fh.write(h5_image(heap=PASSWD_HEAP))
            self.assertEqual(hes.main([bad]), 1)
            self.assertEqual(hes.main([clean]), 0)
            self.assertEqual(hes.main([os.path.join(tmp, "missing.h5")]), 2)
        self.assertEqual(hes.main([]), 2)


@unittest.skipUnless(importlib.util.find_spec("h5py"), "h5py not installed")
class RealH5pyFilesTest(unittest.TestCase):
    """Files written by h5py/libhdf5 with both object-header formats."""

    def setUp(self):
        import h5py
        import numpy
        self.h5py, self.np = h5py, numpy
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def path(self, name):
        return os.path.join(self.tmp, name)

    def test_clean_weights_are_silent(self):
        for libver in ("earliest", "latest"):
            p = self.path("clean-%s.h5" % libver)
            with self.h5py.File(p, "w", libver=libver) as f:
                g = f.create_group("layers/dense/vars")
                g.create_dataset("0", data=self.np.arange(64, dtype="f4").reshape(8, 8))
                g.create_dataset("1", data=self.np.zeros(8, dtype="f4"))
                g.attrs["name"] = "dense"
            self.assertEqual(hes.scan_file(p), [], libver)

    def test_external_storage_is_flagged(self):
        ext = self.path("host-secret.bin")
        with open(ext, "wb") as fh:
            fh.write(b"S" * 64)
        for libver in ("earliest", "latest"):
            p = self.path("efl-%s.h5" % libver)
            with self.h5py.File(p, "w", libver=libver) as f:
                f.create_dataset("w", shape=(16,), dtype="f4", external=[(ext, 0, 64)])
            hits = [x for x in hes.scan_file(p) if x["rule"] == "HES001"]
            self.assertGreaterEqual(len(hits), 1, libver)
            self.assertIn("host-secret.bin", hits[0]["evidence"])
            with open(p, "rb") as fh:
                data = keras_zip(fh.read())
            self.assertIn("HES001", rules(hes.scan_bytes(data)), libver)

    def test_external_link_is_flagged(self):
        for libver in ("earliest", "latest"):
            p = self.path("elink-%s.h5" % libver)
            with self.h5py.File(p, "w", libver=libver) as f:
                f.create_group("layers")
                f["layers"]["dense"] = self.h5py.ExternalLink("other-file.h5", "/vars/0")
            hits = [x for x in hes.scan_file(p) if x["rule"] == "HES002"]
            self.assertGreaterEqual(len(hits), 1, libver)
            self.assertIn("other-file.h5", hits[0]["evidence"])
            self.assertIn("/vars/0", hits[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
