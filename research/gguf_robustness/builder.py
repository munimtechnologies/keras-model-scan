"""Hand-built GGUF corpus for an offline robustness probe of the Python gguf-py reader.

Made with AI by MV2 of Munim, Inc. (Apache-2.0). This writes a set of local,
inert GGUF files -- one well-formed control plus seven malformed variants that each
declare an astronomically large size (tensor dims/count, kv count, string/array
length, data offset) inside a tiny file, or a degenerate alignment. No file here is
executable and nothing is ever loaded against a live or hosted system; the only
reader that touches them is the local Python gguf-py reader, under a memory cap and
a timeout (see probe.py).

The question under test (CWE-400 denial of service / CWE-125 out-of-bounds read):
can any of these crafted files make the Python reader hang or blow up its allocation,
the way the published Go/C++ GGUF-reader CVEs (CVE-2026-7482, CVE-2025-66960,
CVE-2026-27940, ...) do in those compiled readers? Source review predicts NO -- numpy
memmap slices truncate rather than over-read, and reshape raises a clean ValueError --
so the predicted outcome is: control loads, every malformed file is rejected quickly,
no timeout, no MemoryError. A surprise (timeout / OOM) would be a novel, reportable
finding for the Python reader, which currently has no such advisory on OSV.
"""

import struct

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3
ALIGNMENT = 32

# gguf metadata value type enum
GT_UINT32 = 4
GT_STRING = 8
GT_ARRAY = 9

# ggml tensor type enum
GGML_TYPE_F32 = 0

HUGE = 1 << 40  # ~1.1e12 -- far larger than any real tiny-file content


def _u32(v: int) -> bytes:
    return struct.pack("<I", v)


def _u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def _gstr(s: bytes) -> bytes:
    """A well-formed gguf string: uint64 length prefix then that many bytes."""
    return _u64(len(s)) + s


def _gstr_declared(declared_len: int, body: bytes) -> bytes:
    """A gguf string whose declared length may differ from its actual body
    (used to craft an over-long string without supplying the bytes)."""
    return _u64(declared_len) + body


def _pad_to_alignment(buf: bytes) -> bytes:
    rem = len(buf) % ALIGNMENT
    if rem:
        buf += b"\x00" * (ALIGNMENT - rem)
    return buf


def _header(tensor_count: int, kv_count: int) -> bytes:
    return GGUF_MAGIC + _u32(GGUF_VERSION) + _u64(tensor_count) + _u64(kv_count)


def _tensor_info(name: bytes, dims, ggml_type: int, offset: int) -> bytes:
    out = _gstr(name) + _u32(len(dims))
    for d in dims:
        out += _u64(d)
    out += _u32(ggml_type) + _u64(offset)
    return out


def build_control() -> bytes:
    """A minimal well-formed GGUF: no metadata, one 4-element F32 tensor."""
    buf = _header(tensor_count=1, kv_count=0)
    buf += _tensor_info(b"t", dims=[4], ggml_type=GGML_TYPE_F32, offset=0)
    buf = _pad_to_alignment(buf)
    buf += struct.pack("<4f", 0.0, 0.0, 0.0, 0.0)  # 16 bytes of tensor data
    return buf


def build_tensor_dims_overflow() -> bytes:
    """One tensor declaring HUGE elements but with no backing data: forces the
    reader to size/reshape a giant array from a tiny file."""
    buf = _header(tensor_count=1, kv_count=0)
    buf += _tensor_info(b"t", dims=[HUGE], ggml_type=GGML_TYPE_F32, offset=0)
    buf = _pad_to_alignment(buf)
    buf += struct.pack("<4f", 0.0, 0.0, 0.0, 0.0)
    return buf


def build_tensor_count_overflow() -> bytes:
    """Declares 2**32 tensors but supplies none: the reader's per-tensor loop must
    read far past EOF."""
    buf = _header(tensor_count=(1 << 32), kv_count=0)
    # no tensor infos follow
    buf = _pad_to_alignment(buf)
    return buf


def build_kv_count_overflow() -> bytes:
    """Declares 2**32 metadata KV pairs but supplies none."""
    buf = _header(tensor_count=0, kv_count=(1 << 32))
    buf = _pad_to_alignment(buf)
    return buf


def build_string_len_overrun() -> bytes:
    """A metadata value string declaring HUGE bytes but supplying 4."""
    buf = _header(tensor_count=0, kv_count=1)
    buf += _gstr(b"k")              # key
    buf += _u32(GT_STRING)         # value type = string
    buf += _gstr_declared(HUGE, b"abcd")  # value: declared huge, 4 real bytes
    buf = _pad_to_alignment(buf)
    return buf


def build_array_len_overflow() -> bytes:
    """A metadata value array declaring HUGE elements but supplying 1."""
    buf = _header(tensor_count=0, kv_count=1)
    buf += _gstr(b"k")             # key
    buf += _u32(GT_ARRAY)         # value type = array
    buf += _u32(GT_UINT32)        # element type = uint32
    buf += _u64(HUGE)             # declared element count
    buf += _u32(1)               # only one real element (4 bytes)
    buf = _pad_to_alignment(buf)
    return buf


def build_data_offset_oob() -> bytes:
    """A tensor whose data offset points far beyond EOF."""
    buf = _header(tensor_count=1, kv_count=0)
    buf += _tensor_info(b"t", dims=[4], ggml_type=GGML_TYPE_F32, offset=HUGE)
    buf = _pad_to_alignment(buf)
    buf += struct.pack("<4f", 0.0, 0.0, 0.0, 0.0)
    return buf


def build_bad_alignment() -> bytes:
    """Sets general.alignment to 0 (degenerate). A reader that pads with a modulo
    by alignment would hit ZeroDivisionError rather than a hang."""
    buf = _header(tensor_count=1, kv_count=1)
    buf += _gstr(b"general.alignment")
    buf += _u32(GT_UINT32)
    buf += _u32(0)               # alignment = 0
    buf += _tensor_info(b"t", dims=[4], ggml_type=GGML_TYPE_F32, offset=0)
    # deliberately do NOT 32-pad: alignment is 0 per the file
    buf += struct.pack("<4f", 0.0, 0.0, 0.0, 0.0)
    return buf


CORPUS = {
    "control_valid": build_control,
    "tensor_dims_overflow": build_tensor_dims_overflow,
    "tensor_count_overflow": build_tensor_count_overflow,
    "kv_count_overflow": build_kv_count_overflow,
    "string_len_overrun": build_string_len_overrun,
    "array_len_overflow": build_array_len_overflow,
    "data_offset_oob": build_data_offset_oob,
    "bad_alignment": build_bad_alignment,
}


def generate_corpus(out_dir: str) -> dict:
    """Write every fixture into out_dir. Returns {name: path}."""
    import os
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    for name, fn in CORPUS.items():
        path = os.path.join(out_dir, name + ".gguf")
        with open(path, "wb") as fh:
            fh.write(fn())
        paths[name] = path
    return paths
