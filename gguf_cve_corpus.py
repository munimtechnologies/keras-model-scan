# SPDX-License-Identifier: Apache-2.0
# Part of keras-model-scan by MV2 of Munim, Inc. Made with AI.
"""Reproducible GGUF model-file CVE corpus and advisory map.

This module ties the public cluster of GGUF parser memory-safety advisories to
(1) the exact header field whose declared value drives the overflow, (2) the
weakness class (CWE), and (3) the static rule in ``gguf_scan.py`` (GG000-GG012)
that flags the precursor *before any loader runs*.

It also builds a small, **benign, header-only** regression corpus: one tiny
``.gguf`` file per precursor class. Each file merely *declares* an extreme
header value (e.g. a metadata/array count or tensor dimension near 2**64, or a
tensor data offset past EOF). The files contain **no tensor data and no exploit
payload** - a naive parser integer-overflows on the declared value, while a
bounds-checking parser (or ``gguf-scan``) rejects them. You can feed the corpus
to any GGUF reader to regression-test its header validation:

    python gguf_cve_corpus.py --out-dir ./corpus
    gguf-scan ./corpus --fail-on HIGH   # every file should be flagged

Honesty: every CVE below is already public; nothing here is a zero-day. The
crafted files are header-only and carry no payload. A clean scan guarantees
nothing - it only means these specific precursors are absent.

Advisory identifiers were verified at their sources (Cisco Talos TALOS-2024-*,
GitHub Security Advisories, OSV/NVD, VulDB) on 2026-10-14.
"""
from __future__ import annotations

import argparse
import json
import os
import struct

__version__ = "0.1.0"

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

# GGUF metadata value type ids (subset used by the corpus).
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9

U64_MAX = (1 << 64) - 1

# --- Advisory catalogue (verified at source 2026-10-14) ----------------------
# Each entry: the public GGUF parser memory-safety advisory, the component it
# lives in, its weakness class, impact and fix point. Data: CC BY 4.0.
ADVISORIES = {
    "CVE-2024-21825": {
        "ref": "TALOS-2024-1912",
        "component": "llama.cpp GGUF (ggml) GGUF_TYPE_ARRAY/GGUF_TYPE_STRING parsing",
        "cwe": ["CWE-787"],
        "impact": "heap-based buffer overflow -> code execution on a crafted .gguf",
        "fixed": "ggml >= 2024-01-09 (commit 18c2e17 vulnerable)",
    },
    "CVE-2024-23496": {
        "ref": "TALOS-2024-1913 / GHSA-w4wv-vq5v-xp26",
        "component": "llama.cpp GGUF gguf_fread_str",
        "cwe": ["CWE-190", "CWE-787"],
        "impact": "heap-based buffer overflow -> code execution on a crafted .gguf",
        "fixed": "ggml >= 2024-01-09",
    },
    "CVE-2024-23605": {
        "ref": "TALOS-2024-1916",
        "component": "llama.cpp GGUF header.n_kv handling",
        "cwe": ["CWE-190", "CWE-787"],
        "impact": "count*element integer overflow -> undersized alloc -> heap overflow",
        "fixed": "ggml >= 2024-01-09",
    },
    "CVE-2025-53630": {
        "ref": "GHSA-vgg9-87g3-85w8",
        "component": "llama.cpp gguf_init_from_file_impl (ggml/src/gguf.cpp)",
        "cwe": ["CWE-680", "CWE-122"],
        "impact": "integer overflow in size accumulation -> heap out-of-bounds read/write",
        "fixed": "commit 26a48ad699d50b6268900062661bd22f3e792579",
    },
    "CVE-2026-27940": {
        "ref": "GHSA-3p4r-fq3f-q74v",
        "component": "llama.cpp mem_size calculation (bypass of the CVE-2025-53630 fix)",
        "cwe": ["CWE-122"],
        "impact": "integer overflow -> undersized heap allocation -> code execution",
        "fixed": "build b8146",
    },
    "CVE-2026-33298": {
        "ref": "llama.cpp ggml_nbytes advisory",
        "component": "llama.cpp ggml_nbytes() tensor-size computation",
        "cwe": ["CWE-190", "CWE-122"],
        "impact": "tensor-size integer overflow -> heap out-of-bounds access",
        "fixed": "build b7824",
    },
    "CVE-2026-108955": {
        "ref": "VulDB VDB-416774 / Tiiny-AI/PowerInfer#283",
        "component": "PowerInfer gguf_init_from_file (ggml.c) tensor data_offset",
        "cwe": ["CWE-125"],
        "impact": "out-of-bounds read via unchecked tensor data offset",
        "fixed": "pending (rolling release) as of 2026-10-13",
    },
}


# --- Minimal GGUF header writer ----------------------------------------------
def _u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _u64(v: int) -> bytes:
    return struct.pack("<Q", v & U64_MAX)


def _gstr(data: bytes, declared_len: int | None = None) -> bytes:
    """A GGUF string: uint64 length then bytes. ``declared_len`` lets the length
    lie about how many bytes actually follow (to model a length-overrun)."""
    n = len(data) if declared_len is None else declared_len
    return _u64(n) + data


def _base_header(tensor_count: int, kv_count: int) -> bytes:
    return GGUF_MAGIC + _u32(GGUF_VERSION) + _u64(tensor_count) + _u64(kv_count)


def _kv_count_overflow() -> bytes:
    # Declares ~2**64 metadata KV pairs but carries none. GG003.
    return _base_header(0, U64_MAX)


def _tensor_count_overflow() -> bytes:
    # Declares ~2**64 tensors but carries none. GG003.
    return _base_header(U64_MAX, 0)


def _array_len_overflow() -> bytes:
    # One KV whose ARRAY value declares ~2**64 uint32 elements. GG006.
    return (
        _base_header(0, 1)
        + _gstr(b"x")
        + _u32(GGUF_TYPE_ARRAY)
        + _u32(GGUF_TYPE_UINT32)
        + _u64(U64_MAX)
    )


def _string_len_overrun() -> bytes:
    # One KV whose STRING value declares ~2**64 bytes but supplies none. GG004.
    return (
        _base_header(0, 1)
        + _gstr(b"x")
        + _u32(GGUF_TYPE_STRING)
        + _gstr(b"", declared_len=U64_MAX)
    )


def _tensor_dims_overflow() -> bytes:
    # One tensor whose two dimensions multiply past the 64-bit ceiling. GG009.
    return (
        _base_header(1, 0)
        + _gstr(b"t")
        + _u32(2)            # n_dims
        + _u64(U64_MAX)      # dim 0
        + _u64(U64_MAX)      # dim 1
        + _u32(0)            # ggml type
        + _u64(0)            # offset
    )


def _bad_alignment() -> bytes:
    # general.alignment = 0 (not a nonzero power of two) -> GGML_PAD hazard. GG011.
    return (
        _base_header(0, 1)
        + _gstr(b"general.alignment")
        + _u32(GGUF_TYPE_UINT32)
        + _u32(0)
    )


def _data_offset_oob() -> bytes:
    # One tensor whose data offset points far past EOF. GG011 (partial).
    return (
        _base_header(1, 0)
        + _gstr(b"t")
        + _u32(1)            # n_dims
        + _u64(1)            # dim 0
        + _u32(0)            # ggml type
        + _u64(U64_MAX)      # offset past EOF
    )


# --- Corpus: one benign header-only file per precursor class ------------------
CORPUS = [
    {
        "file": "kv_count_overflow.gguf",
        "header_field": "metadata_kv_count",
        "precursor": "declared metadata KV count far exceeds the bytes present",
        "cwe": ["CWE-190", "CWE-787"],
        "gguf_scan_rule": "GG003",
        "coverage": "full",
        "cves": ["CVE-2024-23605"],
        "builder": _kv_count_overflow,
    },
    {
        "file": "tensor_count_overflow.gguf",
        "header_field": "tensor_count",
        "precursor": "declared tensor count drives an oversized size accumulation",
        "cwe": ["CWE-680", "CWE-122"],
        "gguf_scan_rule": "GG003",
        "coverage": "full",
        "cves": ["CVE-2025-53630", "CVE-2026-27940"],
        "builder": _tensor_count_overflow,
    },
    {
        "file": "array_len_overflow.gguf",
        "header_field": "metadata array length",
        "precursor": "array element count times element size overflows the allocation",
        "cwe": ["CWE-787"],
        "gguf_scan_rule": "GG006",
        "coverage": "full",
        "cves": ["CVE-2024-21825"],
        "builder": _array_len_overflow,
    },
    {
        "file": "string_len_overrun.gguf",
        "header_field": "metadata string length",
        "precursor": "declared string length runs past the end of the file",
        "cwe": ["CWE-190", "CWE-787"],
        "gguf_scan_rule": "GG004",
        "coverage": "full",
        "cves": ["CVE-2024-23496"],
        "builder": _string_len_overrun,
    },
    {
        "file": "tensor_dims_overflow.gguf",
        "header_field": "tensor dimensions",
        "precursor": "product of tensor dimensions overflows the 64-bit element count",
        "cwe": ["CWE-190", "CWE-122"],
        "gguf_scan_rule": "GG009",
        "coverage": "full",
        "cves": ["CVE-2026-33298"],
        "builder": _tensor_dims_overflow,
    },
    {
        "file": "bad_alignment.gguf",
        "header_field": "general.alignment",
        "precursor": "alignment is zero (not a nonzero power of two) -> GGML_PAD hazard",
        "cwe": ["CWE-682"],
        "gguf_scan_rule": "GG011",
        "coverage": "full",
        "cves": [],
        "note": "defense-in-depth: no numbered CVE; mirrors public GGML_PAD/alignment hardening",
        "builder": _bad_alignment,
    },
    {
        "file": "data_offset_oob.gguf",
        "header_field": "tensor data offset",
        "precursor": "tensor data offset points past the end of the file",
        "cwe": ["CWE-125"],
        "gguf_scan_rule": "GG011",
        "coverage": "partial",
        "cves": ["CVE-2026-108955"],
        "note": "GG011 flags the unaligned offset; full data-region bounds checking is a documented gap",
        "builder": _data_offset_oob,
    },
]


def build_corpus(out_dir: str) -> dict:
    """Write every crafted header-only .gguf file into ``out_dir``.

    Returns a mapping of filename -> absolute path written."""
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    for entry in CORPUS:
        path = os.path.join(out_dir, entry["file"])
        with open(path, "wb") as fh:
            fh.write(entry["builder"]())
        written[entry["file"]] = os.path.abspath(path)
    return written


def _serializable_map() -> dict:
    """Build the JSON-serializable advisory+corpus map (drops builder funcs)."""
    corpus = []
    for entry in CORPUS:
        item = {k: v for k, v in entry.items() if k != "builder"}
        corpus.append(item)
    return {
        "name": "gguf-cve-map",
        "version": __version__,
        "license": "CC BY 4.0",
        "made_with": "AI, by MV2 of Munim, Inc.",
        "verified_at": "2026-10-14",
        "description": (
            "Maps the public GGUF parser memory-safety advisory cluster to the "
            "header field that overflows, the weakness class, and the gguf_scan "
            "rule that statically flags each precursor before loading."
        ),
        "advisories": ADVISORIES,
        "corpus": corpus,
    }


def dump_map(path: str) -> str:
    """Write the advisory+corpus map as JSON. Returns the absolute path."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_serializable_map(), fh, indent=2, sort_keys=False)
        fh.write("\n")
    return os.path.abspath(path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build the GGUF CVE regression corpus.")
    parser.add_argument("--out-dir", default="gguf_cve_corpus", help="output directory")
    parser.add_argument("--map", default=None, help="also write the JSON map to this path")
    args = parser.parse_args(argv)
    written = build_corpus(args.out_dir)
    for name, path in written.items():
        print(f"wrote {name} -> {path}")
    if args.map:
        print(f"wrote map -> {dump_map(args.map)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
