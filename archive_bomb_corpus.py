#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Part of model-file-scan (munimtechnologies/keras-model-scan).
# Made with AI by MV2 of Munim, Inc. See repository README for details.
"""Safe, payload-free corpus for the model-archive decompression-bomb scanner.

Each generated file is a TINY (well under 100 KiB on disk) ZIP archive that
exercises one detection path in archive_bomb_scan.py WITHOUT being an actual
bomb: nothing here expands to a dangerous size, contains no code, and is safe to
store, commit and open. The files only reproduce the *structure* a real bomb
would have (a high declared amplification ratio, many members, or a nested
archive), so the scanner and any model-zip reader can be regression-tested.

The companion scanner uses LOW thresholds in the test module so these tiny
demonstrators trip the same code paths a multi-gigabyte production bomb would.

Usage
    python archive_bomb_corpus.py --out-dir ./corpus
Writes the archives plus manifest.json (file -> expected finding codes).
"""
from __future__ import annotations

import argparse
import io
import json
import os
import zipfile

# Deliberately small so the whole corpus is harmless. A real bomb would use the
# same structure at millions of times this scale.
_ZERO_BLOCK = 64 * 1024          # 64 KiB of zeros -> compresses to a few hundred B
_MANY_ENTRIES = 600              # trips a low max-entries threshold; file stays tiny


def _zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    """Build a zip in memory from {name: bytes} and return the raw bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def build_corpus():
    """Return {filename: (raw_bytes, [expected finding codes])}."""
    corpus = {}

    # ABZ001 -- one highly compressible member (64 KiB of zeros). A real model
    # weight is high-entropy and barely compresses, so this ratio never occurs
    # in a genuine archive.
    corpus["abomb_high_ratio.zip"] = (
        _zip_bytes([("weights.bin", b"\x00" * _ZERO_BLOCK)]),
        ["ABZ001"],
    )

    # ABZ002 -- several zero blocks so the declared total trips a low size budget.
    corpus["abomb_large_total.zip"] = (
        _zip_bytes([(f"shard_{i}.bin", b"\x00" * _ZERO_BLOCK) for i in range(5)]),
        ["ABZ001", "ABZ002"],
    )

    # ABZ003 -- many tiny members (per-entry / inode exhaustion precursor).
    corpus["abomb_many_entries.zip"] = (
        _zip_bytes([(f"e{i}", b"x") for i in range(_MANY_ENTRIES)]),
        ["ABZ003"],
    )

    # ABZ004 -- a member that is itself an archive (recursive-expansion precursor).
    inner = _zip_bytes([("inner.bin", b"hello")])
    corpus["abomb_nested.zip"] = (
        _zip_bytes([("config.json", b"{}"), ("resources.zip", inner)]),
        ["ABZ004"],
    )

    # Clean control -- a realistic small model zip: a config plus a high-entropy
    # weight blob that does not compress. No findings expected.
    corpus["clean_model.zip"] = (
        _zip_bytes([
            ("config.json", b'{"name": "demo", "layers": 2}'),
            ("weights.bin", os.urandom(4096)),
        ]),
        [],
    )

    return corpus


def write_corpus(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    manifest = {}
    for name, (data, codes) in build_corpus().items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        manifest[name] = {"expected": codes, "bytes": len(data)}
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate the safe, payload-free model-archive bomb corpus. "
                    "Made with AI by MV2 of Munim, Inc.",
    )
    parser.add_argument("--out-dir", required=True, help="directory to write into")
    args = parser.parse_args(argv)
    manifest = write_corpus(args.out_dir)
    total = sum(v["bytes"] for v in manifest.values())
    print(f"wrote {len(manifest)} archives ({total} bytes total) to {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
