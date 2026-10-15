#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Part of model-file-scan (munimtechnologies/keras-model-scan).
# Made with AI by MV2 of Munim, Inc. See repository README for details.
"""Static decompression-bomb / resource-exhaustion scanner for ML model archives.

Many ML model containers are ZIP archives that a loader EXTRACTS or materializes
before inference starts:

    .keras  (Keras v3)   -> keras extracts config.json + weight shards
    .pt/.pth (PyTorch)   -> torch.load reads a zip of pickle + tensor storages
    .npz    (NumPy)       -> zip of .npy arrays
    MLeap / stanza / etc. -> zip of model resources

The traversal dimension of these archives (an entry that escapes the extraction
directory) is already handled by other rules in this suite (KMS005 for .keras,
PKL030 for pickle/.pt). This module covers the ORTHOGONAL dimension: an archive
whose declared sizes, entry count or nesting would exhaust disk or memory when a
loader expands it -- a classic "zip bomb" / data-amplification denial of service
(CWE-409, Improper Handling of Highly Compressed Data).

It is static and framework-free: it reads only the ZIP central directory
(ZipInfo.file_size / compress_size / the member list), which the loader itself
trusts to plan extraction. It NEVER extracts, decompresses or reads entry data,
NEVER imports keras/torch/numpy, and NEVER executes anything.

Findings
    ABZ001 (HIGH)   An entry's declared uncompressed/compressed ratio is far above
                    what real weights produce (weights are high-entropy and barely
                    compress), and the entry is large enough to matter -- a
                    high-amplification member.
    ABZ002 (HIGH)   The sum of declared uncompressed sizes across the archive would
                    write more than the configured budget to disk/memory on load.
    ABZ003 (MEDIUM) The archive declares an unusually large number of members
                    (per-entry overhead / inode exhaustion / slow extraction).
    ABZ004 (MEDIUM) A member is itself an archive (.zip/.gz/.xz/.bz2/.7z/...), which
                    a recursive loader could expand again (nested-bomb precursor).
    ABZ000 (ERROR)  The file looked like an archive but could not be read.

A clean scan does NOT prove a file is safe; thresholds are heuristics. Prior art:
generic zip-bomb detection is well known, and the SecAI-Hub modelscan fork added
archive-bomb checks for model zips; ProtectAI ModelScan and promptfoo ModelAudit's
base scanners do not flag decompression bombs. This is a standalone, stdlib-only
detector for the model-file niche, paired with a safe, payload-free corpus
(archive_bomb_corpus.py).

Usage
    python archive_bomb_scan.py path/to/model.keras
    python archive_bomb_scan.py ./model-dir --fail-on HIGH --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile

__version__ = "0.15.0"

# Extensions a model loader may hand to a zip reader. Any other file is probed by
# zipfile and simply skipped if it is not a valid archive.
MODEL_ARCHIVE_SUFFIXES = (".keras", ".pt", ".pth", ".npz", ".zip", ".ckpt", ".mleap")

# Member suffixes that indicate a nested archive (ABZ004).
NESTED_ARCHIVE_SUFFIXES = (
    ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".rar", ".zst", ".lz4", ".tar",
)

# Realistic production defaults. Tune for your pipeline; the bundled corpus is
# tiny and is meant to be scanned with lower thresholds (see the test module).
DEFAULTS = {
    "per_entry_ratio": 100.0,       # uncompressed/compressed amplification factor
    "min_entry_bytes": 1 << 20,     # ignore ABZ001 below 1 MiB uncompressed
    "total_uncompressed": 1 << 30,  # ABZ002 budget: 1 GiB total declared
    "max_entries": 100_000,         # ABZ003 member-count ceiling
    "flag_nested": True,            # ABZ004
}

_SEVERITY_ORDER = {"ERROR": 3, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _finding(code, severity, cwe, file, member, detail):
    return {
        "code": code,
        "severity": severity,
        "cwe": cwe,
        "file": file,
        "member": member,
        "detail": detail,
    }


def scan_file(path, config=None):
    """Scan a single file. Returns a list of finding dicts (empty if clean or the
    file is not a readable archive)."""
    cfg = dict(DEFAULTS)
    if config:
        cfg.update(config)

    if not zipfile.is_zipfile(path):
        return []

    findings = []
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        return [_finding("ABZ000", "ERROR", "CWE-409", path, None,
                         f"could not read archive: {exc}")]

    total_uncompressed = 0
    for info in infos:
        name = info.filename
        file_size = int(info.file_size)
        compress_size = int(info.compress_size)
        total_uncompressed += file_size

        if file_size >= cfg["min_entry_bytes"] and compress_size > 0:
            ratio = file_size / compress_size
            if ratio >= cfg["per_entry_ratio"]:
                findings.append(_finding(
                    "ABZ001", "HIGH", "CWE-409", path, name,
                    f"member expands {ratio:.0f}x "
                    f"({compress_size} -> {file_size} bytes); high amplification",
                ))

        if cfg["flag_nested"] and name.lower().endswith(NESTED_ARCHIVE_SUFFIXES):
            findings.append(_finding(
                "ABZ004", "MEDIUM", "CWE-409", path, name,
                "member is itself an archive; a recursive loader may re-expand it",
            ))

    if total_uncompressed >= cfg["total_uncompressed"]:
        findings.append(_finding(
            "ABZ002", "HIGH", "CWE-409", path, None,
            f"archive declares {total_uncompressed} bytes uncompressed across "
            f"{len(infos)} members (>= budget {cfg['total_uncompressed']})",
        ))

    if len(infos) >= cfg["max_entries"]:
        findings.append(_finding(
            "ABZ003", "MEDIUM", "CWE-409", path, None,
            f"archive declares {len(infos)} members (>= {cfg['max_entries']})",
        ))

    return findings


def scan_path(path, config=None):
    """Scan a file or walk a directory. Returns a flat list of finding dicts."""
    findings = []
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(MODEL_ARCHIVE_SUFFIXES):
                    findings.extend(scan_file(os.path.join(root, fn), config))
    else:
        findings.extend(scan_file(path, config))
    return findings


def _build_config(args):
    cfg = dict(DEFAULTS)
    if args.per_entry_ratio is not None:
        cfg["per_entry_ratio"] = args.per_entry_ratio
    if args.min_entry_bytes is not None:
        cfg["min_entry_bytes"] = args.min_entry_bytes
    if args.total_uncompressed is not None:
        cfg["total_uncompressed"] = args.total_uncompressed
    if args.max_entries is not None:
        cfg["max_entries"] = args.max_entries
    cfg["flag_nested"] = not args.no_nested
    return cfg


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Static decompression-bomb scanner for ML model archives "
                    "(CWE-409). Reads ZIP central-directory metadata only; never "
                    "extracts or executes. Made with AI by MV2 of Munim, Inc.",
    )
    parser.add_argument("path", help="model archive file or directory to scan")
    parser.add_argument("--per-entry-ratio", type=float, default=None,
                        help=f"ABZ001 amplification threshold (default "
                             f"{DEFAULTS['per_entry_ratio']:.0f})")
    parser.add_argument("--min-entry-bytes", type=int, default=None,
                        help=f"ignore ABZ001 below this uncompressed size "
                             f"(default {DEFAULTS['min_entry_bytes']})")
    parser.add_argument("--total-uncompressed", type=int, default=None,
                        help=f"ABZ002 total-size budget in bytes (default "
                             f"{DEFAULTS['total_uncompressed']})")
    parser.add_argument("--max-entries", type=int, default=None,
                        help=f"ABZ003 member-count ceiling (default "
                             f"{DEFAULTS['max_entries']})")
    parser.add_argument("--no-nested", action="store_true",
                        help="disable ABZ004 nested-archive flagging")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW"],
                        default=None,
                        help="exit non-zero if a finding at or above this "
                             "severity is present")
    args = parser.parse_args(argv)

    findings = scan_path(args.path, _build_config(args))

    if args.json:
        print(json.dumps({"version": __version__, "findings": findings}, indent=2))
    else:
        if not findings:
            print(f"model-archive-bomb-scan {__version__}: no findings in "
                  f"{args.path}")
        for f in findings:
            loc = f["file"] + (f" :: {f['member']}" if f["member"] else "")
            print(f"[{f['severity']}] {f['code']} {f['cwe']} {loc}: {f['detail']}")

    if args.fail_on:
        threshold = _SEVERITY_ORDER[args.fail_on]
        if any(_SEVERITY_ORDER.get(f["severity"], 0) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
