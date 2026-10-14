# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
#
# safetensors_scan.py -- static integrity validator for .safetensors model files.
#
# This work was made with AI, by MV2 of Munim, Inc.
#
# The safetensors format is widely described as "safe" because it carries no
# pickle / code-execution surface. That is true of *code execution*, but the
# header is still attacker-controlled data, and several hand-written loaders have
# trusted it without bounds checks, producing real denial-of-service and
# out-of-bounds bugs:
#
#   * A loader that reads the declared header length straight into file.read()
#     will attempt an attacker-sized allocation (CWE-789 / CWE-400). Example:
#     AUTOMATIC1111/stable-diffusion-webui issue #17498.
#   * A loader that trusts data_offsets without checking size == numel(shape) *
#     dtype_size, or without checking the range lies inside the data section,
#     can read or write out of bounds (CWE-125 / CWE-787). Example:
#     turboderp-org/exllamav2 issue #820.
#   * A loader that json.loads() a deeply nested header without a depth guard can
#     hit an uncaught RecursionError (CWE-674). Example: kornia issues #5218/#5248.
#
# This scanner reads ONLY the 8-byte length prefix and the JSON header. It never
# memory-maps or reads the tensor data section, never allocates the declared
# size, and guards its own JSON parse against the recursion bug it detects. A
# finding means the file would break or exhaust a naive loader and deserves
# review before use in CI; it is not proof of malice, and a clean result is not a
# guarantee of safety.
#
# Standard library only. No third-party dependencies.

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Optional

__version__ = "0.1.0"

# Official safetensors header size cap (bytes). The reference implementation
# rejects anything larger as HeaderTooLarge; a loader without this cap will try
# to allocate the declared size.
HEADER_CAP = 100_000_000

# Maximum JSON nesting depth we will allow before refusing to parse. CPython's
# default recursion limit is ~1000; a header nested past this is malformed and is
# exactly the uncontrolled-recursion DoS class.
DEPTH_CAP = 100

# safetensors dtype -> element size in bytes.
DTYPE_SIZES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1,
    "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
    "I32": 4, "U32": 4, "F32": 4,
    "I64": 8, "U64": 8, "F64": 8,
}

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    location: str
    cve: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "location": self.location,
            "cve": self.cve,
        }


def _max_bracket_depth(raw: bytes) -> int:
    """Return the maximum nesting depth of { and [ in the header bytes, ignoring
    brackets inside JSON strings. Computed by a single byte pass so we never hand
    attacker-controlled depth to json.loads()."""
    depth = 0
    maxd = 0
    in_str = False
    esc = False
    for b in raw:
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:  # backslash
                esc = True
            elif b == 0x22:  # closing quote
                in_str = False
            continue
        if b == 0x22:  # opening quote
            in_str = True
        elif b == 0x7B or b == 0x5B:  # { or [
            depth += 1
            if depth > maxd:
                maxd = depth
        elif b == 0x7D or b == 0x5D:  # } or ]
            if depth > 0:
                depth -= 1
    return maxd


def _numel(shape: Iterable[Any]) -> Optional[int]:
    """Product of shape dims, or None if any dim is not a non-negative int."""
    n = 1
    for d in shape:
        if not isinstance(d, int) or isinstance(d, bool) or d < 0:
            return None
        n *= d
    return n


def scan_file(path: str) -> list[Finding]:
    findings: list[Finding] = []
    loc = os.fspath(path)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return [Finding("SFT007", "LOW", "Unreadable file",
                        f"Could not stat file: {exc}", loc, "CWE-20")]

    if size < 8:
        return [Finding("SFT007", "LOW", "Not a safetensors file",
                        f"File is {size} bytes; a safetensors file needs at least "
                        "an 8-byte header-length prefix.", loc, "CWE-20")]

    with open(path, "rb") as fh:
        prefix = fh.read(8)
        n = struct.unpack("<Q", prefix)[0]

        if n == 0:
            return [Finding("SFT007", "LOW", "Empty header",
                            "Declared header length is 0; no JSON header present.",
                            loc, "CWE-20")]

        header_region = size - 8
        oversized = n + 8 > size
        if oversized:
            findings.append(Finding(
                "SFT001", "HIGH", "Declared header length exceeds file size",
                f"Header-length prefix declares {n} bytes, but only {header_region} "
                "bytes follow. A loader that reads this length directly into "
                "file.read()/allocation attempts an oversized read (allocation DoS).",
                loc, "CWE-789"))
        if n > HEADER_CAP:
            findings.append(Finding(
                "SFT002", "HIGH", "Header length over the 100MB cap",
                f"Header declares {n} bytes, above the {HEADER_CAP}-byte safetensors "
                "cap. A loader without this cap will allocate the declared size "
                "(HeaderTooLarge / allocation DoS).",
                loc, "CWE-400"))

        # Never allocate the attacker-declared size: cap the read.
        to_read = min(n, header_region, HEADER_CAP + 1)
        raw = fh.read(to_read)

    if len(raw) < n and not oversized:
        findings.append(Finding(
            "SFT007", "LOW", "Truncated header",
            f"Header claims {n} bytes but only {len(raw)} could be read.",
            loc, "CWE-20"))

    depth = _max_bracket_depth(raw)
    if depth > DEPTH_CAP:
        findings.append(Finding(
            "SFT006", "MEDIUM", "Excessively nested JSON header",
            f"Header nests {depth} levels deep (cap {DEPTH_CAP}). json.loads on this "
            "can raise an uncaught RecursionError (uncontrolled-recursion DoS). "
            "Parsing was skipped to avoid the same crash.",
            loc, "CWE-674"))
        return findings

    try:
        header = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        findings.append(Finding(
            "SFT007", "HIGH", "Malformed JSON header",
            f"Header is not valid JSON: {exc}. A loader whose error handling does "
            "not catch this will crash on the file.",
            loc, "CWE-20"))
        return findings
    except RecursionError:
        findings.append(Finding(
            "SFT006", "MEDIUM", "Excessively nested JSON header",
            "json.loads raised RecursionError on the header "
            "(uncontrolled-recursion DoS).", loc, "CWE-674"))
        return findings

    if not isinstance(header, dict):
        findings.append(Finding(
            "SFT007", "HIGH", "Header is not a JSON object",
            f"Top-level header JSON is {type(header).__name__}, not an object.",
            loc, "CWE-20"))
        return findings

    data_region = size - 8 - n  # bytes available for the tensor data section
    intervals: list[tuple[int, int, str]] = []

    for name, spec in header.items():
        if name == "__metadata__":
            continue
        tloc = f"{loc} [tensor {name!r}]"
        if not isinstance(spec, dict):
            findings.append(Finding(
                "SFT007", "MEDIUM", "Malformed tensor entry",
                f"Entry {name!r} is not an object.", tloc, "CWE-20"))
            continue

        dtype = spec.get("dtype")
        shape = spec.get("shape")
        offs = spec.get("data_offsets")

        if dtype not in DTYPE_SIZES:
            findings.append(Finding(
                "SFT008", "LOW", "Unknown dtype",
                f"Tensor {name!r} declares dtype {dtype!r}, not a known safetensors "
                "dtype.", tloc, "CWE-20"))

        if (not isinstance(offs, (list, tuple)) or len(offs) != 2
                or not all(isinstance(x, int) and not isinstance(x, bool)
                           for x in offs)):
            findings.append(Finding(
                "SFT003", "HIGH", "Malformed data_offsets",
                f"Tensor {name!r} has data_offsets {offs!r}; expected two integers.",
                tloc, "CWE-125"))
            continue

        begin, end = offs
        if begin < 0 or end < begin:
            findings.append(Finding(
                "SFT003", "HIGH", "Invalid data_offsets range",
                f"Tensor {name!r} has data_offsets [{begin}, {end}]; a negative or "
                "reversed range is malformed.", tloc, "CWE-125"))
            continue
        if end > data_region:
            findings.append(Finding(
                "SFT003", "HIGH", "data_offsets past end of data section",
                f"Tensor {name!r} ends at byte {end}, but the data section is only "
                f"{data_region} bytes. A loader trusting this reads out of bounds.",
                tloc, "CWE-125"))

        if isinstance(shape, (list, tuple)) and dtype in DTYPE_SIZES:
            numel = _numel(shape)
            if numel is None:
                findings.append(Finding(
                    "SFT003", "MEDIUM", "Invalid shape",
                    f"Tensor {name!r} has shape {shape!r} with a non-integer or "
                    "negative dimension.", tloc, "CWE-125"))
            else:
                expected = numel * DTYPE_SIZES[dtype]
                actual = end - begin
                if actual != expected:
                    findings.append(Finding(
                        "SFT005", "HIGH", "data_offsets size mismatch",
                        f"Tensor {name!r} spans {actual} bytes, but shape {shape} of "
                        f"{dtype} needs {expected}. A loader that allocates from "
                        "shape but copies from offsets (or vice versa) overflows.",
                        tloc, "CWE-787"))
        elif not isinstance(shape, (list, tuple)):
            findings.append(Finding(
                "SFT003", "MEDIUM", "Missing or malformed shape",
                f"Tensor {name!r} has shape {shape!r}; expected a list.",
                tloc, "CWE-125"))

        intervals.append((begin, end, name))

    # Contiguity / overlap check across tensors.
    intervals.sort()
    prev_end = 0
    prev_name = None
    for begin, end, name in intervals:
        if prev_name is not None and begin < prev_end:
            findings.append(Finding(
                "SFT004", "MEDIUM", "Overlapping tensor ranges",
                f"Tensor {name!r} starts at {begin}, inside tensor {prev_name!r} "
                f"which ends at {prev_end}. safetensors ranges must not overlap.",
                f"{loc} [tensor {name!r}]", "CWE-125"))
        elif prev_name is not None and begin > prev_end:
            findings.append(Finding(
                "SFT004", "LOW", "Non-contiguous tensor ranges",
                f"Gap between tensor {prev_name!r} (ends {prev_end}) and {name!r} "
                f"(starts {begin}). safetensors ranges should be contiguous.",
                f"{loc} [tensor {name!r}]", "CWE-20"))
        prev_end = max(prev_end, end)
        prev_name = name

    if not findings:
        findings.append(Finding(
            "SFT000", "INFO", "Well-formed safetensors header",
            "Header length, JSON, dtypes and data_offsets are internally "
            "consistent. safetensors carries no code-execution surface.",
            loc, ""))
    return findings


def scan_path(path: str) -> list[Finding]:
    """Scan a file, or walk a directory for *.safetensors files."""
    if os.path.isdir(path):
        out: list[Finding] = []
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith(".safetensors"):
                    out.extend(scan_file(os.path.join(root, fn)))
        return out
    return scan_file(path)


def _max_severity(findings: Iterable[Finding]) -> int:
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="safetensors-scan",
        description="Static integrity validator for .safetensors files. Never "
                    "reads the tensor data section or allocates the declared "
                    "header size. Made with AI by MV2 of Munim, Inc.")
    parser.add_argument("paths", nargs="*", help="files or directories to scan")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit findings as JSON")
    parser.add_argument("--fail-on", default="LOW",
                        choices=list(SEVERITY_ORDER),
                        help="exit 1 if any finding is at least this severity "
                             "(default LOW)")
    parser.add_argument("--version", action="version",
                        version=f"safetensors-scan {__version__}")
    args = parser.parse_args(argv)

    if not args.paths:
        parser.print_help()
        return 2

    all_findings: list[Finding] = []
    for p in args.paths:
        all_findings.extend(scan_path(p))

    if args.as_json:
        print(json.dumps([f.as_dict() for f in all_findings], indent=2))
    else:
        for f in all_findings:
            cve = f" [{f.cve}]" if f.cve else ""
            print(f"{f.severity:>8}  {f.rule}{cve}  {f.title}")
            print(f"          {f.detail}")
            print(f"          @ {f.location}")

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if _max_severity(all_findings) >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
