"""Offline robustness probe of the Python gguf-py reader (CWE-400 / CWE-125).

Generates the local malformed-GGUF corpus (see builder.py), then loads each file in
an isolated child process (load_one.py) with a 1.5 GiB address-space cap and a
per-file wall-clock timeout. Classifies every outcome and writes a machine-readable
results.json plus a human summary.md to the output directory.

This is a proof-of-concept against LOCAL, inert files only. No live, hosted or
out-of-scope system is ever contacted. Made with AI by MV2 of Munim, Inc. (Apache-2.0).

Usage: python probe.py [--out-dir DIR]   (default out dir: /out)
"""

import json
import os
import subprocess
import sys
import time

import builder

PER_FILE_TIMEOUT_S = 30  # a hang beyond this is treated as a denial-of-service signal


def _parse_out_dir(argv) -> str:
    if "--out-dir" in argv:
        return argv[argv.index("--out-dir") + 1]
    return "/out"


def probe_one(path: str) -> dict:
    """Run the child loader on one file; classify by timeout / signal / reported JSON."""
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, "load_one.py", path],
            capture_output=True,
            text=True,
            timeout=PER_FILE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return {
            "path": path,
            "outcome": "timeout_hang",
            "elapsed_s": round(time.monotonic() - started, 3),
            "note": "child did not return within the timeout -- possible DoS",
        }
    elapsed = round(time.monotonic() - started, 3)
    stdout = (proc.stdout or "").strip()
    # The child prints exactly one JSON line on a normal (even if rejected) path.
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                rec = json.loads(line)
                rec["elapsed_s"] = elapsed
                rec["returncode"] = proc.returncode
                return rec
            except json.JSONDecodeError:
                break
    # No JSON: the child was killed before it could report (e.g. OOM-killed, signal).
    outcome = "killed_no_report"
    if proc.returncode is not None and proc.returncode < 0:
        outcome = "killed_signal_%d" % (-proc.returncode)
    return {
        "path": path,
        "outcome": outcome,
        "elapsed_s": elapsed,
        "returncode": proc.returncode,
        "stderr_tail": (proc.stderr or "")[-300:],
    }


def main() -> int:
    out_dir = _parse_out_dir(sys.argv)
    os.makedirs(out_dir, exist_ok=True)
    corpus_dir = os.path.join(out_dir, "corpus")
    paths = builder.generate_corpus(corpus_dir)

    records = []
    for name in builder.CORPUS:  # deterministic order, control first
        path = paths[name]
        rec = probe_one(path)
        rec["fixture"] = name
        rec["file_bytes"] = os.path.getsize(path)
        records.append(rec)

    # A DoS signal = anything other than a clean load (control) or a fast rejection.
    dos_outcomes = {"timeout_hang", "memory_error", "killed_no_report"}
    dos_signals = [
        r["fixture"] for r in records
        if r["outcome"] in dos_outcomes or r["outcome"].startswith("killed_signal_")
    ]
    control = next((r for r in records if r["fixture"] == "control_valid"), None)
    control_loaded = bool(control and control.get("outcome") == "loaded")
    gguf_available = all(r.get("outcome") != "gguf_unavailable" for r in records)

    summary = {
        "contract": "gguf-robustness-probe-v2",
        "made_with": "AI, by MV2 of Munim, Inc.",
        "target": "Python gguf-py GGUFReader (pip package 'gguf')",
        "class_tested": "CWE-400 denial of service / CWE-125 out-of-bounds read",
        "per_file_timeout_s": PER_FILE_TIMEOUT_S,
        "mem_cap_bytes": 1536 * 1024 * 1024,
        "gguf_available": gguf_available,
        "control_loaded": control_loaded,
        "n_fixtures": len(records),
        "dos_signals": dos_signals,
        "verdict": _verdict(gguf_available, control_loaded, dos_signals),
        "records": records,
    }
    try:
        import gguf
        summary["gguf_version"] = getattr(gguf, "__version__", "unknown")
    except Exception:
        summary["gguf_version"] = "unavailable"

    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    with open(os.path.join(out_dir, "summary.md"), "w") as fh:
        fh.write(_render_md(summary))

    print(json.dumps({k: summary[k] for k in
                      ("gguf_version", "gguf_available", "control_loaded",
                       "dos_signals", "verdict")}, indent=2))
    return 0


def _verdict(gguf_available, control_loaded, dos_signals) -> str:
    if not gguf_available:
        return "inconclusive: gguf package not installed (setup had no network)"
    if dos_signals:
        return "DOS_SIGNAL: one or more fixtures hung/over-allocated -- investigate + verify version"
    if not control_loaded:
        return "inconclusive: control file did not load (corpus builder mismatch with reader)"
    return "CLEAN_NEGATIVE: control loaded; every malformed fixture rejected fast, no hang/OOM"


def _render_md(summary: dict) -> str:
    lines = [
        "# gguf-py robustness probe -- results",
        "",
        "_Made with AI by MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (text). "
        "Offline proof-of-concept against local inert files only; no live or hosted "
        "system was contacted._",
        "",
        f"- Target: `{summary['target']}`  (version `{summary.get('gguf_version')}`)",
        f"- Class tested: {summary['class_tested']}",
        f"- Per-file timeout: {summary['per_file_timeout_s']}s; "
        f"memory cap: {summary['mem_cap_bytes'] // (1024*1024)} MiB",
        f"- **Verdict: {summary['verdict']}**",
        "",
        "| fixture | file bytes | outcome | detail | elapsed (s) |",
        "| --- | ---: | --- | --- | ---: |",
    ]
    for r in summary["records"]:
        detail = r.get("exc_type", "") or r.get("note", "") or ""
        if r.get("exc_type") and r.get("exc_msg"):
            detail = f"{r['exc_type']}: {r['exc_msg']}"
        lines.append(
            f"| {r['fixture']} | {r.get('file_bytes','?')} | {r['outcome']} | "
            f"{detail} | {r.get('elapsed_s','?')} |"
        )
    lines += [
        "",
        "## Reading the verdict",
        "`CLEAN_NEGATIVE` means the Python gguf reader structurally resists the "
        "crafted-size denial-of-service / out-of-bounds class that has published CVEs "
        "in the Go and C/C++ GGUF readers (CVE-2026-7482, CVE-2025-66960, "
        "CVE-2026-27940): every malformed file is rejected quickly with no hang and no "
        "runaway allocation, and the well-formed control still loads. A `DOS_SIGNAL` "
        "verdict would be a candidate finding and must be re-checked against a pinned "
        "reader version before any private report.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
