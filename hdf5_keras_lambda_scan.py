"""hdf5_keras_lambda_scan.py -- static, no-execution detector for code-execution
risk in legacy Keras HDF5 (.h5 / .hdf5) model files.

Covers CVE-2025-9905 and CVE-2025-9906: Keras ``Model.load_model`` silently
ignores ``safe_mode=True`` when reading a legacy HDF5 model, so a ``Lambda``
layer whose function is stored as serialized (marshalled) Python code executes
on load even when the caller asked for safe mode. Fixed in Keras 3.11.3.
CWE-913 (Improper Control of Dynamically-Managed Code Resources).

Why a separate scanner: the existing ``keras_model_scan`` in this toolkit reads
the ``.keras`` v3 format, which is a ZIP archive carrying ``config.json``. The
legacy ``.h5``/``.hdf5`` format is an HDF5 *binary container* that stores the
architecture as a UTF-8 ``model_config`` attribute, and ``safe_mode`` does not
apply to it at all. That is a distinct file format and a distinct sink, so it
needs its own detector.

How it works (and what it does NOT do): this reads only the file BYTES. It never
imports h5py, never builds or loads the model, never executes any payload. It
confirms the HDF5 superblock signature, then locates the Keras configuration
text that legacy files embed as readable UTF-8 inside the container and reports
the markers that make ``load_model`` unsafe.

Honest limits: detection is marker-based over the raw bytes (the configuration
JSON is stored contiguously as text in the HDF5 file). It will not parse an
HDF5 file whose Keras config has been externally compressed/chunked such that
the JSON is not present as contiguous text; such a file is better handled by a
loader-based tool. Validate against real Keras-saved ``.h5`` files before
relying on it in CI. Made with AI by MV2 of Munim, Inc. Apache-2.0.
"""

import os
import re
import sys

__version__ = "0.1.0"

# HDF5 superblock signature (8 bytes), per the HDF5 File Format Specification.
HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"

# Only attempt the (cheap) text scan on files up to this size; above it we still
# confirm the signature and the config markers but keep the regex work bounded.
_MAX_TEXT_SCAN = 128 * 1024 * 1024  # 128 MiB

# Keras stores the architecture under one of these attribute names.
_CONFIG_NAMES = ("model_config", "training_config")


def _superblock_offsets(size):
    """HDF5 allows the superblock at byte offset 0 or at 512 * 2**k."""
    offsets = []
    off = 0
    while off < max(size, 1):
        offsets.append(off)
        off = 512 if off == 0 else off * 2
    return offsets


def looks_like_hdf5(data):
    """True if the HDF5 superblock signature appears at a legal offset."""
    n = len(HDF5_SIGNATURE)
    for off in _superblock_offsets(len(data)):
        if data[off:off + n] == HDF5_SIGNATURE:
            return True
    return False


def _decode(data):
    # latin-1 maps every byte to one code point, so marker offsets stay exact.
    return data.decode("latin-1", errors="replace")


def _snippet(text, match, width=48):
    start = max(0, match.start() - 8)
    end = min(len(text), match.end() + width)
    frag = text[start:end]
    return re.sub(r"[^\x20-\x7e]", ".", frag)


def _finding(rule, severity, cve, cwe, message, evidence):
    return {
        "rule": rule,
        "severity": severity,
        "cve": cve,
        "cwe": cwe,
        "message": message,
        "evidence": evidence,
    }


def scan_bytes(data, name="<bytes>"):
    """Return a list of findings for the given file bytes.

    An empty list means: not an HDF5 file, or an HDF5 file with no embedded
    Keras configuration (other scanners handle .keras/ZIP and raw weights).
    """
    findings = []
    if not looks_like_hdf5(data):
        return findings

    if len(data) > _MAX_TEXT_SCAN:
        # Still report the format advisory; keep heavy regex off huge weights.
        text = _decode(data[: _MAX_TEXT_SCAN])
    else:
        text = _decode(data)

    has_config = any(cname in text for cname in _CONFIG_NAMES)
    if not has_config:
        # HDF5 container that is not a Keras model (e.g. raw weights/dataset).
        return findings

    lambda_match = re.search(r'"class_name"\s*:\s*"Lambda"', text)
    function_match = re.search(r'"function(?:_type)?"\s*:', text)
    registered_match = re.search(r'"registered_name"\s*:\s*"[^"]+"', text)
    custom_module_match = re.search(
        r'"module"\s*:\s*"(?!keras)(?!builtins)[^"]+"', text
    )

    if lambda_match:
        if function_match:
            msg = (
                "Legacy HDF5 Keras model embeds a Lambda layer whose function is "
                "stored as serialized code. Keras <3.11.3 load_model executes it "
                "on load even with safe_mode=True (CVE-2025-9905 / CVE-2025-9906). "
                "Do not load this file from an untrusted source."
            )
        else:
            msg = (
                "Legacy HDF5 Keras model embeds a Lambda layer. safe_mode does not "
                "protect .h5/.hdf5 loads in Keras <3.11.3, so a Lambda function can "
                "execute arbitrary code on load (CVE-2025-9905)."
            )
        findings.append(
            _finding(
                "HKL001", "high", "CVE-2025-9905", "CWE-913",
                msg, _snippet(text, lambda_match),
            )
        )

    custom = registered_match or custom_module_match
    if custom:
        m = registered_match or custom_module_match
        findings.append(
            _finding(
                "HKL002", "medium", "", "CWE-502",
                "Legacy HDF5 Keras config references a non-core / custom "
                "registered object. Loading deserializes attacker-controllable "
                "classes and may require custom_objects; treat as unsafe from an "
                "untrusted source.",
                _snippet(text, m),
            )
        )

    if not findings:
        # It IS a legacy Keras HDF5 model with no code marker found, but the key
        # fact remains true and worth surfacing.
        findings.append(
            _finding(
                "HKL003", "info", "CVE-2025-9905", "CWE-913",
                "Legacy Keras HDF5 model (.h5/.hdf5). safe_mode=True does NOT "
                "protect this format in Keras <3.11.3; prefer the .keras v3 "
                "format and upgrade Keras. No code marker was found in the "
                "embedded config, but only load this file if you trust it.",
                "model_config present; no Lambda/custom-object marker",
            )
        )

    return findings


def scan_file(path):
    with open(path, "rb") as f:
        data = f.read()
    return scan_bytes(data, name=os.path.basename(path))


def _format(path, findings):
    lines = []
    for f in findings:
        cve = (" " + f["cve"]) if f["cve"] else ""
        lines.append(
            "{path}: [{rule}] {sev}{cve} {cwe} - {msg}".format(
                path=path, rule=f["rule"], sev=f["severity"].upper(),
                cve=cve, cwe=f["cwe"], msg=f["message"],
            )
        )
        lines.append("    evidence: " + f["evidence"])
    return "\n".join(lines)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python hdf5_keras_lambda_scan.py <file.h5> [more.h5 ...]")
        return 2
    worst = 0
    for path in argv:
        try:
            findings = scan_file(path)
        except OSError as exc:
            print("{path}: error: {exc}".format(path=path, exc=exc))
            worst = max(worst, 2)
            continue
        if findings:
            print(_format(path, findings))
            if any(f["severity"] == "high" for f in findings):
                worst = max(worst, 1)
        else:
            print("{path}: no HDF5 Keras code-execution markers found".format(path=path))
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
