#!/usr/bin/env python3
"""torch_module_wrapper_scan.py -- detect Keras ``TorchModuleWrapper`` code-execution
sinks in a serialized model configuration.

Keras 3's ``keras.layers.TorchModuleWrapper`` serializes its wrapped PyTorch module
by ``torch.save``-ing it to a buffer and base64-encoding the bytes into the layer
``config`` under the key ``"module"`` (see keras/src/utils/torch_utils.py).  When the
model is loaded, ``TorchModuleWrapper.from_config`` base64-decodes that string and
calls ``torch.load(buffer, weights_only=False)`` -- i.e. it unpickles
attacker-controllable bytes.  Loading a model file from an untrusted source therefore
risks arbitrary code execution.  This is CWE-502 (Deserialization of Untrusted Data).

Two public CVEs track this exact class:
  * CVE-2026-12484 (CVSS 7.8, keras 3.15.0): ``from_config`` does not enforce safe
    deserialization by default outside a ``SafeModeScope(True)`` context.
  * CVE-2025-49655 (CVSS 9.8, keras 3.11.0-3.11.2): the ``torch.load`` call bypassed
    even Keras "safe mode" (HiddenLayer disclosure).

The repo's main Keras config walk (keras_model_scan.py) enumerates class_names such as
Lambda (KMS002) and TFSMLayer (KMS004) but does NOT enumerate TorchModuleWrapper, and
its module ("keras.layers") is on the allowlist so KMS001 skips it; the base64 pickle
payload sits as text inside JSON so the pickle scanner never sees a stream.  A crafted
TorchModuleWrapper model therefore scans clean.  This standalone detector closes that
gap: it flags the sink class statically, independent of any runtime safe_mode, and
(when a payload is embedded) reports what the serialized blob looks like.

Static and read-only: it only parses JSON/zip structure and optionally walks pickle
opcodes with ``pickletools`` (which never executes the pickle).  It never imports keras
or torch and never unpickles anything.

Part of munimtechnologies/keras-model-scan.  Made with AI by MV2 of Munim, Inc.
Licensed under the Apache License, Version 2.0.
"""

import base64
import binascii
import io
import json
import sys
import zipfile

__version__ = "0.1.0"

_TARGET_CLASS = "TorchModuleWrapper"

# pickle opcodes that can drive code execution while a pickle is unpickled
_EXEC_OPCODES = frozenset({
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "INST", "OBJ",
    "NEWOBJ", "NEWOBJ_EX", "BUILD",
})


def _snippet(text, limit=180):
    """Return a short, single-line, redacted snippet for evidence."""
    if isinstance(text, bytes):
        text = text.decode("latin-1", "replace")
    text = " ".join(str(text).split())
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def _finding(rule, severity, cve, cwe, message, evidence):
    return {
        "rule": rule,
        "severity": severity,
        "cve": cve,
        "cwe": cwe,
        "message": message,
        "evidence": _snippet(evidence),
    }


def _is_target(name):
    """True if ``name`` is a TorchModuleWrapper class/registered name.

    Handles bare ("TorchModuleWrapper"), dotted ("keras.layers.TorchModuleWrapper")
    and Keras registered forms ("pkg>TorchModuleWrapper").
    """
    if not isinstance(name, str):
        return False
    tail = name.replace(">", ".").split(".")[-1]
    return tail == _TARGET_CLASS


def _looks_base64(value):
    """True if ``value`` is a str long enough to plausibly be a base64 payload."""
    if not isinstance(value, str):
        return False
    s = value.strip()
    if len(s) < 24:
        return False
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    )
    return all(c in allowed for c in s)


def _decode_base64(value):
    try:
        return base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None


def _pickle_opcodes(raw):
    """Return the set of opcode names in a pickle stream, or None if not a pickle."""
    try:
        import pickletools
    except ImportError:  # pragma: no cover
        return None
    names = set()
    try:
        for opcode, _arg, _pos in pickletools.genops(raw):
            names.add(opcode.name)
    except Exception:
        return names or None
    return names


def _describe_payload(raw):
    """Describe decoded payload bytes as a short string, or None if unremarkable."""
    if not raw:
        return None
    if raw[:4] == b"PK\x03\x04":
        return "torch.save zip archive (PK zip magic)"
    opcodes = _pickle_opcodes(raw)
    if opcodes is not None:
        hits = sorted(opcodes & _EXEC_OPCODES)
        if hits:
            return "pickle stream with code-exec opcodes: " + ", ".join(hits)
        if raw[:1] == b"\x80":
            return "pickle stream (PROTO opcode)"
    return None


def _walk(node, path, findings):
    """Recursively walk a parsed-JSON structure, flagging TorchModuleWrapper nodes."""
    if isinstance(node, dict):
        cls = node.get("class_name")
        reg = node.get("registered_name")
        if _is_target(cls) or _is_target(reg):
            where = path or "<root>"
            findings.append(_finding(
                "TMW001", "high", "CVE-2026-12484", "CWE-502",
                "Keras TorchModuleWrapper layer found: loading this model calls "
                "torch.load(weights_only=False) on an embedded pickle, enabling "
                "arbitrary code execution from an untrusted model file.",
                "{}: class_name={!r}".format(where, cls or reg),
            ))
            cfg = node.get("config")
            if isinstance(cfg, dict):
                payload = cfg.get("module")
                if _looks_base64(payload):
                    raw = _decode_base64(payload)
                    detail = _describe_payload(raw)
                    if detail is not None:
                        findings.append(_finding(
                            "TMW002", "high", "CVE-2026-12484", "CWE-502",
                            "TorchModuleWrapper config embeds a serialized payload "
                            "under 'module' that is passed to torch.load; " + detail,
                            "{}.config.module: {} bytes, {}".format(
                                where, len(raw), detail),
                        ))
        for key, value in node.items():
            child = "{}.{}".format(path, key) if path else str(key)
            _walk(value, child, findings)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _walk(value, "{}[{}]".format(path, i), findings)


def _iter_json_blobs(data):
    """Yield (name, parsed_json) for config/metadata JSON found in ``data``.

    Handles a ``.keras``/zip archive (reads each ``*.json`` member) and a raw
    config.json byte string.
    """
    if data[:4] == b"PK\x03\x04":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return
        for inner in zf.namelist():
            if not inner.endswith(".json"):
                continue
            try:
                blob = zf.read(inner)
                yield inner, json.loads(blob.decode("utf-8"))
            except (KeyError, ValueError, UnicodeDecodeError):
                continue
        return
    try:
        yield "<json>", json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return


def scan_bytes(data, name="<bytes>"):
    """Return a list of findings for the given model-file bytes."""
    findings = []
    for blob_name, parsed in _iter_json_blobs(data):
        base = blob_name if blob_name != "<json>" else ""
        _walk(parsed, base, findings)
    return findings


def scan_file(path):
    """Return a list of findings for the file at ``path``."""
    with open(path, "rb") as fh:
        return scan_bytes(fh.read(), name=path)


def _format(name, findings):
    lines = []
    for f in findings:
        lines.append("{}: {} [{}] {} ({}) -- {}".format(
            name, f["severity"].upper(), f["rule"], f["message"],
            f["cve"] or f["cwe"], f["evidence"]))
    return lines


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write(
            "usage: torch_module_wrapper_scan.py FILE [FILE ...]\n")
        return 2
    worst = 0
    for path in argv:
        try:
            findings = scan_file(path)
        except OSError as exc:
            sys.stderr.write("error: cannot read {}: {}\n".format(path, exc))
            worst = max(worst, 2)
            continue
        if not findings:
            print("{}: OK (no TorchModuleWrapper sink found)".format(path))
            continue
        for line in _format(path, findings):
            print(line)
        if any(f["severity"] == "high" for f in findings):
            worst = max(worst, 1)
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
