# ONNX `external_data` key scanner — catching the CVE-2026-34445 attribute-injection vector before load

`onnx_external_data_key_scan.py` is a standard-library, no-execution static check
that flags **unexpected keys** in an ONNX tensor's `external_data` metadata — the
precondition behind **CVE-2026-34445** — before any model loader runs.

*Made with AI by MV2 of Munim, Inc. Code: Apache-2.0. This document: CC BY 4.0.*

## The bug this detects

An `.onnx` file is a protobuf message with no code of its own. A tensor whose
`data_location` is `EXTERNAL` stores its weights in a separate file, named by a list
of key/value string pairs in the tensor's `external_data` field. The ONNX IR spec
recognises only four keys:

| key | meaning |
|-----|---------|
| `location` | filesystem path of the data file (required) |
| `offset`   | byte offset where the tensor's data begins |
| `length`   | number of bytes |
| `checksum` | SHA1 digest of the data file |

`onnx >= 1.21.0` additionally keeps `basepath` for save/load round-trips, giving the
allowlist it enforces, `_ALLOWED_EXTERNAL_DATA_KEYS = {location, offset, length,
checksum, basepath}`.

**Before 1.21.0**, `onnx`'s `ExternalDataInfo` loaded those entries by calling
`setattr(self, key, value)` for *every* key, **without validating it**. A crafted
model carrying an unexpected key — a Python dunder such as `__class__`, or any other
attribute name — could overwrite internal object state, crashing a model-serving
process at load time.

- **Advisory:** CVE-2026-34445 / GHSA-538c-55jv-c5g9
- **Package / fix:** `onnx` < 1.21.0, fixed in 1.21.0 (allowlist validation)
- **Class:** CWE-20 (Improper Input Validation), CWE-400, CWE-915
- **Realistic impact:** object-state corruption / denial of service (CVSS 8.6 HIGH)

Every identifier above is already public; nothing here is a zero-day.

## What the scanner does

It parses the protobuf wire format itself — **no `onnx` dependency** — and walks
every tensor in the model: graph initializers, sparse initializers, and tensors and
subgraphs nested inside node attributes (recursively). For each tensor it reads the
`external_data` key strings and reports any key outside the recognised set.

| rule | severity | meaning |
|------|----------|---------|
| OEK001 | HIGH | `external_data` carries a key not in `{location, offset, length, checksum, basepath}` — the CVE-2026-34445 attribute-injection vector. Dunder keys are called out as `attribute-injection`. |
| OEK000 | ERROR | the file could not be parsed as an ONNX protobuf |

## Usage

```bash
# one file, or a whole directory of .onnx files
python onnx_external_data_key_scan.py ./model-dir --fail-on HIGH
python onnx_external_data_key_scan.py model.onnx --json
```

Exit code is non-zero when a finding at or above `--fail-on` is present, so it drops
into CI as a gate.

## Honest limits

- This is **detection, not exploitation**. The scanner reads only key strings; it
  never materialises, loads or executes anything, and touches no external file.
- A **clean scan guarantees nothing** — it means only that no unexpected
  `external_data` key was found. Other model-file risks (path traversal in
  `location`, pickle payloads in other formats, custom operators) are out of scope
  here; see the companion `onnx_external_data_scan.py` (path traversal) and the
  cross-format `model_file_cve_map.json`.
- The right fix remains upgrading `onnx` to >= 1.21.0. A static gate helps when you
  ingest third-party models and cannot guarantee every consumer is patched.

## Prior art (why this is worth shipping)

Existing model scanners (ModelScan, ModelAudit) check ONNX for custom operators and
for `external_data` **path traversal**, but — as of this writing — none flag
*unexpected `external_data` keys*, which is the distinct mechanism CVE-2026-34445
abuses. This standalone, dependency-free detector appears to be the first to target
that exact vector. Stated as *plausibly first* — if you know of prior art, please
open an issue.
