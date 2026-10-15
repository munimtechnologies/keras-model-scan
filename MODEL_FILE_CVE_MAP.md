# Model-file CVE → static-detector map

A consolidated, machine-readable map from public **model-file parser and
deserialization advisories** to three things:

1. the **file field an attacker controls** that triggers the bug,
2. the **weakness class** (CWE), and
3. the **static, no-execution pre-load rule** in `model-file-scan`
   (this repo) that detects it *before any loader runs* — or an honest note
   that no static file scanner can.

It unifies five container families in one dataset: **pickle**, **keras**
(`.keras`), **safetensors** (sharded index), **ONNX**, and **GGUF**.

Data: [`model_file_cve_map.json`](./model_file_cve_map.json) (CC BY 4.0).
Code in this repo is Apache-2.0.

> Made with AI, by MV2 of Munim, Inc. Every identifier below was checked at its
> source; each entry records where and when in its `verified` field.

## Why this is new

Good static scanners exist — ModelScan (Protect AI), Fickling (Trail of Bits),
picklescan, and commercial tools — and advisory databases (OSV, GHSA, NVD) list
the CVEs. What did **not** exist in public is a single dataset that *joins* them:
for each advisory, the exact header field / opcode / JSON key that triggers it,
its CWE, and the concrete detection rule that flags it, across all five formats,
**with coverage gaps marked honestly**. A prior-art search (2026-10-14) for a
"CVE → detection-rule" mapping across pickle/safetensors/GGUF/ONNX returned only
scanners and format overviews, none publishing such a mapping.

The map doubles as a coverage audit of `model-file-scan` itself and a roadmap:
it names exactly which classes a rule already catches and which are still gaps.

## Coverage, stated honestly

| coverage | meaning |
|----------|---------|
| `full` | a shipped rule flags the exact malformed field/opcode |
| `partial` | a shipped rule flags a related signal, not the full condition |
| `class` | a shipped rule covers the weakness class; the citation is representative |
| `gap` | no shipped rule yet — a documented roadmap item |
| `out-of-scope` | no static *file* scanner can catch it (runs at inference, not load) |

### What is already covered (`full`)
- **keras**: Lambda-layer and crafted-`config.json` arbitrary code execution —
  CVE-2024-3660, CVE-2025-1550 (CWE-94).
- **pickle**: the STACK_GLOBAL scanner-bypass class — CVE-2025-71325 (PKL007);
  generic REDUCE/BUILD code execution (PKL001, CWE-502); Zip Slip (PKL030).
- **safetensors**: sharded-index `weight_map` path traversal —
  CVE-2026-65920 (diffusers), GHSA-f569-37c9-8pv7 (pytorch), CVE-2026-9856
  (transformers) — `safetensors_index_scan` STI001–STI006 (CWE-22).
- **GGUF**: the header integer-overflow cluster — CVE-2024-21825, CVE-2024-23496,
  CVE-2024-23605, CVE-2025-53630, CVE-2026-27940, CVE-2026-33298, CVE-2026-108955
  — `gguf_scan` GG003/GG004/GG006/GG009/GG011.

### Documented gaps (`gap`) — roadmap
- **ONNX `external_data` location traversal** — CVE-2022-25882 (onnx ≤ 1.12,
  `../../../etc/passwd` in a TensorProto `location`), CVE-2026-55832 (tract).
  This is the same CWE-22 shape as the safetensors `weight_map` traversal the
  tool already catches, applied to a different JSON/protobuf field. A dedicated
  `onnx_external_data_scan` rule is the clear next module.

### Partial
- **ONNX tar-slip** in `download_model_with_test_data` — CVE-2024-5187 — maps to
  the same Zip-Slip logic as PKL030 (tar analogue).
- **numpy f2py reduce gadget** — CVE-2025-71339 — caught by the dangerous-import /
  allowlist rules, but the gadget list is not exhaustive.

### Out of scope for static file scanning
- **GGUF chat-template SSTI**: a malicious Jinja chat template embedded in GGUF
  metadata executes during **inference** (template rendering), not at file load,
  so byte-level pre-load scanning cannot catch it. Named here only so readers are
  not misled into thinking a clean file scan covers it; the control is runtime
  template sandboxing.

## Honest limits

- A clean scan guarantees nothing: it checks the known fields above, not every
  possible malformed input, and not inference-time behaviour.
- The `gap` rows are **not** yet detected by this tool.
- Several GGUF and safetensors entries carry their facts forward from the
  already-shipped `gguf_cve_map.json` (run 13) and `weight_map_traversal.json`
  (runs 9–10); the five keras/pickle/ONNX CVEs new to this dataset were
  re-checked at OSV/GHSA on 2026-10-14.

## Use

```python
import json
m = json.load(open("model_file_cve_map.json"))
# every advisory a shipped rule already detects:
for e in m["entries"]:
    if e["detector"]["coverage"] == "full":
        print(e["id"], e["format"], e["detector"]["rule"])
```

Pair it with the scanners in this repo:

```bash
model-file-scan ./model-dir --fail-on HIGH   # routes by extension
gguf-scan ./my-model.gguf --fail-on HIGH
safetensors-index-scan ./my-model --fail-on HIGH
```
