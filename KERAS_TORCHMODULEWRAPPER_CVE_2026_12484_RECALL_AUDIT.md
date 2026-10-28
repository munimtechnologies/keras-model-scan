# Cross-coverage audit: the July-2026 Keras deserialization cluster (CVE-2026-12480 / -12481 / -12484) against keras-model-scan

**Scope:** source review of `keras_model_scan.py` and `pickle_model_scan.py` on `main`
(release v0.47.0) against three public Keras advisories and the Keras source of the
affected layer. No code was executed and no system was probed; this is a read of open
files plus public CVE/GHSA records. Work produced by AI agents in the name of MV2,
Munim, Inc.; see the note at the end.

## TL;DR

Three Keras deserialization CVEs landed in mid-2026, adjacent in number and all CWE-502 /
code-execution-on-load. Cross-mapped against keras-model-scan:

| CVE | vector | keras-model-scan verdict |
|---|---|---|
| **CVE-2026-12481** (8.8, GHSA-5gwj-m78q-7pq3) | `Lambda` layer code exec when `safe_mode` defaults to `None` (conflated with `False`) | **COVERED** — `KMS002` flags every `__lambda__` class_name statically, independent of any runtime `safe_mode` state. Already cited in the scanner docstring. |
| **CVE-2026-12480** (HDF5 virtual-dataset external-file mapping) | `.h5`/`.hdf5` virtual dataset points at an external file | **COVERED** — named in `SCANNER_COVERAGE_MATRIX.md` (HDF5 virtual-dataset row). |
| **CVE-2026-12484** (7.8, GHSA-v2w2-w228-c444) | `TorchModuleWrapper.from_config` runs `torch.load(..., weights_only=False)` on a base64 pickle stored in the layer config | **RECALL GAP** — flagged by no rule in the suite (verified). |

The first two confirm coverage. The third is a **genuine, source-verified recall gap**:
a malicious `.keras`/`.h5` file that wraps a pickle under `TorchModuleWrapper` passes the
entire scanner clean. This audit documents the gap, explains the structural reason, and
specs the fix (needs a compute slot). CVE-2026-12484 is **not** in
`model_file_cve_map.json` and `TorchModuleWrapper` appears nowhere in the scanner source
as of v0.47.0.

## The covered sibling: CVE-2026-12481 (Lambda, safe_mode=None)

CVE-2026-12481 is a logic bug in Keras's own guard: `_raise_for_lambda_deserialization()`
conflates `safe_mode=None` (unset/default) with `safe_mode=False` (explicitly disabled),
so a `Lambda` layer carrying marshalled bytecode executes on `from_config` /
`clone_model` / `layers.deserialize` outside a `SafeModeScope(True)`.

keras-model-scan does not depend on Keras's runtime guard at all. **KMS002** flags any
config node whose `class_name == "__lambda__"` as HIGH, because such a node "holds a
marshalled Python code object that runs when the layer is called" — the file is dangerous
regardless of which Keras version loads it or what `safe_mode` is in effect. The scanner
docstring already lists CVE-2026-12481 alongside CVE-2025-1550 for KMS002, so this CVE is
covered in the detector; it is merely **absent from the central `model_file_cve_map.json`**
(backfill item below).

## The gap: CVE-2026-12484 (TorchModuleWrapper), verified

### How the vector is stored in the file (Keras source)

`keras.layers.TorchModuleWrapper` (registered `@keras_export("keras.layers.TorchModuleWrapper")`,
module `keras.layers`) serializes its wrapped `torch.nn.Module` in `get_config()` via:

```python
buffer = io.BytesIO()
torch.save(self.module, buffer)                    # a pickle stream
config["module"] = base64.b64encode(buffer.getvalue()).decode(...)
```

and reconstructs it in `from_config()` via `torch.load(buffer, weights_only=False)` — full
pickle deserialization. The HiddenLayer advisory's PoC is exactly this shape:
`{"module": base64.b64encode(payload).decode()}` with a `__reduce__` gadget, passed to
`from_config`. So inside the model archive, the attacker-controlled pickle is **a base64
string value under the `"module"` key of a `TorchModuleWrapper` node in `config.json`** —
not a standalone pickle member of the archive.

### Why the scanner misses it (verified against both scanners)

1. **`keras_model_scan.py` config walk.** It reads `class_name`/`module` on each JSON node
   and flags only: `__lambda__` (KMS002), `function`/`class` *when `module` is outside the
   allowlist `{keras, keras_hub, keras_cv, keras_nlp}`* (KMS001), and `TFSMLayer` (KMS004);
   plus the raw-text `enable_unsafe_deserialization` (KMS003). A `TorchModuleWrapper` node
   has `class_name == "TorchModuleWrapper"` (none of the flagged values) and
   `module == "keras.layers"` (**inside** the allowlist, so KMS001 explicitly skips it).
   Nothing fires.
2. **`pickle_model_scan.py`.** It classifies globals inside *pickle streams* (archive
   members / `.pkl`). The malicious pickle here is base64-encoded text inside a JSON string;
   it is never presented to the pickle scanner as a stream, so none of PKL001/003/005 can see
   its opcodes or imports.

The two defenses are structurally orthogonal to this vector: the Keras config scanner knows
class_names but not base64-encoded pickle payloads, and the pickle scanner knows pickle
opcodes but is never handed this payload. A file wrapping a torch pickle under
`TorchModuleWrapper` therefore scans clean. This is the same shape as `Lambda` — a Keras
layer whose `from_config` is a code-execution sink — but for a class_name the walk does not
enumerate. It is a **detection miss**, not a severity under-rating.

## Fix spec (needs a compute slot; editing a live scanner = compute job)

1. **Add `TorchModuleWrapper` to the KMS class_name walk** as a dangerous deserializing
   layer, mirroring the Lambda treatment: a new rule (**KMS008**, HIGH, CWE-502,
   CVE-2026-12484) that fires when a config node has `class_name == "TorchModuleWrapper"`
   (any `module`), because its `from_config` performs `torch.load(weights_only=False)`.
   Flag by class_name and independently of `safe_mode`, exactly as KMS002 does for Lambda —
   the file is dangerous to any Keras < 3.15.0 / any loader with unsafe deserialization
   enabled, regardless of the ambient guard.
2. **Second-layer depth (optional, stronger):** when a `TorchModuleWrapper` node is found,
   base64-decode its `"module"` value and run the resulting bytes through the existing pickle
   opcode scanner, so the embedded gadget is classified (PKL001/005) rather than only the
   wrapper flagged. This also future-proofs against any other layer that base64-embeds a
   pickle in config.
3. **CVE-map backfill (clean, low-risk):** add **CVE-2026-12484** (GHSA-v2w2-w228-c444,
   CWE-502, keras, fixed 3.12.3 / 3.15.0) keyed to the new KMS008 rule; and backfill
   **CVE-2026-12481** (GHSA-5gwj-m78q-7pq3) onto KMS002 and **CVE-2026-12480** onto the HDF5
   virtual-dataset rule, since the detectors already cover them but the central map does not
   list them.
4. **Tests (sibling module, so the KMS008 logic can be unit-tested):** a `config.json` with a
   `TorchModuleWrapper` node → KMS008 HIGH; a benign `Dense`/`Conv2D` node → no finding; a
   `Lambda` node still → KMS002 (unchanged, no double-count).

Do **not** instead widen KMS001's allowlist logic to treat `keras.layers` as suspect — that
would mass-false-positive on every ordinary Keras model. The correct move is a specific
class_name flag, the same discipline KMS002/KMS004 already use.

## Prior art / why this is new

CVE-2026-12484 was disclosed 2026-07-19; HiddenLayer's advisory and the huntr/GHSA records
describe the exploit (base64 pickle in the `TorchModuleWrapper` `module` config key) and note
that "a model scanner would detect this pattern," but none publishes a scanner that actually
does, and no public source documents keras-model-scan's behaviour here. This is the first
cross-map of the July-2026 Keras cluster against this scanner. Its contribution is: (a) a
source-verified confirmation that the Lambda sibling CVE-2026-12481 is already caught by the
static class_name posture (KMS002), and (b) a source-verified demonstration that the
`TorchModuleWrapper` vector evades *both* the Keras config scanner (allowlisted module,
un-enumerated class_name) *and* the pickle scanner (payload is base64 text in JSON, never a
pickle stream) — a structural miss, with a class_name-flag + base64-decode fix. The recurring
toolkit theme holds: a verdict keyed on an enumerated set is only as complete as the set, and
the durable fix enumerates the *sink* (a deserializing layer) rather than the payload.

## Honest limits

- Verified by **source review** of open files (`keras_model_scan.py`, `pickle_model_scan.py`,
  Keras `torch_utils.py`) plus public CVE/GHSA/advisory records; **nothing was executed**.
  The claim "scans clean" is a reading of which rules can fire, not a scanner run — the fix
  and its tests will confirm it in a sealed sandbox when a compute slot frees.
- This audit does not re-prove the CVE is exploitable; it relies on the upstream advisory and
  reasons only about how this scanner classifies the file.
- It does not assess other scanners (e.g. modelscan); the base64-in-JSON structure suggests
  any pickle-stream-only scanner would also miss it, but that is noted, not verified here.
- Current Keras (3.15.1) fails closed in safe mode for this path; the scanner's job is to flag
  the dangerous file regardless, since vulnerable Keras versions and unsafe-deserialization
  opt-ins remain in the wild.

---

*This document was produced by AI agents working in the name of MV2, Munim, Inc. It is part
of the Apache-2.0 licensed `keras-model-scan` project; the prose may be reused under CC BY
4.0. It analyses a defensive scanner and public CVE records only — no exploit code, and no
live or third-party system was touched.*
