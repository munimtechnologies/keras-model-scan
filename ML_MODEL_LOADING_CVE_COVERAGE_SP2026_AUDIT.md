# Coverage audit: the 2026 IEEE S&P "(In)Security of Loading ML Models" CVE set

**Project:** keras-model-scan (Apache-2.0) · release v0.47.0 · audit dated 2026-10-28
**Made with AI agents in the name of MV2, Munim, Inc.** Source review only — no code was
executed for this audit; every rule statement below was read from the scanner source at
`main` and every CVE mechanism from the primary source.

## Why this audit

keras-model-scan already carries per-CVE and oss-security coverage docs
(`GGUF_OSS_SECURITY_2026_COVERAGE_AUDIT.md`, `MODEL_FILE_CVE_MAP.md`). What it did **not**
have is a coverage check against the single most authoritative academic account of the
attack class the tool exists to detect:

> **"On the (In)Security of Loading Machine Learning Models"**, to appear at the 2026 IEEE
> Symposium on Security and Privacy (S&P). Preprint: arXiv:2509.06703.

That paper responsibly disclosed **six 0-day arbitrary-code-execution vulnerabilities**
during model **loading** across Keras and skops, to which **seven CVE identifiers** were
assigned (the Lambda code-reuse vulnerability KV.2 received two). These are precisely the
"model file bites you on load" vectors this scanner targets, so the paper is the right
yardstick for a recall/attribution check.

This audit answers two separate questions and keeps them separate:

1. **Detection** — does some rule in the scanner fire on a file carrying each vulnerability?
2. **Attribution** — is each CVE recorded in the project's *central* CVE map
   (`model_file_cve_map.json`), so a user who greps for the CVE can find the rule?

## The paper's CVE set (primary source)

| CVE | Lib | Paper id | Mechanism (loading-time RCE) | Fixed |
|---|---|---|---|---|
| CVE-2025-1550 | Keras | KV.1 | `config.json` names an arbitrary module/callable (e.g. `subprocess.run`) resolved as a "layer" | 3.9 |
| CVE-2025-8747 | Keras | KV.2 | Lambda-layer **gadget reuse** → arbitrary file download | — |
| CVE-2025-9906 | Keras | KV.2 | Lambda layer re-enables unsafe deserialization to bypass the CVE-2025-1550 fix | — |
| CVE-2025-9905 | Keras | KV.3 | `safe_mode=True` **silently ignored** on the legacy HDF5 load path | 3.11.3 |
| CVE-2025-54413 | skops | SV.1 | `MethodNode` object-graph traversal reaches `__builtins__` (`eval`/`exec`) | 0.12.0 |
| CVE-2025-54412 | skops | SV.2 | `OperatorFuncNode` validate/execute mismatch invokes `operator.<name>` | 0.12.0 |
| CVE-2025-54886 | skops | SV.3 | `Card.get_model()` silent `joblib.load()` fallback on a non-ZIP file | 0.13.0 |

(The older `CVE-2024-3660`, the original Keras Lambda RCE, is **not** from this paper but is
the scanner's general Lambda citation; it is noted here only to avoid double-counting.)

## Result 1 — Detection: 7 / 7 (every mechanism fires a rule)

Verified by reading the rule source at `main`:

| CVE | Detecting rule(s) | How it fires |
|---|---|---|
| CVE-2025-1550 | **KMS001** (HIGH/MED), **KMS002** (HIGH) | KMS001 flags a `function`/`class` node whose module resolves outside the `{keras, keras_hub, keras_cv, keras_nlp}` allowlist — "the shape of the `subprocess.Popen` RCE gadget" |
| CVE-2025-8747 | **KMS002** (HIGH) | KMS002 is **flag-all**: any `__lambda__` node fires regardless of payload, so a gadget-reuse Lambda is caught |
| CVE-2025-9906 | **KMS003** (CRITICAL), KMS002 | KMS003 is a raw-text match for `enable_unsafe_deserialization` — "turns off safe mode from within its own load sequence" |
| CVE-2025-9905 | **HKL001** (HIGH), HKL003 (info) | `hdf5_keras_lambda_scan.py` flags any Lambda in a legacy HDF5 `model_config`; HKL003 flags a legacy HDF5 file even with no code marker, because "safe_mode does not protect .h5/.hdf5 loads in Keras <3.11.3" |
| CVE-2025-54413 | **SKP002** (HIGH) | `OperatorFuncNode`/`MethodNode` are in `RISKY_LOADERS` — flag-all on the loader type |
| CVE-2025-54412 | **SKP002** (HIGH) | same (`OperatorFuncNode`) |
| CVE-2025-54886 | **SKP001** (CRITICAL via `pickle`/`_pickle` module), **SKP010** (HIGH non-ZIP `.skops`) | SKP010 flags a `.skops` path that is not a valid ZIP — the exact precondition for the joblib fallback |

Detection rests heavily on **flag-all backstops** (every Lambda, every risky loader node):
behavior-agnostic by design, the same choice the Hydra `_target_` scanner makes at MEDIUM.
A clean scan still guarantees nothing, and a benign Lambda will also fire — that is the
intended trade for complete recall on a class where a denylist can always be bypassed.

## Result 2 — Attribution: 1 / 7 in the central CVE map

`model_file_cve_map.json` (read this run) contains, from the paper's set, **only
CVE-2025-1550** (and the non-paper CVE-2024-3660). The other six are **absent from the
central map**. Their citations are scattered, and one is missing entirely:

| CVE | In `model_file_cve_map.json`? | Cited anywhere in repo? |
|---|---|---|
| CVE-2025-1550 | **yes** (config.json callable) | yes |
| CVE-2025-9906 | no | yes — `keras_model_scan.py` KMS003 docstring |
| CVE-2025-9905 | no | yes — `hdf5_keras_lambda_scan.py` HKL001/HKL003 (GHSA-36rr-ww3j-vrjv) |
| CVE-2025-54412 | no | yes — `skops_scan.py` docstring |
| CVE-2025-54413 | no | yes — `skops_scan.py` docstring |
| CVE-2025-54886 | no | yes — `skops_scan.py` docstring |
| **CVE-2025-8747** | no | **no — uncited anywhere** (detected only via flag-all KMS002) |

So the gap is **not recall** — the scanner detects all seven. The gap is **traceability**:
a user, auditor, or CI policy that looks up one of these CVEs in the project's central map
(the file the `cve_map_lint.py` / `test_model_file_cve_map.py` tooling treats as the source
of truth) finds six of the seven missing, and CVE-2025-8747 is undocumented in the repo at
all. This is the same provenance lesson recorded for Hydra in
`HYDRA_TARGET_BLACKLIST_BYPASS_CVE_2026_106442_RECALL_AUDIT.md` (cite the root CVE, not only
what a single scanner happens to mention), now applied comprehensively to the canonical
academic reference for this whole attack class.

## Fix spec (for a code-editing run; edits live files → needs a sandbox slot)

Add the six missing paper CVEs to `model_file_cve_map.json`, each mapped to the detecting
rule already verified above, and add the one missing docstring citation:

1. `CVE-2025-8747` → **KMS002** ("Lambda-layer gadget reuse, arbitrary file download"); also
   add it to the KMS002 docstring in `keras_model_scan.py` alongside CVE-2025-1550 /
   CVE-2026-12481.
2. `CVE-2025-9906` → **KMS003** ("Lambda re-enables unsafe deserialization").
3. `CVE-2025-9905` → **HKL001** ("safe_mode silently ignored on legacy HDF5 load").
4. `CVE-2025-54412` → **SKP002** ("OperatorFuncNode validate/execute mismatch").
5. `CVE-2025-54413` → **SKP002** ("MethodNode object-graph traversal").
6. `CVE-2025-54886` → **SKP010** ("Card non-ZIP joblib fallback").

Each needs a reference URL (NVD/OSV/GHSA) and, where `cve_map_lint.py` requires it, a
one-line description; then `test_model_file_cve_map.py` should assert each CVE string
resolves to its rule. Because this edits live modules and their test, it belongs in a
compute job, not a docs-only commit.

## Honest limits

- **Source review, not execution.** No crafted `.keras`/`.h5`/`.skops` file was built or
  loaded for this audit. Detection claims rest on reading the rule predicates, not on
  observing them fire; the pending sandbox-backed PoC jobs remain the way to prove a hit.
- **Detection is behavior-agnostic.** The flag-all rules fire on benign Lambda layers and
  benign `OperatorFuncNode`s too; this audit measures recall, not precision.
- **Attribution ≠ recall.** The central-map omissions do not reduce what the tool catches;
  they reduce how easily a reader can trace a known CVE to the rule that covers it.
- **CVE-2025-8747 detection** is inferred from the paper placing it in the Lambda class
  (KV.2) that KMS002 flags unconditionally; the paper does not publish a minimal PoC file,
  so the mapping is by mechanism, not by a reproduced sample.

---
*keras-model-scan is Apache-2.0. This document is released under CC BY 4.0. Work produced by
AI agents acting for MV2, Munim, Inc.*
