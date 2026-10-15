# Model-file scanner coverage vs. the attack-vector taxonomy

*A vendor-neutral, cited coverage matrix. Made with AI by MV2 of Munim, Inc.
Data in this document is CC BY 4.0; the code in this repository is Apache-2.0.*

## What this is

Open-source machine-learning model files carry a surprisingly wide attack surface:
arbitrary code execution on deserialization, path traversal, template injection that
fires at inference time, decompression bombs, and more. Several free scanners exist,
but each one targets a different slice of the problem, and the only public
side-by-side comparisons are either **vendor-authored and narrow** (one tool vs. one
other, on a handful of files) or **academic and pickle-evasion-focused**. There is no
single vendor-neutral reference that maps the *whole* cross-format attack-vector
taxonomy — including the newest 2026 vectors — against *all* the common scanners.

This document is that matrix. It is meant to help a practitioner choosing scanners,
and to make the blind spots explicit.

## Important: this is a documentation review, not a benchmark

**The scanners were not executed here.** Each cell states what a tool's own
documentation, source, or linked advisory says it detects, as of October 2026. This
is deliberate and disclosed: it means every cell is traceable to a citation you can
check, but it is **not** an empirical pass/fail on a shared corpus. For executed
results, see Promptfoo's ModelAudit-vs-ModelScan run (11 files) and the academic
evasion papers cited below. The machine-readable form is
[`scanner_coverage.json`](scanner_coverage.json); a structural validator
([`coverage_matrix_lint.py`](coverage_matrix_lint.py)) keeps that file internally
consistent but asserts no security facts of its own.

Legend: **✓** documented detection · **~** partial / related / historically affected ·
**✗** in scope but not documented as covered · **–** out of scope (wrong format/layer) ·
**?** not determinable from public docs.

## The scanners

| id | tool | scope |
|----|------|-------|
| ps | picklescan (Hugging Face) | pickle family; hybrid denylist; used by Hugging Face |
| fk | fickling (Trail of Bits) | pickle only; AST / allowlist with dataflow |
| ms | ModelScan (Protect AI) | pickle, PyTorch, Keras H5, TF SavedModel; denylist of dangerous globals |
| ma | ModelAudit (Promptfoo) | widest set incl. config files, ONNX, SafeTensors, NumPy, PMML, archives |
| kms | keras-model-scan (MV2 / Munim, Inc.) | static, dependency-free, no-execution detectors across many formats |

## The matrix

| Attack vector (format) | ps | fk | ms | ma | kms |
|---|:--:|:--:|:--:|:--:|:--:|
| Pickle dangerous-import RCE — CWE-502 (pickle/.pt/.joblib) | ✓ | ✓ | ✓ | ✓ | ✓ |
| STACK_GLOBAL off-by-one scanner bypass — CVE-2025-71325 (pickle) | ~ | ~ | ~ | ? | ~ |
| Stealthy/evasive pickle — ShadowPickle class (pickle) | ✗ | ~ | ✗ | ? | ✗ |
| Keras Lambda-layer code execution — CWE-94 (.h5/.keras) | – | – | ✓ | ✓ | ✓ |
| .keras v3 config.json safe_mode bypass — CVE-2025-1550 (.keras) | – | – | ✗ | ? | ~ |
| .keras archive zip-slip — CWE-22 (.keras) | – | – | ✗ | ✓ | ✓ |
| TensorFlow SavedModel risky/custom ops (SavedModel) | – | – | ✓ | ~ | ✗ |
| ONNX external_data path traversal — CVE-2022-25882 (.onnx) | – | – | ✗ | ~ | ✓ |
| ONNX external_data unexpected-key injection — CVE-2026-34445 (.onnx) | – | – | ✗ | ? | ✓ |
| GGUF parser memory-safety, malformed counts (.gguf) | – | – | – | ? | ~ |
| GGUF chat_template SSTI, inference-time — CVE-2024-34359 class (.gguf) | – | – | ✗ | ? | ✓ |
| HF config chat_template SSTI — CVE-2024-34359 class (JSON/.jinja) | – | – | ✗ | ~ | ✓ |
| HF config auto_map / trust_remote_code pointer (config.json) | – | – | ✗ | ~ | ✓ |
| Archive decompression bomb — CWE-409 (zip/tar) | ✗ | – | ~ | ~ | ✓ |
| SafeTensors header/metadata abuse, DoS not RCE (.safetensors) | – | – | – | ~ | ~ |
| Embedded executable in model archive (archives) | – | – | ✗ | ✓ | ✗ |

## What the matrix shows

1. **Pickle RCE is the one vector everyone covers** — and the one where coverage is
   most deceptive. Every scanner flags a plain dangerous-import-plus-REDUCE pickle,
   but academic work shows the two most-used static scanners (picklescan, ModelScan)
   drop to **zero recall** against the ShadowPickle stealthy-pickle technique, and
   SOTA scanners sit at 7–63% F1 on the SafePickle benchmark. Fickling's AST approach
   is more robust but, per DITTO, security-critical operations can still be buried.
   *Static file scanning is necessary but not sufficient against a motivated attacker.*

2. **Breadth vs. depth splits the field.** ModelAudit is the broadest (config files,
   ONNX, SafeTensors, embedded executables, path traversal); ModelScan is focused and
   solid on the classic pickle/Keras/TF triad; picklescan and fickling are pickle
   specialists. No single scanner dominates every row.

3. **The newest vectors are the least covered.** The 2026 vectors — ONNX
   external_data *key* injection (CVE-2026-34445) and chat-template SSTI that fires at
   *inference* time, not load time (CVE-2024-34359 class) — are documented by almost
   no general-purpose scanner. keras-model-scan is included here because it ships
   standalone detectors for several of them; it is narrow (no TensorFlow, static-only,
   and shares every static scanner's evasion limitation), and it is listed on the same
   documentation-based footing as the others, not as a recommendation.

4. **Inference-time template injection is a category gap.** A GGUF or config
   chat_template can pass every *file* scanner and still execute a payload against
   every prompt in production. This is a layer most model-file scanners do not look at.

## Honest limits

- Documentation-based, not executed: a "✓" means *documented*, not *verified on your
  files*. Run the tools on your own corpus before relying on any cell.
- Tools change fast; versions and dates are in `scanner_coverage.json`. A "✗"/"?" may
  become "✓" in a later release.
- `kms` cells point at this repository's own detector docs; treat them with the same
  "verify before relying" caution as every other column.
- This is a coverage map, not a ranking. The right choice depends on your formats and
  threat model; many teams run more than one scanner plus a SafeTensors-only ingestion
  policy.

## Sources

- Promptfoo, *Open-Sourcing ModelAudit* — https://www.promptfoo.dev/blog/open-sourcing-modelaudit/
- Promptfoo, *ModelAudit vs ModelScan* — https://www.promptfoo.dev/blog/modelaudit-vs-modelscan/
- Protect AI, *modelscan model serialization attacks* — https://github.com/protectai/modelscan/blob/main/docs/model_serialization_attacks.md
- Huntr, *Hunting vulnerabilities in ML model file formats* — https://blog.huntr.com/hunting-vulnerabilities-in-machine-learning-model-file-formats
- GHSA-9gvj-pp9x-gcfr / CVE-2025-71325 (picklescan STACK_GLOBAL bypass) — https://github.com/advisories/GHSA-9gvj-pp9x-gcfr
- GHSA-ffxj-547x-5j7c / CVE-2022-25882 (ONNX external_data path traversal) — https://github.com/advisories/GHSA-ffxj-547x-5j7c
- GHSA-538c-55jv-c5g9 / CVE-2026-34445 (ONNX external_data key injection) — https://github.com/advisories/GHSA-538c-55jv-c5g9
- GHSA-56xg-wfcc-g829 / CVE-2024-34359 (chat-template SSTI) — https://github.com/advisories/GHSA-56xg-wfcc-g829
- CVE-2025-1550 (.keras safe_mode bypass) — https://nvd.nist.gov/vuln/detail/CVE-2025-1550
- *ShadowPickle: Evading ML Model Scanners* (arXiv 2607.17503) — https://arxiv.org/abs/2607.17503
- *DITTO: Context-aware Pickle-based Pre-Trained Model Scanner* (arXiv 2610.10735) — https://arxiv.org/abs/2610.10735
- *SafePickle* (arXiv 2602.19818) — https://arxiv.org/abs/2602.19818
- *PickleBall: Secure Deserialization of Pickle-based ML Models* (arXiv 2508.15987) — https://arxiv.org/abs/2508.15987
- *Models Are Codes* (arXiv 2409.09368) — https://arxiv.org/abs/2409.09368
