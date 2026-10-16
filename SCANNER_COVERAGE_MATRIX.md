# Model-file scanner coverage vs. the attack-vector taxonomy

*A vendor-neutral, cited coverage matrix. Made with AI by MV2 of Munim, Inc.
Data in this document is CC BY 4.0; the code in this repository is Apache-2.0.*

## What this is

Open-source machine-learning model files carry a surprisingly wide attack surface:
arbitrary code execution on deserialization, path traversal, template injection that
fires at inference time, decompression bombs, configuration keys that choose which
class a loader builds, and more. Several free scanners exist, but each one targets a
different slice of the problem, and the only public side-by-side comparisons are
either **vendor-authored and narrow** (one tool vs. one other, on a handful of files)
or **academic and pickle-evasion-focused**. There is no single vendor-neutral
reference that maps the *whole* cross-format attack-vector taxonomy — including the
newest 2026 vectors — against *all* the common scanners.

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
consistent but asserts no security facts of its own, and
[`test_scanner_coverage_data.py`](test_scanner_coverage_data.py) checks that every
row of the table below matches the JSON cell for cell.

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
| .keras v3 config.json safe_mode bypass — CVE-2025-1550 (.keras) | – | – | ✗ | ~ | ~ |
| .keras archive zip-slip — CWE-22 (.keras) | – | – | ✗ | ✓ | ✓ |
| TensorFlow SavedModel risky/custom ops (SavedModel) | – | – | ✓ | ✓ | ✗ |
| ONNX external_data path traversal — CVE-2022-25882 (.onnx) | – | – | ✗ | ✓ | ✓ |
| ONNX external_data unexpected-key injection — CVE-2026-34445 (.onnx) | – | – | ✗ | ? | ✓ |
| GGUF parser memory-safety, malformed counts (.gguf) | – | – | – | ~ | ~ |
| GGUF chat_template SSTI, inference-time — CVE-2024-34359 class (.gguf) | – | – | ✗ | ✓ | ✓ |
| HF config chat_template SSTI — CVE-2024-34359 class (JSON/.jinja) | – | – | ✗ | ✓ | ✓ |
| HF config auto_map / trust_remote_code pointer (config.json) | – | – | ✗ | ~ | ✓ |
| Archive decompression bomb — CWE-409 (zip/tar) | ✗ | – | ~ | ✓ | ✓ |
| SafeTensors header/metadata abuse, DoS not RCE (.safetensors) | – | – | – | ✓ | ~ |
| Embedded executable in model archive (archives) | – | – | ✗ | ✓ | ✗ |
| Hydra/OmegaConf `_target_` instantiation — CVE-2025-23304, CVE-2026-22584, CVE-2026-68508 (YAML/JSON config, .nemo) | – | – | ✗ | ~ | ✓ |
| pyannote `pipeline.name` class reference — issues #2000/#2019, unfixed (config.yaml) | – | – | ✗ | ~ | ✓ |
| sentence-transformers module `type` outside the package — CVE-2026-68770 (modules.json) | – | – | ✗ | ~ | ✓ |
| jsonargparse / LightningCLI `class_path` instantiation — PR #959 class (YAML/JSON config) | – | – | ✗ | ~ | ✓ |
| Lightning checkpoint `_instantiator` / `_class_path` hparams — CVE-2026-58659 (.ckpt) | ✗ | ✗ | ✗ | ? | ~ |
| Python object tags in YAML metadata — CVE-2026-10036 (CKPT.yaml/hyperparams.yaml) | – | – | – | ~ | ✓ |
| MONAI bundle `$` Python-eval expressions & `_target_` — CVE-2026-100840 (bundle JSON/YAML) | – | – | ✗ | ~ | ✓ |
| Diffusers `model_index.json` component import & custom-pipeline `_class_name` — no CVE, by-design remote-code adjacency (model_index.json) | – | – | ✗ | ~ | ✓ |

## What the matrix shows

1. **Pickle RCE is the one vector everyone covers** — and the one where coverage is
   most deceptive. Every scanner flags a plain dangerous-import-plus-REDUCE pickle,
   but academic work shows the two most-used static scanners (picklescan, ModelScan)
   drop to **zero recall** against the ShadowPickle stealthy-pickle technique, and
   SOTA scanners sit at 7–63% F1 on the SafePickle benchmark. Fickling's AST approach
   is more robust but, per DITTO, security-critical operations can still be buried.
   *Static file scanning is necessary but not sufficient against a motivated attacker.*

2. **Breadth vs. depth splits the field.** ModelAudit is the broadest by a wide
   margin: its scanner reference documents ONNX external-data traversal, GGUF and
   config chat-template SSTI (CVE-2024-34359), archive bombs, SafeTensors header
   checks and embedded executables. ModelScan is focused and solid on the classic
   pickle/Keras/TF triad; picklescan and fickling are pickle specialists. No single
   scanner dominates every row.

3. **The newest file-format vectors are the least covered.** ONNX external_data
   *key* injection (CVE-2026-34445) has no documented rule in any general-purpose
   scanner reviewed here. keras-model-scan is included because it ships standalone
   detectors for several of these; it is narrow (no TensorFlow, static-only, and
   shares every static scanner's evasion limitation), and it is listed on the same
   documentation-based footing as the others, not as a recommendation.

4. **Config-driven class instantiation is a category gap.** Seven rows above cover
   configuration keys and expressions that name a Python callable for a loader to
   import, build, or evaluate: Hydra `_target_`, pyannote `pipeline.name`,
   sentence-transformers `modules.json` `type`, jsonargparse `class_path`, Lightning's
   `_instantiator` / `_class_path` checkpoint hyper-parameters, MONAI bundle configs,
   and the Diffusers `model_index.json` component list. MONAI (CVE-2026-100840,
   ≤ 1.6.0) is a double case: its bundle engine both resolves `_target_` to any
   importable callable *without* an allowlist **and** evaluates any string beginning
   with `$` as a Python expression through `eval()` (CWE-95), so `monai.bundle.load` /
   `run` on an untrusted bundle runs arbitrary code — the `$`-expression sink is a
   mechanism distinct from every class-naming key. The Diffusers case is a by-design
   adjacency rather than a CVE: `DiffusionPipeline.from_pretrained` resolves each
   component's `[library, class]` through `importlib.import_module(library)` with no
   allowlist (only `diffusers`, `transformers` and `onnxruntime.training` are known
   load targets), and a list-form `_class_name` loads a local custom-pipeline `.py` —
   the same trust boundary as `trust_remote_code`. These run code **even when the
   weights are SafeTensors**, and the Lightning case bypasses `weights_only=True`
   because the payload is a plain string, not a pickle import. None of the pickle
   scanners documents these keys; ModelAudit's generic config-pattern scanner is the
   closest documented coverage. The real fix is in the loaders (allowlists, explicit
   trust flags, upgrades) and in only loading from sources you trust, not in scanners.

5. **YAML's own type system is a second config-layer gap.** The YAML-tags row covers a
   different mechanism from the class-naming keys above: YAML *tags*. Under PyYAML's
   unsafe loader, `!!python/object/apply:os.system` runs code the instant the file is
   parsed, and HyperPyYAML's `!new:` / `!apply:` shorthand (SpeechBrain
   `hyperparams.yaml`) constructs or calls any importable target by design.
   SpeechBrain's `CKPT.yaml` parsing was a live instance of this —
   **CVE-2026-10036** (fixed 1.1.1), where a python tag in any checkpoint's
   `CKPT.yaml` ran code during candidate enumeration even if that checkpoint was
   never selected. It is not a one-off: **CVE-2026-84202** is the same mechanism in
   ModelScope, which parsed model configuration files with PyYAML's unsafe
   `yaml.Loader` (CWE-502). No reviewed general-purpose scanner documents a rule for
   these tags; ModelAudit's YAML pattern matching is the nearest. The real fix is
   `yaml.safe_load`, an upgrade, and loading `hyperparams.yaml` only from trusted
   sources.

## Honest limits

- Documentation-based, not executed: a "✓" means *documented*, not *verified on your
  files*. Run the tools on your own corpus before relying on any cell.
- Tools change fast; versions and dates are in `scanner_coverage.json`. A "✗"/"?" may
  become "✓" in a later release. The ModelAudit column was re-checked against its
  scanner reference on 2026-10-16, which moved several of its cells up.
- `kms` cells point at this repository's own detector docs; treat them with the same
  "verify before relying" caution as every other column. Its config-instantiation,
  YAML-tag, MONAI-bundle and Diffusers-manifest detectors read config text on disk;
  they do not unpack `.nemo` or `.ckpt` files or follow a custom-pipeline `.py`, and
  the MONAI `$`-expression rule flags the eval sink statically — it never evaluates
  the expression.
- This is a coverage map, not a ranking. The right choice depends on your formats and
  threat model; many teams run more than one scanner plus a SafeTensors-only ingestion
  policy.

## Sources

- Promptfoo, *Open-Sourcing ModelAudit* — https://www.promptfoo.dev/blog/open-sourcing-modelaudit/
- Promptfoo, *ModelAudit vs ModelScan* — https://www.promptfoo.dev/blog/modelaudit-vs-modelscan/
- Promptfoo, *ModelAudit scanners reference* — https://www.promptfoo.dev/docs/model-audit/scanners/
- Protect AI, *modelscan model serialization attacks* — https://github.com/protectai/modelscan/blob/main/docs/model_serialization_attacks.md
- Huntr, *Hunting vulnerabilities in ML model file formats* — https://blog.huntr.com/hunting-vulnerabilities-in-machine-learning-model-file-formats
- GHSA-9gvj-pp9x-gcfr / CVE-2025-71325 (picklescan STACK_GLOBAL bypass) — https://github.com/advisories/GHSA-9gvj-pp9x-gcfr
- GHSA-ffxj-547x-5j7c / CVE-2022-25882 (ONNX external_data path traversal) — https://github.com/advisories/GHSA-ffxj-547x-5j7c
- GHSA-538c-55jv-c5g9 / CVE-2026-34445 (ONNX external_data key injection) — https://github.com/advisories/GHSA-538c-55jv-c5g9
- GHSA-56xg-wfcc-g829 / CVE-2024-34359 (chat-template SSTI) — https://github.com/advisories/GHSA-56xg-wfcc-g829
- CVE-2025-1550 (.keras safe_mode bypass) — https://nvd.nist.gov/vuln/detail/CVE-2025-1550
- Unit 42, *Remote Code Execution With Modern AI/ML Formats and Libraries* (NeMo CVE-2025-23304, Uni2TS CVE-2026-22584, FlexTok) — https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/
- GHSA-2cp2-2r3c-7p7r / CVE-2026-68508 (hydra-core `instantiate()` with untrusted config, fixed 1.3.4) — https://github.com/advisories/GHSA-2cp2-2r3c-7p7r
- pyannote-audio issues #2000 and #2019 (`Pipeline.from_pretrained` class instantiation) — https://github.com/pyannote/pyannote-audio/issues/2000 , https://github.com/pyannote/pyannote-audio/issues/2019
- GHSA-jhr6-gm9c-rqjv / CVE-2026-68770 (sentence-transformers `modules.json`) — https://github.com/advisories/GHSA-jhr6-gm9c-rqjv
- jsonargparse PR #959 (import-path denylist for `class_path`) — https://github.com/mauvilsa/jsonargparse/pull/959
- GHSA-qqmf-gpg7-g8gw / CVE-2026-58659 (Lightning checkpoint `_instantiator`, fixed 2.6.6) — https://github.com/advisories/GHSA-qqmf-gpg7-g8gw
- CVE-2026-10036 (SpeechBrain arbitrary code execution via `CKPT.yaml` parsing, fixed 1.1.1) — https://vulncheck.com/advisories/speechbrain-arbitrary-code-execution-via-ckpt-yaml-parsing
- CVE-2026-84202 (ModelScope unsafe `yaml.Loader` on model config files, CWE-502) — https://nvd.nist.gov/vuln/detail/CVE-2026-84202
- GHSA-873f-pvrv-4x83 / CVE-2026-100840 (MONAI bundle RCE via `_target_` without allowlist and `$` → `eval()`, ≤ 1.6.0, CWE-95) — https://github.com/advisories/GHSA-873f-pvrv-4x83
- Diffusers `get_class_obj_and_candidates` component import (`importlib.import_module` on a `[library, class]` with no allowlist; `LOADABLE_CLASSES` = diffusers / transformers / onnxruntime.training) — https://github.com/huggingface/diffusers/blob/main/src/diffusers/pipelines/pipeline_loading_utils.py
- HyperPyYAML README, security note (`!new:` / `!apply:` allow arbitrary code) — https://github.com/speechbrain/HyperPyYAML
- *ShadowPickle: Evading ML Model Scanners* (arXiv 2607.17503) — https://arxiv.org/abs/2607.17503
- *DITTO: Context-aware Pickle-based Pre-Trained Model Scanner* (arXiv 2610.10735) — https://arxiv.org/abs/2610.10735
- *SafePickle* (arXiv 2602.19818) — https://arxiv.org/abs/2602.19818
- *PickleBall: Secure Deserialization of Pickle-based ML Models* (arXiv 2508.15987) — https://arxiv.org/abs/2508.15987
- *Models Are Codes* (arXiv 2409.09368) — https://arxiv.org/abs/2409.09368
