<!--
Copyright 2026 MV2, Munim, Inc.
Text licensed under CC BY 4.0; code under Apache-2.0.
-->
# Diffusers repository remote-code scanner (`diffusers_remote_code_scan.py`)

A static, no-execution detector for **auto-executing Python inside a Hugging
Face Diffusers pipeline repository** — the "FaceHugger" remote-code surface. It
reads file *names* only; it never imports, parses, resolves, downloads, or
executes anything it finds.

Made with AI by MV2 of Munim, Inc. This detector documents a published Diffusers
loading behaviour so a reviewer can spot an unexpected, auto-loadable Python
module in an untrusted pipeline. It is not an exploit and claims no new CVE.

## The surface

A Diffusers pipeline repository is normally just weights plus JSON/text
configuration. But `DiffusionPipeline.from_pretrained` can import and run a
**Python module that lives inside the repository**, and two 2026 advisories —
collectively **FaceHugger** (Zafran Security; disclosed July 2026), both fixed in
diffusers **0.38.0** — show this happens *even when the caller passes
`trust_remote_code=False`*:

- **CVE-2026-44827** (CVSS 8.8, CWE-94). When `from_pretrained` is called with
  **no** `custom_pipeline` argument, the unset value stringifies to `"None"` and
  diffusers builds the literal module filename **`None.py`**; an existence check
  then loads that file from the target repo without treating it as untrusted
  custom code. A repository that merely *contains a file named `None.py`* runs
  its code on a plain, default `from_pretrained()` call. `None.py` is an exact
  exploit fingerprint — no legitimate repository ships a module by that name.
- **CVE-2026-44513** (CVSS 8.8, CWE-94). The `custom_pipeline` /
  local-custom-components path imports a local `<name>.py` from the repository.
  Before 0.38.0 the trust gate ran at the *download* call site, not at the
  *module-load* call site (a TOCTOU split), so local Python executed without
  validation. (The sibling race, **CVE-2026-45804**, flips the config between
  two HTTP calls and is not statically detectable from repository contents, so
  this tool does not attempt it.)

This is a different surface from
[`diffusers_manifest_scan.py`](DIFFUSERS_MANIFEST_SCAN.md), which reads the
`model_index.json` *text* (component import targets and the list-form
`_class_name` custom-pipeline reference). This tool looks at the repository's
*files* for Python that diffusers can auto-load.

## Rules

| rule | trigger | severity |
|------|---------|----------|
| `DRC001` | a file named exactly `None.py` (the CVE-2026-44827 fingerprint), found anywhere in the tree | **CRITICAL** |
| `DRC002` | any other `*.py` module in a Diffusers pipeline repository (the directory that holds `model_index.json`) | HIGH |

`None.py` is flagged wherever it appears because the name is effectively never
legitimate. `DRC002` requires a `model_index.json` in the **same** directory, so
ordinary Python projects do not light up; it is the `custom_pipeline` /
local-custom-components surface and is a **review signal**, not a verdict.

## Usage

```bash
# walk a downloaded pipeline directory; fail CI on any HIGH+ finding
python diffusers_remote_code_scan.py ./my_pipeline_dir --fail-on HIGH

# inspect one file, machine-readable output
python diffusers_remote_code_scan.py None.py --json
```

A directory argument is walked; `None.py` is reported anywhere, other `*.py`
only when a `model_index.json` sits beside it. An explicit file argument is
inspected whatever its name (`None.py` → `DRC001`, any other `.py` → `DRC002`).
Pure standard library — no diffusers, no network. Exit code is non-zero when a
finding at or above `--fail-on` is present.

## How it compares

Existing model/config scanners (ModelScan, picklescan, fickling, ModelAudit) do
not treat a loose `.py` in a model repository as an auto-execution signal, and
MV2's own `diffusers_manifest_scan` reads `model_index.json` text, not the
repository's Python files. To the author's knowledge this is the first
standalone static detector for the Diffusers repository-embedded remote-code
surface (the `None.py` default-path case and local custom-component modules).

## Honest limits

- A `*.py` next to `model_index.json` is **not proof of malice**: some
  legitimate community pipelines genuinely ship a `pipeline.py`. `DRC002` is a
  lead for review.
- The real fix is upgrading to diffusers **≥ 0.38.0** and only loading
  pipelines from a source you trust. **A clean scan guarantees nothing.**
- It reads file names, not file contents: it does not confirm what any module
  does. `DRC002` flags `*.py` in the repository root (beside `model_index.json`);
  Python nested in unrelated sub-directories is not flagged, while a `None.py` is
  flagged wherever it appears.
- It does not cover the TOCTOU race (CVE-2026-45804), which is not visible in a
  static snapshot of repository files.

## Sources

- Zafran Labs, *FaceHugger: vulnerabilities in Hugging Face Diffusers* —
  https://www.zafran.io/resources/facehugger-vulnerabilities-in-hugging-face-diffusers-open-door-to-supply-chain-attacks-on-enterprise-ai
- Cloud Security Alliance, *HuggingFace Diffusers FaceHugger RCE* —
  https://labs.cloudsecurityalliance.org/research/csa-research-note-huggingface-diffusers-facehugger-rce-20260/
- CVE-2026-44513 (custom_pipeline / local custom components) —
  https://nvd.nist.gov/vuln/detail/CVE-2026-44513
- CVE-2026-44827 (`None.py` default-path bypass) —
  https://nvd.nist.gov/vuln/detail/CVE-2026-44827
- CVE-2026-45804 (TOCTOU race; out of scope for this static tool) —
  https://github.com/advisories/GHSA-7wx4-6vff-v64p
- Diffusers 0.38.0 release (fixes all three) —
  https://github.com/huggingface/diffusers/releases/tag/v0.38.0
