<!--
Copyright 2026 MV2, Munim, Inc.
Text licensed under CC BY 4.0; code under Apache-2.0.
-->
# Diffusers `model_index.json` class-instantiation scanner (`diffusers_manifest_scan.py`)

A static, no-execution detector for the **class-instantiation surface** exposed
by a Hugging Face Diffusers pipeline manifest, `model_index.json`. It reads the
manifest's JSON text only; it never imports, resolves, downloads, or executes
anything it finds.

Made with AI by MV2 of Munim, Inc. This is a detector that documents a Diffusers
loading behaviour so a reviewer can spot an unexpected import target — it is not
an exploit and makes no claim of a new CVE.

## The surface

A Diffusers pipeline repo is described by a flat JSON manifest. Besides the
pipeline class (`_class_name`) and the library version (`_diffusers_version`),
every sub-model is recorded as a two-element `[library_name, class_name]` list:

```json
{
  "_class_name": "StableDiffusionPipeline",
  "_diffusers_version": "0.31.0",
  "text_encoder": ["transformers", "CLIPTextModel"],
  "unet": ["diffusers", "UNet2DConditionModel"]
}
```

When `DiffusionPipeline.from_pretrained` loads such a repo, it resolves each
component's class in
[`get_class_obj_and_candidates`](https://github.com/huggingface/diffusers/blob/main/src/diffusers/pipelines/pipeline_loading_utils.py).
In the fallback branch that function calls `importlib.import_module(library_name)`
on the first element of the list **with no allowlist** — the `LOADABLE_CLASSES` /
`ALL_IMPORTABLE_CLASSES` tables are used only to enumerate candidate *parent*
classes, not to gate which module is imported. The only three libraries Diffusers
knows how to load a component from are **`diffusers`**, **`transformers`**, and
**`onnxruntime.training`** (the `LOADABLE_CLASSES` keys), so a component pointing
anywhere else is an unexpected import target a reader should see.

Separately, when `_class_name` is a **two-element list** rather than a plain
string, Diffusers treats element 0 as a local `<file>.py` and imports the class
named by element 1 from it — the custom-pipeline / remote-code path, analogous to
`trust_remote_code`.

## Rules

| rule | trigger | severity |
|------|---------|----------|
| `DMS001` | a component `[library, class]` whose `library` is outside `{diffusers, transformers, onnxruntime}` | HIGH, or **CRITICAL** if the library's top-level module is dangerous |
| `DMS002` | a list-form `_class_name` (custom pipeline loaded from a local `.py`) | HIGH |

A `DMS001` finding is escalated to **CRITICAL** when the library's top-level
module grants code execution, deserialization, imports, reflection, filesystem,
process, or network access (`os`, `subprocess`, `pickle`, `importlib`,
`builtins`, `socket`, `ctypes`, …). Disabled components recorded as
`[null, null]` are ignored.

## Usage

```bash
# walk a directory for model_index.json files, fail CI on any HIGH+ finding
python diffusers_manifest_scan.py ./pipeline_dir --fail-on HIGH

# scan one manifest, machine-readable output
python diffusers_manifest_scan.py model_index.json --json
```

A directory walk matches only files named `model_index.json`; an explicit file
argument is scanned whatever its name. Pure standard library — no diffusers, no
network. Exit code is non-zero when a finding at or above `--fail-on` is present.

## How it compares

Existing model/config scanners (ModelScan, picklescan, fickling, ModelAudit) do
not parse `model_index.json`, and MV2's own detectors cover other instantiation
surfaces — `config.json` `auto_map` (Hugging Face transformers `trust_remote_code`),
Hydra/OmegaConf `_target_` (`hydra_target_scan`), jsonargparse / LightningCLI
`class_path` (`jsonargparse_config_scan`), and MONAI `$`-eval (`hydra_target_scan`
HYD006). To the author's knowledge this is the first standalone static detector
for the Diffusers `model_index.json` component-import and custom-pipeline surface.

## Honest limits

- The real protection is only loading pipelines from a source you trust.
  **A clean scan guarantees nothing.**
- Naming an unusual library is not proof of malice — a legitimate pipeline may
  occasionally reference an uncommon helper. These findings are **leads for
  review**, not confirmed exploits.
- The dangerous-module list is a list-of-concern, not exhaustive; a HIGH finding
  on an unknown library can still be exploitable, and a CRITICAL one is not
  automatically so.
- This parses one manifest's JSON text. It does not download the referenced
  weights, follow the custom-pipeline `.py`, or confirm what any import does.
