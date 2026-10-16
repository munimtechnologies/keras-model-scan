<!--
Copyright 2026 MV2, Munim, Inc.
Text licensed under CC BY 4.0; code under Apache-2.0.
-->
# YAML Python-tag scanner (`yaml_python_tag_scan.py`)

A static, no-execution detector for **Python object tags in YAML model metadata**:
PyYAML's `!!python/...` tags and HyperPyYAML's `!new:` / `!apply:` / `!name:` /
`!module:` shorthand used by SpeechBrain `hyperparams.yaml`. It reads YAML text
only; it never loads it with a YAML library, and never imports or calls anything
it finds.

Made with AI by MV2 of Munim, Inc. Everything named here is already public; this
is a detector, not an exploit.

## The vector

- **PyYAML python tags.** Under `yaml.unsafe_load` / `yaml.Loader`,
  `!!python/object/apply:os.system ["id"]` calls `os.system("id")` while the
  file loads. `!!python/object/new:` and `!!python/object:` construct objects;
  `!!python/name:` and `!!python/module:` import and reference code.
  `yaml.safe_load` rejects all of them.
- **CVE-2026-10036** (SpeechBrain < 1.1.1, CVSS 8.8, CWE-502, fixed in 1.1.1):
  `Checkpointer.recover_if_possible()` parsed every `CKPT.yaml` under the
  checkpoint directory with PyYAML's unsafe loader while enumerating candidates,
  so a python tag in any `CKPT.yaml` ran code even if that checkpoint was never
  selected.
- **HyperPyYAML (by design).** SpeechBrain's `from_hparams` loads
  `hyperparams.yaml`, whose `!new:` / `!apply:` tags construct or call any
  importable callable. HyperPyYAML's README and SpeechBrain's docs say loading it
  allows arbitrary code execution and that only trusted files should be loaded.
  This is documented behaviour, not a vulnerability; the scanner grades it so a
  reviewer can see which callables a downloaded file will run.

## Rules

| rule | trigger | severity |
|------|---------|----------|
| `YPT001` | PyYAML `!!python/object/apply`, `object/new`, `object`, `name` or `module` tag (also the verbatim `!<tag:yaml.org,2002:python/...>` form) | **CRITICAL** when a calling tag targets a code-execution module or builtin, otherwise HIGH |
| `YPT002` | HyperPyYAML `!apply:` / `!new:` / `!name:` / `!module:` tag | **CRITICAL** for a calling tag on a dangerous target, HIGH for a reference to one, MEDIUM for an unknown namespace, LOW for `speechbrain.`, `torch.`, `torchaudio.`, `transformers.`, `sentencepiece.`, `numpy.` |
| `YPT003` | a `%TAG` directive that aliases the python tag namespace | HIGH (aliased tags are not followed; review by hand) |
| `YPT004` | any code tag in a file named `CKPT.yaml` | **CRITICAL** (checkpoint metadata should be plain data; CVE-2026-10036) |

Primitive tags that build plain data (`!!python/tuple`, `!!python/bytes`, ...) and
HyperPyYAML's `!ref` are ignored. Dangerous targets are the same module families
as `jsonargparse_config_scan.py` (`os`, `subprocess`, `builtins`, `importlib`,
`pickle`, `ctypes`, `socket`, ...) plus bare builtins such as `eval` and `exec`,
which both loaders resolve from `builtins`.

## Usage

```bash
# scan a model or checkpoint directory, fail CI on CRITICAL
python yaml_python_tag_scan.py ./pretrained_model --fail-on CRITICAL

# machine-readable output
python yaml_python_tag_scan.py hyperparams.yaml --json
```

Scans `*.yaml` and `*.yml`. Standard library only, no network. Tests:
`python -m unittest test_yaml_python_tag_scan` (inline, inert fixtures).

## How it compares

General code linters (Bandit, Semgrep) flag *calls* to `yaml.load` in Python
source; they do not read YAML data files shipped with a model. MV2's
`hydra_target_scan` and `jsonargparse_config_scan` cover config *keys*
(`_target_`, `class_path`), not YAML *tags*. ModelAudit's Manifest scanner looks
for generic code-execution patterns in YAML and may overlap; it documents no
rule for these tags or for CVE-2026-10036. We found no scanner that documents
one.

## Honest limits

- The real fixes are upgrading SpeechBrain to 1.1.1 or later, parsing metadata
  with `yaml.safe_load`, and loading `hyperparams.yaml` only from trusted
  sources. **A clean scan guarantees nothing.**
- Line-based: tags inside quoted scalars and comments are ignored, block scalars
  are not modelled, and `%TAG` aliases are reported but not followed.
- A LOW `YPT002` finding means "ordinary-looking namespace", not "safe": a
  `torch.` or `speechbrain.` callable can still be misused with crafted
  arguments.
- Severity is read from the target string only; the scanner does not model the
  installed SpeechBrain or PyYAML version.

## Sources

- CVE-2026-10036 (VulnCheck) — https://vulncheck.com/advisories/speechbrain-arbitrary-code-execution-via-ckpt-yaml-parsing
- HyperPyYAML README, security note — https://github.com/speechbrain/HyperPyYAML
- SpeechBrain `from_hparams` docs — https://speechbrain.readthedocs.io/en/latest/API/speechbrain.inference.interfaces.html
