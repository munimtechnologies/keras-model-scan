# hydra_target_scan.py — config-driven class instantiation in model metadata

Static, standard-library-only, no-execution scanner for model configuration files that
name a Python callable for a loader to build. It covers two loader styles:

- **Hydra / OmegaConf `_target_`**: `hydra.utils.instantiate()` calls whatever dotted
  path a `_target_` key names, with arguments taken from the same config.
- **pyannote `pipeline: name:`**: `pyannote.audio` `Pipeline.from_pretrained` reads
  `pipeline.name` and each `preprocessors.<key>.name` from a repository's
  `config.yaml`, resolves the dotted name with `get_class_by_name()` and calls it with
  the config's `params`.

In both cases the risk comes from the configuration, not the weights, so it applies
even when the weights are safetensors.

## Findings

| ID | Severity | Meaning |
|---|---|---|
| HYD001 | HIGH | `_target_` names a known code-execution callable (`builtins.exec`, `os.system`, `subprocess.*`, `importlib.import_module`, `ctypes.*`, ...) |
| HYD002 | MEDIUM / LOW | any other `_target_`. MEDIUM by default, because Hydra's blocklist can be bypassed (GHSA-mwj6-rfh8-7qf4). LOW for common benign prefixes (`torch.optim.`, `torch.nn.`, `transformers.`, ...) |
| HYD003 | INFO | Hydra helper keys (`_args_`, `_partial_`, `_recursive_`, ...) that corroborate `instantiate()` use |
| HYD004 | HIGH / MEDIUM / LOW | pyannote-style class reference at `pipeline.name` or `preprocessors.<key>.name`. HIGH for a known code-execution callable. MEDIUM for a dotted name outside the `pyannote.` namespace. LOW for a name inside it (or a bare name, which pyannote resolves in its own module) |
| HYD000 | ERROR | unreadable file or malformed JSON |

Files scanned: `config.json`, `*_config.json`, `generation_config.json`,
`hparams.json`, `preprocessor_config.json` (parsed as JSON), and `*.yaml` / `*.yml`
(a dependency-free text scan that tracks block-mapping indentation).

## Usage

```
python hydra_target_scan.py ./model-dir                 # exit 1 on HIGH
python hydra_target_scan.py ./model-dir --fail-on MEDIUM
python hydra_target_scan.py config.yaml --json
```

Regression corpus: `python hydra_target_corpus.py --out-dir ./corpus` writes the
fixtures (all payloads are inert and are only ever read as text). Tests:
`python -m unittest test_hydra_target_scan`.

## Public precedent (nothing here is new or undisclosed)

- CVE-2026-22584: Salesforce Uni2TS, Hydra `instantiate()` on model metadata.
- CVE-2025-23304: NVIDIA NeMo, same class, fixed in NeMo 2.3.2.
- FlexTok: same class (Palo Alto Networks Unit 42, 2026).
- GHSA-mwj6-rfh8-7qf4: the Hydra `_target_` blocklist can be bypassed.
- pyannote-audio issues #2000 (opened 2026-04-06) and #2019 (opened 2026-06-06):
  class instantiation from `config.yaml` in `Pipeline.from_pretrained`, reported
  against versions up to 4.0.4. As of 2026-10-16 both issues are open and no fix is
  linked. Until one ships, load pipelines only from repositories you trust, and pin
  them to a reviewed revision.

## Limits

- Static only. It never imports, resolves or calls a name. A clean scan does not
  prove a file is safe.
- The YAML scan handles block mappings, comments and quoted scalars. It does not
  follow anchors, aliases, flow mappings (`pipeline: {name: ...}`) or `!include`-style
  tags. Parse untrusted YAML with a real YAML parser before trusting the result.
- The fix belongs in the loader: an allowlist or an explicit trust flag
  (as with `trust_remote_code`), and keeping affected libraries up to date.

Apache-2.0. Made with AI by MV2, Munim, Inc.
