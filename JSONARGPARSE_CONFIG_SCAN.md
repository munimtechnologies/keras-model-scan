<!--
Copyright 2026 MV2, Munim, Inc.
Text licensed under CC BY 4.0; code under Apache-2.0.
-->
# jsonargparse / LightningCLI config-instantiation scanner (`jsonargparse_config_scan.py`)

A static, no-execution detector for the **config-driven class instantiation**
vector that jsonargparse and PyTorch Lightning's `LightningCLI` expose — the
**CVE-2026-58659** class. It reads YAML/JSON config text only; it never imports,
evaluates, or executes anything it finds.

Made with AI by MV2 of Munim, Inc. Everything named here is already public and
fixed upstream — this is a detector, not an exploit, and not a zero-day.

## The vector

jsonargparse resolves a config's `class_path` by importing the named module and
instantiating the class with config-supplied `init_args`, so **"a config
effectively decides what code runs"** (mauvilsa/jsonargparse
[PR #959](https://github.com/mauvilsa/jsonargparse/pull/959)). When the config
comes from an untrusted source, a dotted import path can reach module-level code
that runs on import.

PyTorch Lightning's `LightningModule.load_from_checkpoint` stores two such
values in a checkpoint's hyper-parameters and resolves them on load, **bypassing
`weights_only=True`**:

| key | how it runs | advisory |
|-----|-------------|----------|
| `_instantiator` | Lightning imports and calls the named dotted path | CVE-2026-58659 primary vector |
| `_class_path` | passed to jsonargparse `import_object`, which calls `__import__` on the module **before** the subclass check | second vector, closed by Lightning [PR #21914](https://github.com/Lightning-AI/pytorch-lightning/pull/21914) |

**CVE-2026-58659** — GHSA-qqmf-gpg7-g8gw / PYSEC-2026-3624, CVSS 8.4 (High),
affects `pytorch-lightning` **≤ 2.6.5**, fixed in **2.6.6**. The jsonargparse
side is mitigated by the import-path denylist/allowlist added in PR #959
(enforced from jsonargparse v5.0.0).

## Rules

| rule | trigger | severity |
|------|---------|----------|
| `JAC001` | a `class_path` key whose value is a dotted import path | HIGH, or **CRITICAL** if the module is dangerous |
| `JAC002` | a `_class_path` key (checkpoint hparam, CVE-2026-58659) | HIGH / **CRITICAL** |
| `JAC003` | an `_instantiator` key (checkpoint hparam, CVE-2026-58659) | HIGH / **CRITICAL** |

A finding is escalated to **CRITICAL** when the import path's top-level module
grants code execution, deserialization, imports, reflection, filesystem,
process, or network access (`os`, `subprocess`, `pickle`, `importlib`,
`builtins`, `socket`, `ctypes`, …) — the same families jsonargparse's own
denylist targets.

## Usage

```bash
# scan a directory of config files, fail CI on any HIGH+ finding
python jsonargparse_config_scan.py ./configs --fail-on HIGH

# machine-readable output
python jsonargparse_config_scan.py model_config.yaml --json
```

Scans `*.json`, `*.yaml`, and `*.yml`. Pure standard library — no jsonargparse,
no PyYAML, no network. Exit code is non-zero when a finding at or above
`--fail-on` is present.

### Scanning a checkpoint's hparams

A `.ckpt` file embeds its hyper-parameters inside a zip/pickle container; extract
the `hparams.yaml` (or the hparams dict serialized to JSON/YAML) first, then scan
that text. This tool deliberately does not open pickle/zip containers.

## How it compares

Existing model/config scanners (ModelScan, ModelAudit, and MV2's own
`hydra_target_scan` for the Hydra/OmegaConf `_target_` vector) do not flag the
jsonargparse/LightningCLI `class_path` / `_class_path` / `_instantiator` keys. To
the author's knowledge this is the first standalone static detector for this
exact vector.

## Honest limits

- The real fix is upgrading (`pytorch-lightning >= 2.6.6`, jsonargparse with the
  import-path denylist) and never loading configs or checkpoints from untrusted
  sources. **A clean scan guarantees nothing.**
- A dotted path in a config is not proof of a vulnerability — it is only
  dangerous if the consuming CLI/loader resolves it without an allowlist. These
  findings are **leads for review**, not confirmed exploits.
- The YAML path is a line-based scan (no PyYAML), so it reports the key and its
  scalar value; it does not model anchors, multi-line, or flow collections.
- The dangerous-module list is an allowlist-of-concern, not exhaustive; a HIGH
  finding on an unknown module can still be exploitable.
