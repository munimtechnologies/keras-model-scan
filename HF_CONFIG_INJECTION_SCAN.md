# HuggingFace config-injection scanner (CVE-2026-4372)

`hf_config_injection_scan.py` is a static, no-execution scanner that flags the
config-injection remote-code-execution vector in HuggingFace `transformers` model
configs — **CVE-2026-4372 / GHSA-29pf-2h5f-8g72** (CWE-1066 / CWE-502, CVSS 7.8
HIGH, `transformers` < 5.3.0, fixed in **5.3.0**).

Made with AI by MV2 of Munim, Inc. Licence: **Apache-2.0**.

## The vector, plainly

A model config (`config.json` and its nested sub-configs) is plain JSON with no code
of its own. But `transformers` builds a `PretrainedConfig` by calling `setattr` for
every key in that JSON with no allowlist. Before the fix, the underscore-prefixed
internal field **`_attn_implementation_internal`** (and its companion
**`_experts_implementation_internal`**) reached an unsandboxed kernel loader: when
its value looked like an `owner/repo` Hub id and the `kernels` package was installed,
the library downloaded that repository and imported it via `importlib`, running
module-level code in `__init__.py` at `from_pretrained()` time.

The public `trust_remote_code` flag never gated this path — the sanitisers only
covered the public `attn_implementation` field, not the underscore-prefixed internal
one — so a crafted config executes code **even with `trust_remote_code=False`**. That
is what makes this different from the classic `auto_map` / `trust_remote_code` vector:
scanners that grep for `trust_remote_code=True` find nothing, because the victim
never sets it.

## Why a static check is reliable here

The fix in `transformers` 5.3.0 (`PretrainedConfig.from_dict`) simply **drops** these
keys from the loaded dict, including nested sub-configs, because transformers never
writes them itself. So a legitimately serialised config never contains
`_attn_implementation_internal` or `_experts_implementation_internal`. Their mere
presence is a high-confidence indicator of a config-injection payload, with a very
low false-positive rate.

## What it flags

| Rule | Severity | Meaning |
| --- | --- | --- |
| `HCI001` | HIGH | `_attn_implementation_internal` present (CVE-2026-4372). |
| `HCI002` | HIGH | `_experts_implementation_internal` present (CVE-2026-4372). |
| `HCI003` | INFO | `auto_map` / `custom_pipeline` / `auto_pipeline` present — the model carries custom Python that runs under `trust_remote_code=True`. Normal for custom-architecture models; review the referenced module. |
| `HCI000` | ERROR | A scanned config file could not be parsed as JSON. |

For the HIGH rules, if the value matches the `owner/repo` Hub-id shape the vulnerable
`is_kernel()` check accepted, the message says so (an even stronger signal).

The scanner reads **only** JSON. It never loads a model, never imports a kernel and
never touches the network. It walks every config file in a directory (`config.json`,
`*_config.json`, `model_index.json`, and the common tokenizer/preprocessor/scheduler
configs), recursing through nested dicts and lists so sub-configs like `text_config`
are covered.

## Usage

```bash
# fail CI if any HIGH finding is seen (default threshold is HIGH)
python hf_config_injection_scan.py ./model-dir --fail-on HIGH

# scan a single config file, machine-readable output
python hf_config_injection_scan.py ./config.json --json
```

Exit code is `1` when the worst finding is at or above `--fail-on`, else `0`.

## Prior art and novelty

Existing model scanners key on different things: `modelscan` and `picklescan` on
pickle opcodes; `ModelAudit` on 40+ formats including pickle, Keras, ONNX and config
files; `mlsupplyscan` on pickle RCE, `auto_map` bundled Python, chat-template Jinja
escapes and zip-slip. A prior-art check (October 2026) did not find a standalone
static detector keyed on the **`_attn_implementation_internal` /
`_experts_implementation_internal`** kernel-injection fields, which is the exact class
of signal that the classic `trust_remote_code` / `auto_map` scanners miss. This
appears to be the first dependency-free static detector dedicated to CVE-2026-4372.

## Honesty and limits

Every identifier named here is already public and the vulnerability is **fixed in
`transformers` 5.3.0** — the real remediation is upgrading `transformers`. This tool
describes **detection, not exploitation**: it never crafts or runs a payload. A clean
scan guarantees nothing — a config can carry other risks (pickle weights, `auto_map`
custom code, typosquatted repo ids) that this specific detector does not cover; pair
it with a full model-file scan. Verify every advisory at its source
(`github.com/advisories/GHSA-29pf-2h5f-8g72`, `osv.dev/vulnerability/CVE-2026-4372`).
