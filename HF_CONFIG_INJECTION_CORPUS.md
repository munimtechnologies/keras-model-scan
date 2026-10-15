# HF config-injection regression corpus (CVE-2026-4372)

A small, dependency-free generator of **benign** Hugging Face model
configuration files that exercise every branch of a config-injection scanner.
It pairs with [`hf_config_injection_scan.py`](./hf_config_injection_scan.py)
(the standalone detector, released in v0.16.0) and gives any such scanner a
fixed, reproducible set of inputs with known-correct expected findings.

> Made with AI by MV2 of Munim, Inc. Code: Apache-2.0. This document and the
> emitted `manifest.json` data: CC BY 4.0. Nothing here is a zero-day — every
> identifier named is already public, and the files contain no executable
> payload of any kind (only JSON strings).

## The vector, briefly

`transformers` chooses an attention or mixture-of-experts kernel from values in
a model's `config.json`. An attacker who can edit that config can set the
underscore-prefixed internal fields

- `_attn_implementation_internal`
- `_experts_implementation_internal`

to a value that reaches an import of attacker-named Python **without** the user
passing `trust_remote_code=True`. This is CVE-2026-4372 /
[GHSA-29pf-2h5f-8g72](https://github.com/advisories/GHSA-29pf-2h5f-8g72)
(transformers < 5.3.0, CWE-502 / CWE-94). A legitimately serialised config
never contains these fields, so their mere presence is a high-confidence
injection indicator.

Separately, `auto_map`, `custom_pipeline` and `auto_pipeline` point to custom
Python that runs only under `trust_remote_code=True`. These are normal for
custom-architecture models and are **informational**, not a vulnerability.

## Why a corpus

A detector is only trustworthy if a regression test proves it still flags each
vector and still leaves clean files clean. There was no standalone, dependency-
free, loader-agnostic corpus for this exact config-injection class (a prior-art
check found `transformers`' own tests cover the fix internally, and model
scanners such as ModelScan and ModelAudit do not key on these fields at all), so
this is plausibly the first. A real benign corpus also lets anyone reproduce and
audit the detector's behaviour without trusting a binary fixture.

## Usage

```bash
python hf_config_injection_corpus.py --out-dir ./corpus_hf_config
```

This writes 11 files plus a `manifest.json`. To regression-test a scanner, run
it over the directory and compare its findings against the `expected_code` and
`expected_severity` in the manifest.

## The files

| File | Expected | Code | Exercises |
|------|----------|------|-----------|
| `clean_control.json` | clean | – | a normal config, no indicator fields |
| `attn_internal.json` | HIGH | HCI001 | top-level `_attn_implementation_internal` |
| `experts_internal.json` | HIGH | HCI002 | top-level `_experts_implementation_internal` |
| `nested_attn_internal.json` | HIGH | HCI001 | injection field in a nested `text_config` (dict recursion) |
| `nested_list_experts.json` | HIGH | HCI002 | injection field in a dict inside a list (list recursion) |
| `hubid_value.json` | HIGH | HCI001 | value matching the `owner/repo` Hub-id shape |
| `model_index_experts.json` | HIGH | HCI002 | a diffusers-style `model_index.json` carrying the field |
| `auto_map.json` | INFO | HCI003 | `auto_map` remote-code pointer |
| `custom_pipeline.json` | INFO | HCI003 | `custom_pipeline` remote-code pointer |
| `auto_pipeline.json` | INFO | HCI003 | `auto_pipeline` remote-code pointer |
| `malformed.json` | ERROR | HCI000 | not valid JSON (truncated) |

A correct scanner reports **6 HIGH, 3 INFO, 1 ERROR, and leaves the clean
control clean**.

## Honest limits

- The corpus proves a scanner's **detection** of these indicators; it does not
  exploit anything and never loads a model.
- A clean scan guarantees nothing about other vectors — the real fix is
  upgrading `transformers` to >= 5.3.0.
- The underscore-prefixed-field denylist is a signature; a future variant that
  reaches the same kernel-selection path through a different field would not be
  caught by name alone.
- The files are deliberately minimal; real configs carry many more keys.

## Verification

`test_hf_config_injection_corpus.py` regenerates the corpus and asserts that
each crafted file carries exactly the field its finding code depends on, the
clean control carries none, the nested cases hide the field below the top level,
the malformed file is genuinely unparseable, and no file contains an executable
payload. Run it with `python -m unittest test_hf_config_injection_corpus`.
