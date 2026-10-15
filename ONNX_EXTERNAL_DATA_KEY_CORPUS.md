# ONNX `external_data` unexpected-key corpus (CVE-2026-34445)

A small, **benign, header-only** corpus of crafted `.onnx` files that each carry
an *unexpected* `external_data` key — the attribute-injection vector of
**CVE-2026-34445** (GHSA-538c-55jv-c5g9). It pairs with the static detector
[`onnx_external_data_key_scan.py`](./ONNX_EXTERNAL_DATA_KEY_SCAN.md) so that the
scanner — and any other ONNX loader or checker — can be regression-tested
against the vector without downloading a real model.

> Made with AI by MV2 of Munim, Inc. Code: Apache-2.0. This document and the
> manifest data: CC BY 4.0. Everything named below is already public; nothing
> here is a zero-day, and nothing here exploits anything.

## The vector, briefly

An `.onnx` file is a protobuf with no code of its own. A tensor marked `EXTERNAL`
names its weights file through a repeated list of key/value string pairs
(`StringStringEntryProto`) in the tensor's `external_data` field. The ONNX IR
spec recognises only four keys — `location`, `offset`, `length`, `checksum` — and
onnx ≥ 1.21.0 also keeps its internal round-trip key `basepath`.

Before 1.21.0, `onnx`'s `ExternalDataInfo.__init__` called
`setattr(self, key, value)` for **every** entry, without validating the key. A
crafted model carrying an unexpected key — a Python dunder such as `__class__`,
or any other attribute name — could overwrite internal object state and crash a
model-serving process at load time. onnx **1.21.0** fixed it with an allow-list
of the recognised keys (CWE-20 / CWE-400 / CWE-915; realistic impact:
denial of service). The real fix is upgrading onnx to ≥ 1.21.0.

## What the corpus contains

Each file is a protobuf header only — **no tensor payload, no exploit code** —
with one `EXTERNAL` tensor whose `external_data` carries the crafted key(s).

| File | Placement | Unexpected key | What it checks |
|---|---|---|---|
| `dunder_class.onnx` | initializer | `__class__` | the archetypal attribute-injection key |
| `dunder_dict.onnx` | initializer | `__dict__` | attribute-namespace overwrite |
| `dunder_reduce.onnx` | initializer | `__reduce__` | a deserialization-adjacent dunder |
| `arbitrary_attr.onnx` | initializer | `payload` | an ordinary non-dunder unrecognised key |
| `case_variant.onnx` | initializer | `Location` | case sensitivity (`Location` ≠ `location`) |
| `whitespace_key.onnx` | initializer | `" location"` | a leading space makes a distinct key |
| `empty_key.onnx` | initializer | `""` | the empty-string key edge case |
| `nested_node_attr.onnx` | node → Constant → attr `t` | `__class__` | walker recursion into node attributes |
| `clean_control.onnx` | initializer | *(none)* | control: only `location`/`offset`/`length` |

Eight malicious files plus one clean control. A correct detector flags all eight
as `OEK001` (HIGH) and leaves `clean_control.onnx` clean.

## Usage

```bash
# write the corpus
python onnx_external_data_key_corpus.py --out-dir ./corpus_keys

# scan it with the paired detector: 8 HIGH findings, control clean
python onnx_external_data_key_scan.py ./corpus_keys --fail-on HIGH
```

Each file also appears in `manifest.json`, with its keys, the unexpected ones,
the rule (`OEK001`), the CWE list and a one-line note — a machine-readable index
for anyone building their own check.

## Why this is new, honestly

MV2's earlier [`onnx_external_data_corpus.py`](./ONNX_EXTERNAL_DATA_CORPUS.md)
covers the *path-traversal* vector — malicious **values** in the `location` key
(CVE-2022-25882, tract `CVE-2026-55832`). This corpus covers a **distinct**
vector: unexpected **keys**, the CVE-2026-34445 attribute-injection class. A
prior-art check (ModelScan, ModelAudit, Fickling and the public advisories) found
scanners that flag ONNX custom ops and `external_data` path traversal, but no
published, benign, reproducible corpus of crafted `.onnx` files carrying
unexpected `external_data` keys. The corpus claims no new vulnerability; it is a
regression artifact that any ONNX parser author can reuse.

## Limits

A clean scan proves nothing. The corpus exercises detection of the *key* vector
only; it does not model offset/length bounds, tensor-data payloads, or any
runtime behaviour. It describes detection, not exploitation.
