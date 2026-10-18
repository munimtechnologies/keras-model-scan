# Keras lookup-layer vocabulary scan (CVE-2025-12058)

`keras_lookup_vocab_scan.py` is a static, no-execution detector for the Keras
preprocessing-layer **`vocabulary` file/URL sink**: an arbitrary local file
read and server-side request forgery (SSRF) that fires on `load_model`, *even
with `safe_mode=True`* (**CVE-2025-12058**, CWE-502).

It is part of [keras-model-scan](https://github.com/munimtechnologies/keras-model-scan).
Made with AI by MV2 of Munim, Inc. Licensed Apache-2.0.

## The vulnerability

A `.keras` model is a ZIP archive whose `config.json` is rebuilt into a live
model by `keras.models.load_model()`. The `StringLookup`, `IndexLookup` and
`IntegerLookup` preprocessing layers take a `vocabulary` argument that is
**either**:

- an inline list of tokens (`["a", "b", "c"]`) — safe; **or**
- a **string path or URL** to a vocabulary file.

When `vocabulary` is a string, Keras opens it with `tf.io.gfile` **during
deserialization**, before any `safe_mode` object checks. Because `tf.io.gfile`
honours absolute paths, `file://`, and remote handlers (`http(s)://`, `gs://`,
`hdfs://`, `s3://`, …), a crafted model can:

- **read an arbitrary local file** — e.g. `vocabulary="/home/victim/.ssh/id_rsa"`
  or `"file:///home/dev/.netrc"` — whose contents land in the model state and
  are recoverable via `get_vocabulary()`; or
- **perform SSRF** — e.g.
  `vocabulary="http://169.254.169.254/latest/meta-data/iam/security-credentials/…"`
  to reach cloud-metadata or other internal endpoints.

`safe_mode=True` does **not** block it: the read happens before the safe-mode
checks on custom objects.

### Facts (verified)

| Field | Value |
|---|---|
| CVE | CVE-2025-12058 |
| GHSA | GHSA-qg93-c7p6-gg7f (alias GHSA-mq84-hjqx-cwf2) |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| CVSS | 5.9 (Medium), CVSS v4.0 |
| Affected | Keras ≤ 3.11.3 |
| Fixed | Keras 3.11.4 (GitHub advisory / Zscaler); OSV normalises the fixed version to 3.12.0 |
| Layers | `StringLookup`, `IndexLookup`, `IntegerLookup` |
| Fix PR | https://github.com/keras-team/keras/pull/21751 |
| Discovery | Zscaler ThreatLabz (responsibly disclosed; published 2025-10-29) |

## What this tool does

It reads `config.json` out of a `.keras` archive (or a raw `config.json`) and
walks the layer tree **statically** — it never imports Keras, never executes the
model, and never opens any path named in the config. It flags any lookup layer
whose `vocabulary` is a string.

| Rule | Severity | Meaning |
|---|---|---|
| `KLV000` | info | `config.json` is not valid JSON |
| `KLV001` | medium | lookup layer with a string `vocabulary` **path** (local file read) |
| `KLV002` | high | lookup layer with a `vocabulary` **URL / remote scheme** (SSRF) |
| `KLV003` | info | `config.json` too large to scan safely (decompression-bomb cap) |

Exit code is `1` if any actionable (non-info) finding is present, else `0`, so
it works as a CI or pre-load gate.

## Usage

```bash
python keras_lookup_vocab_scan.py model.keras
python keras_lookup_vocab_scan.py config.json --json
```

## Why flagging *any* string vocabulary is the right signal

Per the Keras API, a `vocabulary` string is **always** a filename/URL to read;
inline vocabularies are lists. So a string value is exactly the sink described
by CVE-2025-12058, with very low false-positive risk against ordinary models
(which serialise either a list or `null`).

## Honest limits

- A model **legitimately** built with a file-path vocabulary will also be
  flagged (KLV001) — by design: that read *is* the sink, and the warning tells
  you to confirm the path is trusted before loading from an untrusted source.
- Scheme classification (KLV001 vs KLV002) is a prefix match on a fixed list of
  URL schemes; an unusual custom `tf.io.gfile` handler not in that list would be
  reported as KLV001 (local read) rather than KLV002.
- It matches on the layer class name (`StringLookup`/`IndexLookup`/
  `IntegerLookup`), including dotted (`keras.layers.StringLookup`) and
  registered (`Custom>StringLookup`) forms. A sink reached through a
  differently-named custom subclass that wraps these layers would be missed.
- Static analysis only: it does not and cannot confirm exploitability against a
  specific Keras version. Patch to Keras 3.11.4+ regardless.

## Prior art

promptfoo's [ModelAudit](https://github.com/promptfoo/modelaudit) scans Keras
files but, per its documentation, its Keras checks target **Lambda layers**; no
public documentation or source was found showing it (or any other public static
model scanner) flags the lookup-layer `vocabulary` file/URL sink. This module is
a stdlib, no-execution check specifically for CVE-2025-12058. If ModelAudit or
another tool adds equivalent coverage, this is complementary, not a first claim
beyond "no public static scanner was found covering it as of 2026-10-18".

## References

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-12058
- OSV: https://osv.dev/vulnerability/CVE-2025-12058
- Zscaler disclosure:
  https://www.zscaler.com/blogs/security-research/zscaler-discovers-vulnerability-keras-models-allowing-arbitrary-file-access
