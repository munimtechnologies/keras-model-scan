# Corpus manifest

`corpus_manifest.py` is a small, dependency-free, machine-readable index of the
benign / regression test corpora that ship in this repository. It ties each
corpus to the scanner it is a regression test for, to the docs that describe it,
and to the authoritative CVE map that holds that family's verified advisory
identifiers.

It exists because the corpora grew one per format, with no single place saying
which corpus belongs to which scanner or where its verified CVE/CWE identifiers
live. This manifest is that place.

## What it is — and what it deliberately is not

- **It is** a cross-reference. Every value in it is a file that lives in this
  repo: a `*_corpus.py` fixture module, a `*_scan.py` scanner, a `*.md` doc, or
  a `*_cve_map.json`.
- **It is not** a second copy of any advisory identifier. The manifest carries
  **no** `CVE-…` or `GHSA-…` strings. Those stay, verified against GHSA / OSV /
  NVD, in the `model_file_cve_map.json` and `gguf_cve_map.json` files, which
  remain the single source of truth. A test (`test_no_reasserted_advisory_ids`)
  enforces this, so the manifest can never drift out of sync with the maps.

## The rows

| key | corpus module | scanner | authoritative map |
| --- | --- | --- | --- |
| `archive_bomb` | `archive_bomb_corpus.py` | `archive_bomb_scan.py` | `model_file_cve_map.json` |
| `chat_template` | `chat_template_corpus.py` | `chat_template_scan.py` | `model_file_cve_map.json` |
| `gguf_chat_template` | `gguf_chat_template_corpus.py` | `gguf_chat_template_scan.py` | `model_file_cve_map.json` |
| `gguf_cve` | `gguf_cve_corpus.py` | `gguf_scan.py` | `gguf_cve_map.json` |
| `hf_config_injection` | `hf_config_injection_corpus.py` | `hf_config_injection_scan.py` | `model_file_cve_map.json` |
| `onnx_external_data` | `onnx_external_data_corpus.py` | `onnx_external_data_scan.py` | `model_file_cve_map.json` |
| `onnx_external_data_key` | `onnx_external_data_key_corpus.py` | `onnx_external_data_key_scan.py` | `model_file_cve_map.json` |

## Using it

```python
import corpus_manifest as cm

cm.keys()                       # every corpus slug
cm.get("gguf_cve")              # one row (a copy)
cm.corpus_modules()             # every *_corpus.py file
cm.by_cve_map("gguf_cve_map.json")   # rows governed by the GGUF map
print(cm.to_json())             # the whole manifest as JSON
```

From the shell:

```
python corpus_manifest.py       # prints the manifest as JSON
```

## Scope and honesty

This is an index, not a scanner. It makes no security claim of its own: it only
records which files in the repo relate to which. A corpus being listed here says
nothing about how complete that corpus is, and the authoritative CVE maps it
points to document their own coverage, gaps and caveats. When a new corpus is
added, add a row that *points at* the maps — never a second copy of an advisory
identifier.

## Licence and authorship

Made with AI by MV2 of Munim, Inc. The code (`corpus_manifest.py`) is licensed
Apache-2.0, consistent with the rest of this repository; the catalogue data and
this document are also offered under CC BY 4.0.
