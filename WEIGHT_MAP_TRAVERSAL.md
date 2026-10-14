<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Text and data in this file are also available under CC BY 4.0. -->

# The `weight_map` path-traversal class (CWE-22) in ML model loaders

*A reference compiled by MV2 of Munim, Inc. This document and its companion
dataset were made with AI. The catalogue data (`weight_map_traversal.json`) is
offered under CC BY 4.0; the code in this repository is Apache-2.0.*

During 2026 the same path-traversal weakness was reported, independently, against
loader after loader across the machine-learning ecosystem. This page states the
one root cause they share, maps it to the checks in this project's
[`safetensors_index_scan.py`](safetensors_index_scan.py), and lists the public
advisories we were able to verify. As far as we could find, no single public
reference ties this wave of advisories to one root cause and to a static
pre-load detector; that gap is what this page fills.

## The root cause, in six lines

A large checkpoint is split into shards. A small JSON index maps each tensor to
the shard that holds it:

```json
{"metadata": {"total_size": 13476837376},
 "weight_map": {"lm_head.weight": "model-00002-of-00002.safetensors"}}
```

To open a shard, a loader resolves the map value against the model directory:

```python
# the vulnerable pattern, seen verbatim across many loaders
path = os.path.join(model_dir, weight_map[name])   # or Path(model_dir) / value
tensors = safe_open(path, framework="pt")
```

The value comes straight from the attacker-controlled package. Two inputs break
the assumption that it is a bare filename:

* **Absolute path** — `"/etc/passwd"` or `"C:\\Windows\\win.ini"`. Both
  `os.path.join` and `pathlib` *discard* the `model_dir` prefix when the second
  component is absolute, so the loader opens exactly the attacker's path.
* **`..` traversal** — `"../../../../etc/shadow"` climbs out of the model
  directory.

Loading the crafted package then reads (or, for writers, writes) an arbitrary
local file. The crafted package contains **only JSON and tensor data — no code,
no pickle** — so tools that look only for executable payloads miss it entirely.

## The fix, in one line

Reject any shard value that is not a bare filename resolving *inside* the model
directory — e.g. `Path(model_dir, value).resolve()` must be relative to
`Path(model_dir).resolve()`, else raise. The `huggingface_hub` reference loader
applies exactly this guard (`_validate_relative_filename`).

## How this maps to `safetensors-index-scan`

The scanner reads only the JSON text of a `*.index.json` file — it never opens a
shard, resolves a path on disk, or loads a model — and flags the `weight_map`
values a naive loader would follow out of the model directory:

| Rule   | Severity | What it catches |
|--------|----------|-----------------|
| STI001 | HIGH     | Absolute shard path (POSIX, Windows, or drive-relative) |
| STI002 | HIGH     | `..` traversal segment |
| STI003 | MEDIUM   | Backslash separator (cross-OS ambiguity) |
| STI004 | MEDIUM   | URL / `fsspec` scheme (`https://`, `file://`, `s3://`) |
| STI005 | LOW      | Subdirectory component instead of a bare filename |
| STI006 | MEDIUM   | NUL byte (truncates the path in a C-backed `open`) |

Run it in CI over a model directory:

```
safetensors-index-scan ./my-model --fail-on HIGH
```

## Verified public advisories

Confirmed from their public sources on 2026-10-14. Full machine-readable detail,
including the honest status of each, is in
[`weight_map_traversal.json`](weight_map_traversal.json).

| Project | ID | Sink | Status |
|---------|----|------|--------|
| huggingface/diffusers | CVE-2026-65920 | `_get_checkpoint_shard_files` | fixed in 0.40.0 (`cee298c`) |
| pytorch/pytorch | GHSA-f569-37c9-8pv7 | `QuantizedHuggingFaceStorageReader` | open, fix PR #199436 |
| sonos/tract (`tract-onnx`) | CVE-2026-55832 | ONNX external-data `location` | fixed 0.21.17 / 0.22.3 / 0.23.2 |
| huggingface/transformers | CVE-2026-9856 | `save_pretrained` chat-template path | fixed |
| huggingface/huggingface_hub | PR #4916 / #4935 | `get_safetensors_metadata` | **declined** — out of threat model |

Two of these are *sibling sinks*: `tract` resolves an ONNX external-data
`location` and `transformers` a chat-template path. They are not `weight_map`
index files (so the scanner does not read them), but they are the same
join-an-untrusted-path-onto-the-model-directory bug in a different field — a
reminder that the class is about the pattern, not one file format.

The `huggingface_hub` entry is kept **as a boundary case, not a win**: the
maintainer closed the hardening PRs as "not a security issue, very corner case,"
because there the traversal stays same-host, returns bytes to the victim rather
than the attacker, and exposes only a header. We record that honestly.

## Community-reported leads (not independently confirmed)

Real issues in real, maintained projects whose maintainer acceptance we did not
independently confirm. Included as leads, each with its source link in the JSON:
`UbiquitousLearning/mllm` #711, `tenstorrent/tt-metal` #59616, and
`alibaba/Pai-Megatron-Patch` #737.

## Scope and honesty

This is a *detection and reference* contribution, not an exploit kit. The
underlying bugs are already public; nothing here is a zero-day, and the scanner
only reads JSON text. A finding means an index deserves review before use — it
is not proof of malice, and a clean result is not a guarantee of safety. If you
believe an entry is inaccurate, please open an issue.

— MV2 of Munim, Inc.
