<!--
Copyright 2026 Munim, Inc.
SPDX-License-Identifier: Apache-2.0
Text and data in this document are licensed CC BY 4.0.
Made with AI agents working in the name of MV2 of Munim, Inc.
-->

# What a `.keras` namespace allowlist still misses in 2026: deserialization-time I/O layers (CVE-2025-12058), and how a scanner should be version-aware

*By MV2 of Munim, Inc. Made with AI agents working in his name. Source review only; no
model was loaded and no code was executed against any live or hosted system. All Keras and
keras-model-scan facts below were read from open source on 2026-10-24.*

This is a correction and a sharpening of the fourth axis of the keras-model-scan coverage
study ([`KERAS_ALLOWLIST_GADGET_BLINDSPOT.md`](KERAS_ALLOWLIST_GADGET_BLINDSPOT.md)). That
earlier note used `keras.utils.get_file` as its live example of an in-namespace gadget. On
re-reading current Keras source, **`get_file` is no longer reachable by name during
deserialization** — Keras has closed it. The structural point (a top-package allowlist is
not gadget-free) stands, but the *live* example is now a different, unpatched-until-recently
class, and the honest framing is version-aware.

## Keras's in-namespace gadget mitigation timeline (verified live, 2026-10-24)

Each guard below fires only under the default `safe_mode=True`.

| Keras version | mitigation | what it closes |
|---|---|---|
| 3.9 | namespace allowlist in `_retrieve_class_or_fn`: a `function`/`class` node is refused unless its module's top package is in `{keras, keras_hub, keras_cv, keras_nlp}` | CVE-2025-1550 (arbitrary module import) |
| ≤ 3.11.0 | `LOADING_APIS` frozenset (7 names, incl. `keras.utils.get_file`): resolving one raises *"loading functions are not allowed during deserialization"* | JFrog's `get_file` download/SSRF gadget class |
| ≤ 3.12.4 (latest release) | `serialization_lib.in_safe_mode()` guard inside `IndexLookup.set_vocabulary`: raises *"Requested the loading of a vocabulary file outside of the model archive."* | CVE-2025-12058 |
| master | `NON_MODELING_APIS` frozenset (~30 names) supersedes `LOADING_APIS` | the broader non-modeling-callable class |

Verification pointers (all `raw.githubusercontent.com`, read 2026-10-24):

- `keras/src/saving/serialization_lib.py` @ `v3.11.0` defines `LOADING_APIS` and raises on it.
- The same file @ `master` defines `NON_MODELING_APIS` and raises *"it is not a modeling function."*
- `keras/src/layers/preprocessing/index_lookup.py` @ `v3.12.4` and `master` both guard the
  string-path branch of `set_vocabulary` with `serialization_lib.in_safe_mode()`.

So on the **latest release (v3.12.4)**, under default safe mode, both the `get_file` class
and the vocabulary-path class are closed. The earlier note's "the gadget remains" wording
was correct for the 3.9–3.10 window but is **outdated for current Keras**, and this note
supersedes it.

## The live residual: CVE-2025-12058, StringLookup / IntegerLookup vocabulary paths

[GHSA-qg93-c7p6-gg7f](https://github.com/keras-team/keras/security/advisories/GHSA-qg93-c7p6-gg7f)
/ CVE-2025-12058 (CVSS 5.5): `keras.layers.StringLookup` and `keras.layers.IntegerLookup`
(both backed by the `IndexLookup` base) accept a `vocabulary` argument that may be a
**filesystem path or URL**. It is read **during `__init__` → `set_vocabulary()` at
deserialization**, not at inference, via `tf.io.gfile` — giving **arbitrary local file read
(LFI)** and, on builds with remote filesystem handlers, **SSRF** (e.g. cloud metadata
endpoints). The advisory confirms it works with `safe_mode=True` on Keras 3.11.3 and older
3.x. Keras has since added the `in_safe_mode()` guard shown above (present in v3.12.4), so it
is **mitigated on the current release under safe mode** — but it remains live for:

1. the large installed base still on Keras **3.9–3.11.x**; and
2. **any load with `safe_mode=False`**, which is routine for pipelines that load
   Lambda-bearing or legacy models — on *every* version, including v3.12.4.

These are exactly the files a model-file scanner exists to catch before they are loaded.

## The scanner gap, measured

keras-model-scan's `KMS001` implements only the Keras 3.9 step — the top-package allowlist.
Verified live in `keras_model_scan.py` on `main` (2026-10-24): it contains
`KERAS_IMPORT_ALLOWLIST = frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"})` and
**none** of the strings `StringLookup`, `IntegerLookup`, `IndexLookup`, `vocabulary`,
`CVE-2025-12058`, or any by-name non-modeling denylist. Its rule set is KMS000–KMS005, KMS007
(KMS006 is unused). Consequently it scans **clean**:

- a `function` node naming `keras.utils.get_file` — top package `keras` is allowlisted, and
  no rule carries `LOADING_APIS`/`NON_MODELING_APIS`; and
- a `StringLookup` node with `"vocabulary": "/etc/passwd"` — `KMS001` only examines
  `class_name in ("function", "class")`, so an ordinary layer node is never inspected.

Both are dangerous files for the audiences in (1) and (2) above.

## Why a string `vocabulary` is a clean attack signature (low false positives)

A *legitimately saved* model never carries a string path here: Keras
`IndexLookup.get_config` stores the **resolved vocabulary as a list** (or `None`, with the
vocabulary carried separately as an archive asset — `self.input_vocabulary = vocabulary if
not isinstance(vocabulary, str) else None`). Only a **hand-crafted** `config.json` puts a
raw path/URL into `vocabulary`. So flagging a string `vocabulary` on a lookup layer targets
exactly the attack shape with essentially no cost to honest models.

## The fix: a version-aware KMS006

A scanner can — and for these audiences should — be **stricter than the loader**: flag the
danger regardless of the target's Keras version or `safe_mode` setting. The proposed KMS006
(modelled and tested in [`keras_deserialization_io_blindspot.py`](keras_deserialization_io_blindspot.py)
/ [`test_keras_deserialization_io_blindspot.py`](test_keras_deserialization_io_blindspot.py))
flags two shapes KMS001 misses:

1. a `function`/`class` node resolving to a name in Keras's own `LOADING_APIS ∪
   NON_MODELING_APIS` denylist (the `get_file` class — authoritative, copied from upstream); and
2. a `StringLookup`/`IntegerLookup`/`IndexLookup` node whose `vocabulary` config is a string
   (CVE-2025-12058).

It leaves a benign `Dense` layer, and a `StringLookup` with an inline vocabulary list or a
null vocabulary, untouched. The denylist is Keras's own, so it tracks upstream rather than a
hand-enumerated guess.

## Why this is new

Prior public work documents each Keras mitigation and each CVE in isolation. What is new
here is the **mapping of Keras's evolving deserialization-security model onto a model-file
scanner's coverage, over version boundaries**: that an allowlist-only `.keras` scanner lags
Keras itself by three mitigations (LOADING_APIS, the vocabulary `in_safe_mode` guard,
NON_MODELING_APIS), and therefore under-protects the pre-3.12 installed base and every
`safe_mode=False` load — with a concrete, upstream-sourced, false-positive-aware rule to
close it. It is reproducible by reading four open-source files with no execution.

## Honest limits

- Source review only; **not** a vulnerability report against Keras. CVE-2025-12058 and the
  `get_file` class were disclosed by others (Huntr/JFrog) and Keras has since hardened both.
- `NON_MODELING_APIS` was transcribed from master as rendered on 2026-10-24; the demonstrator
  asserts key membership and a lower bound rather than a brittle exact count. The production
  merge should copy the frozenset from the pinned upstream source directly.
- No novel vulnerability is claimed. The contribution is defensive scanner coverage plus the
  version-aware coverage mapping; it does not, by itself, earn a bounty.

## Reproduce

```
python keras_deserialization_io_blindspot.py            # prints the current-vs-proposed matrix
python -m unittest test_keras_deserialization_io_blindspot -v
```
