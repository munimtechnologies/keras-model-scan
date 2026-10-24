<!--
Copyright 2026 Munim, Inc.
SPDX-License-Identifier: Apache-2.0
Text and data in this document are licensed CC BY 4.0.
Made with AI agents working in the name of MV2 of Munim, Inc.
-->

# What a `.keras` namespace allowlist still misses in 2026: deserialization-time I/O layers and tokenizers (CVE-2025-12058), and how a scanner should be version-aware

*By MV2 of Munim, Inc. Made with AI agents working in his name. Source review only; no
model was loaded and no code was executed against any live or hosted system. All Keras,
keras_hub and keras-model-scan facts below were read from open source on 2026-10-24.*

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
| ≤ 3.12.4 (latest release) | `serialization_lib.in_safe_mode()` guard inside `IndexLookup.set_vocabulary`, **and the same guard in every file-reading `keras_hub` tokenizer** | CVE-2025-12058 (file-read at deserialization) |
| master | `NON_MODELING_APIS` frozenset (~30 names) supersedes `LOADING_APIS` | the broader non-modeling-callable class |

Verification pointers (all `raw.githubusercontent.com`, read 2026-10-24):

- `keras/src/saving/serialization_lib.py` @ `v3.11.0` defines `LOADING_APIS` and raises on it.
- The same file @ `master` defines `NON_MODELING_APIS` and raises *"it is not a modeling function."*
- `keras/src/layers/preprocessing/index_lookup.py` @ `v3.12.4` and `master` both guard the
  string-path branch of `set_vocabulary` with `serialization_lib.in_safe_mode()`.
- `keras-hub` @ `master`: `word_piece_tokenizer.py`, `sentence_piece_tokenizer.py` and
  `byte_pair_tokenizer.py` each guard their string-path branch with the same
  `serialization_lib.in_safe_mode()` check before calling `open()` (see next section).

So on the **latest release**, under default safe mode, the `get_file` class, the core
vocabulary-path class, and the keras_hub tokenizer file-read class are all closed. The
earlier note's "the gadget remains" wording was correct for the 3.9–3.10 window but is
**outdated for current Keras**, and this note supersedes it.

## The live residual (1): CVE-2025-12058, StringLookup / IntegerLookup vocabulary paths

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
   Lambda-bearing or legacy models — on *every* version, including the latest.

## The live residual (2): the keras_hub tokenizer file-read family (same class, new coverage)

The CVE-2025-12058 *fix family* — an `in_safe_mode()` guard placed in front of a branch that
treats a string argument as a file path — was applied in a second package, `keras_hub`, to
every tokenizer that loads a vocabulary/proto/merges file at construction. Verified on
keras-team/keras-hub `master`, 2026-10-24:

| keras_hub class | string argument(s) | read mechanism | guarded by `in_safe_mode()`? | `get_config` stores |
|---|---|---|---|---|
| `WordPieceTokenizer` | `vocabulary` | `open(vocabulary, "r")` | yes | `vocabulary: None` (asset) |
| `SentencePieceTokenizer` | `proto` | `open(proto, "rb").read()` | yes | `proto: None` (asset) |
| `BytePairTokenizer` | `vocabulary`, `merges` | `open(...)` + `json.load` / line read | yes (both) | neither stored (asset) |

Each tokenizer is a registered Keras serializable, so in a `.keras` config it appears as a
**class node** whose `module` top package is `keras_hub`. Because `keras_hub` is in the
allowlist, `KMS001` passes it as benign. Under `safe_mode=False`, or on any keras_hub version
predating the guard, a crafted node such as

```json
{"class_name": "WordPieceTokenizer",
 "module": "keras_hub.src.tokenizers.word_piece_tokenizer",
 "config": {"vocabulary": "/etc/passwd"}}
```

causes `open("/etc/passwd")` at load time — the same LFI/SSRF class as residual (1), now via
`open()` rather than `tf.io.gfile`. This family is, to our knowledge, not previously mapped
onto model-file scanner coverage; it is the new result of this note.

## The scanner gap, measured

keras-model-scan's `KMS001` implements only the Keras 3.9 step — the top-package allowlist.
Verified live in `keras_model_scan.py` on `main` (2026-10-24): it contains
`KERAS_IMPORT_ALLOWLIST = frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"})` and
**none** of the strings `StringLookup`, `IntegerLookup`, `IndexLookup`, `WordPieceTokenizer`,
`SentencePieceTokenizer`, `BytePairTokenizer`, `vocabulary`, `proto`, `merges`,
`CVE-2025-12058`, or any by-name non-modeling denylist. Consequently it scans **clean**:

- a `function` node naming `keras.utils.get_file` — top package `keras` is allowlisted;
- a `StringLookup` node with `"vocabulary": "/etc/passwd"` — an ordinary layer node is never
  inspected; and
- a `WordPieceTokenizer`/`SentencePieceTokenizer`/`BytePairTokenizer` node with a string
  `vocabulary`/`proto`/`merges` — top package `keras_hub` is allowlisted.

All of these are dangerous files for the audiences in (1) and (2) above.

## Why a string path field is a clean attack signature (low false positives)

A *legitimately saved* model never carries a string path in these fields. Keras
`IndexLookup.get_config` stores the **resolved vocabulary as a list** (or `None`, with the
vocabulary carried separately as an archive asset). Every keras_hub tokenizer `get_config`
likewise stores `None` for `vocabulary`/`proto` (BytePairTokenizer omits them entirely) and
carries the real file as an archive asset. Only a **hand-crafted** `config.json` puts a raw
path/URL into one of these fields. So flagging a *string* value targets exactly the attack
shape with essentially no cost to honest models.

## The fix: a version-aware KMS006

A scanner can — and for these audiences should — be **stricter than the loader**: flag the
danger regardless of the target's Keras / keras_hub version or `safe_mode` setting. The
proposed KMS006 (modelled and tested in
[`keras_deserialization_io_blindspot.py`](keras_deserialization_io_blindspot.py)
/ [`test_keras_deserialization_io_blindspot.py`](test_keras_deserialization_io_blindspot.py))
flags three shapes KMS001 misses:

1. a `function`/`class` node resolving to a name in Keras's own `LOADING_APIS ∪
   NON_MODELING_APIS` denylist (the `get_file` class — authoritative, copied from upstream);
2. a `StringLookup`/`IntegerLookup`/`IndexLookup` node whose `vocabulary` config is a string
   (CVE-2025-12058); and
3. a `WordPieceTokenizer`/`SentencePieceTokenizer`/`BytePairTokenizer` node whose
   `vocabulary`/`proto`/`merges` config is a string (the keras_hub file-read family).

It leaves a benign `Dense` layer, a `StringLookup` with an inline vocabulary list or null
vocabulary, and a saved tokenizer with `None` fields, untouched. The denylists are Keras's
own, and the tokenizer map was source-reviewed against upstream, so the rule tracks upstream
rather than a hand-enumerated guess.

## Why this is new

Prior public work documents each Keras mitigation and each CVE in isolation. What is new
here is (a) the **mapping of Keras's evolving deserialization-security model onto a
model-file scanner's coverage, over version boundaries** — an allowlist-only `.keras`
scanner lags Keras itself by three mitigations and therefore under-protects the pre-3.12
installed base and every `safe_mode=False` load — and (b) the identification of the
**keras_hub tokenizer file-read family as a second, parallel instance of the CVE-2025-12058
class** that the same allowlist misses, with a concrete, upstream-sourced,
false-positive-aware rule to close both. It is reproducible by reading a handful of
open-source files with no execution.

## Honest limits

- Source review only; **not** a vulnerability report against Keras or keras_hub.
  CVE-2025-12058, the `get_file` class and the keras_hub tokenizer file reads were all
  disclosed and/or hardened upstream by others; each is guarded under `safe_mode=True` on the
  current releases. No novel vulnerability is claimed here.
- `NON_MODELING_APIS` was transcribed from master as rendered on 2026-10-24; the demonstrator
  asserts key membership and a lower bound rather than a brittle exact count. The production
  merge should copy the frozenset, and the keras_hub tokenizer map, from the pinned upstream
  source directly.
- The contribution is defensive scanner coverage plus the version-aware coverage mapping; it
  does not, by itself, earn a bounty.

## Reproduce

```
python keras_deserialization_io_blindspot.py            # prints the current-vs-proposed matrix
python -m unittest test_keras_deserialization_io_blindspot -v
```
