# Keras safe-mode guard: a per-release audit of the config-time file-read surface

**Scope:** Does the `.keras` config-time (deserialization-time) file-read surface stay
`in_safe_mode()`-guarded on the Keras and KerasHub *releases a user actually installs* —
including the `3.13.x` / `3.14.x` / `3.15.1` line that earlier project docs never checked?

**Short answer:** Yes. Every config-supplied file-path read in the safe-mode allowlist is
gated by `serialization_lib.in_safe_mode()` on every release reviewed here, with an identical
guard and the same hardened error message. This turns the project's earlier "guarded on
latest + master" claim into a verified *per-release* statement across the whole supported line.

Made with AI agents working in the name of MV2, Munim, Inc. Source review only — no code was
executed against any system and no live service was contacted. Reproducible by reading the
open-source files linked below.

---

## Why this audit exists (the blind spot it closes)

For `keras-team/keras`, the GitHub API `GET /releases/latest` endpoint returns the release with
the newest `published_at`, **not the highest semver**. On 2026-10-25 it returns **v3.12.4**
(published `2026-07-29T22:19:46Z`) and hides **v3.15.1** (published `2026-07-29T18:25:38Z`, four
hours earlier but a higher version), plus the entire `v3.13.x` and `v3.14.x` line. A reviewer who
anchors on "latest" therefore reviews v3.12.4 and `master`, and silently skips every release in
between — exactly the releases many users pin. This audit walks the skipped releases directly by
tag.

Release ordering confirmed live via `GET /repos/keras-team/keras/releases?per_page=15`
(2026-10-25): highest semver is **v3.15.1**; `/releases/latest` returns v3.12.4.

---

## The surface under audit

Across the full safe-mode load-time allowlist `{keras, keras_hub, keras_cv, keras_nlp}`, exactly
two object families read a config-supplied file path at `from_config`/`__init__` time (established
by prior project source review; keras_cv layers carry no such path and keras_nlp is a thin
keras_hub shim):

- **(A) keras-core lookup family** — `StringLookup` / `IntegerLookup` / `TextVectorization`, which
  all delegate to `IndexLookup.set_vocabulary` when the `vocabulary` argument is a string path.
- **(B) keras_hub tokenizer family** — `WordPieceTokenizer`, `SentencePieceTokenizer`,
  `BytePairTokenizer` (the last reads **two** paths: `vocabulary` and `merges`).

A clean scanner result on any other allowlisted class is therefore sound, not a blind spot.

---

## (A) keras-core `IndexLookup.set_vocabulary` — per-release verification

File: `keras/src/layers/preprocessing/index_lookup.py`. When `vocabulary` is a string, the string
branch opens with the guard before any file is touched:

```python
if serialization_lib.in_safe_mode():
    raise ValueError(
        "Requested the loading of a vocabulary file outside of the "
        "model archive. This carries a potential risk of loading "
        "arbitrary and sensitive files and thus it is disallowed ..."
        f"Vocabulary file: '{vocabulary}'"
    )
...
self.lookup_table = self._lookup_table_from_file(vocabulary)   # tf.lookup.TextFileInitializer
```

| Keras release | `published_at` | guard line present | error message identical | load line |
|---|---|---|---|---|
| v3.13.0 | 2025-12-18 | `if serialization_lib.in_safe_mode():` | yes | `self._lookup_table_from_file(vocabulary)` |
| v3.14.0 | 2026-04-03 | `if serialization_lib.in_safe_mode():` | yes | (same) |
| v3.15.1 | 2026-07-29 | `if serialization_lib.in_safe_mode():` | yes | (same) |

(v3.12.4 and `master` were already confirmed guarded in earlier runs; v3.13.0 is the earliest of
the previously-unreviewed gap, so the three rows above bracket the entire skipped line.)

The file is only reached when safe mode is **off** (`safe_mode=False` or
`keras.config.enable_unsafe_deserialization()`), matching the documented, intended escape hatch.

---

## (B) keras_hub tokenizers — verified on the latest release (v0.32.0, 2026-09-18)

KerasHub versions independently of Keras; its current release is **v0.32.0**
(`GET /repos/keras-team/keras-hub/releases`). Each tokenizer's string-path branch is guarded by
the same `serialization_lib.in_safe_mode()` check before the file is opened:

| keras_hub class | file arg(s) | guard | file-read line |
|---|---|---|---|
| `WordPieceTokenizer` | `vocabulary` | `if serialization_lib.in_safe_mode():` | `with open(vocabulary, "r", encoding="utf-8") as file:` |
| `SentencePieceTokenizer` | `proto` | `if serialization_lib.in_safe_mode():` | `proto_bytes = open(proto, "rb").read()` |
| `BytePairTokenizer` | `vocabulary` | `if serialization_lib.in_safe_mode():` | `with open(vocabulary, "r", encoding="utf-8") as f:` |
| `BytePairTokenizer` | `merges` | `if serialization_lib.in_safe_mode():` | `with open(merges, encoding="utf-8") as f:` |

Each guard raises the same family of hardened `ValueError` messages
(`"Requested the loading of a vocabulary file outside of the ..."`,
`"Requested the loading of a proto file outside of ..."`,
`"Requested the loading of a merges file outside of the ..."`). `BytePairTokenizer` is the one
class in the surface with **two** independently-guarded file paths — worth noting for any scanner
rule that keys off a single config field.

---

## Result

The config-time file-read surface of the Keras / KerasHub safe-mode allowlist is
`in_safe_mode()`-guarded on **every release a user would install today**, not merely on the single
`/releases/latest` build and `master` that earlier reviews covered. The previously-unreviewed
`3.13.x`–`3.15.1` window — hidden by the `/releases/latest` semver quirk — introduces no unguarded
config-path read and removes none of the existing guards.

This is a *negative* result for vulnerability-hunting purposes (no new reachable file read), and a
*positive* completeness result for scanner users: a clean result on these layers is trustworthy
across the supported release line, and a model that triggers one of these loads outside safe mode
is doing something the library already refuses by default.

### Honest limits
- Static source review of pinned release tags; no execution. A compute-sandbox PoC would
  strengthen (not change) the reading.
- Verifies the *presence and placement* of the guard and the *existence* of the file-read lines;
  it does not re-derive that `in_safe_mode()` itself is unbypassable (that is the serialization
  core's contract, unchanged across these releases).
- Covers the two file-reading families only; it does not re-enumerate the allowlist (done in prior
  project docs). It says nothing about `safe_mode=False` usage, which is the user's explicit choice.

### Reproduce
For each release tag `T` below, read the file and confirm the guard precedes the file-read line:
- `raw.githubusercontent.com/keras-team/keras/<T>/keras/src/layers/preprocessing/index_lookup.py`
  for `T` in `v3.13.0`, `v3.14.0`, `v3.15.1`.
- `raw.githubusercontent.com/keras-team/keras-hub/v0.32.0/keras_hub/src/tokenizers/{word_piece,sentence_piece,byte_pair}_tokenizer.py`.
