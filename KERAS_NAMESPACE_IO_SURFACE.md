# The Keras namespace allowlist, mapped for deserialization-time file I/O

*A source-review companion to [`KERAS_DESERIALIZATION_IO_BLINDSPOT.md`](KERAS_DESERIALIZATION_IO_BLINDSPOT.md).
Made with AI agents working in the name of MV2, Munim, Inc. Source review only: no
system was scanned, probed or attacked. Everything below is reproducible by reading the
cited open-source files. Honest limits are stated at the end.*

## Why this document exists

Since Keras 3.9, loading a `.keras` file under the default `safe_mode=True` only
instantiates objects whose top-level package is in a fixed **namespace allowlist**:

```python
{"keras", "keras_hub", "keras_cv", "keras_nlp"}
```

(CVE-2025-1550 mitigation; mirrored by this project's `KMS001` detector, see
`KERAS_ALLOWLIST_GADGET_BLINDSPOT.md`.) That allowlist is a *whole-namespace* grant: any
registered serializable object inside those four packages can be built from an
attacker-controlled config during a load. The question this document answers is narrow and
concrete:

> Across the **entire** namespace allowlist, which serializable objects read a file (or
> fetch a URL) from a config-supplied value at `__init__`/`from_config` time — i.e. at the
> moment a `.keras` load deserializes them — and is each such read guarded on the latest
> release?

`KERAS_DESERIALIZATION_IO_BLINDSPOT.md` answered this for `keras` core (the lookup family)
and for `keras_hub` tokenizers. This companion closes the remaining two members of the
allowlist, **`keras_cv`** and **`keras_nlp`**, so the map is now complete rather than a
sample.

## The complete surface (verified live 2026-10-24)

| Namespace | Config-time file/URL read reachable via `from_config`? | Guarded on latest? |
|-----------|--------------------------------------------------------|--------------------|
| `keras` (core) | **Yes** — `StringLookup`/`IntegerLookup`/`TextVectorization` string `vocabulary` path; `Lambda` marshalled bytecode | Yes — `vocabulary` string branch behind `in_safe_mode()` (CVE-2025-12058); `Lambda` behind safe_mode (CVE-2025-1550) |
| `keras_hub` | **Yes** — exactly three tokenizers: `WordPieceTokenizer`, `SentencePieceTokenizer`, `BytePairTokenizer` (`vocabulary`/`proto`/`merges`) | Yes — same `in_safe_mode()` guard |
| `keras_cv` | **No** — see below | n/a (no such surface) |
| `keras_nlp` | **No** independent surface — it is a shim over `keras_hub` | inherits `keras_hub` |

### `keras_cv`: no registered layer reads a file from its config

`keras_cv/src/layers/` was read in full on master (2026-10-24). Every augmentation layer in
`layers/preprocessing/` (and `preprocessing_3d/`) derives from
`base_image_augmentation_layer.py`, whose constructor is:

```python
def __init__(self, seed=None, **kwargs):
```

It defines no `get_config` that stores a path, calls no `open()`, and reads no file or URL.
The concrete layers (e.g. `rand_augment.py`, `random_jpeg_quality.py`, `solarization.py`,
`resizing.py`, `rescaling.py`) take only numeric parameters such as `factor`, `seed`,
`value_range`. `random_jpeg_quality.py` — the one layer that touches *encoded image bytes* —
operates on an in-memory tensor via `tf.image.adjust_jpeg_quality` and reads nothing from
disk (`__init__(self, factor, seed=None, **kwargs)`).

The object-detection layers (`anchor_generator.py`, `box_matcher.py`, `non_max_suppression.py`,
`roi_align.py`, `roi_generator.py`, `roi_pool.py`, `roi_sampler.py`, `rpn_label_encoder.py`,
`sampling.py`, `multi_class_non_max_suppression.py`) and the top-level network blocks
(`feature_pyramid.py`, `spatial_pyramid.py`, `transformer_encoder.py`,
`hierarchical_transformer_encoder.py`, `vit_layers.py`, `vit_det_layers.py`,
`mbconv.py`, `fusedmbconv.py`, `segformer_multihead_attention.py`,
`overlapping_patching_embedding.py`) are pure tensor computations with numeric configs.

keras_cv **models** do load files, but only through `from_preset`/`load_weights` — explicit
API calls, never the `from_config` path a `.keras` load takes — so they are outside this
scope (the same reasoning that put `keras_hub`'s `ImageConverter`/`AudioConverter` out of
scope in the blindspot doc).

### `keras_nlp`: a compatibility shim over `keras_hub`

`keras_nlp/keras_nlp/__init__.py` on master is:

```python
import keras_hub
__path__.extend(keras_hub.__path__)
from keras_hub import *            # noqa: F403, E402
from keras_hub import __version__  # noqa: E402
```

It re-exports `keras_hub` and extends its own import path with `keras_hub`'s. So the
`keras_nlp.*` serializable objects **are** the `keras_hub.*` objects — the three guarded
tokenizers and nothing else. No independent surface.

## What this means

1. **The config-time file-I/O surface across the whole Keras namespace allowlist is now
   enumerated, not sampled.** Exactly two families read a config-supplied path at
   deserialization time: the `keras`-core lookup family (incl. `TextVectorization`) and the
   three `keras_hub` tokenizers. `keras_cv` has no such layer; `keras_nlp` has no independent
   surface.
2. **Every member of that surface is guarded on the latest release** (`keras` 3.12.4,
   `keras_hub` master, 2026-10-24): the string-path branch is behind `in_safe_mode()`
   (CVE-2025-12058) and `Lambda` bytecode is behind safe_mode (CVE-2025-1550). Under
   `safe_mode=False`, or on `keras <= 3.11.x`, the whole surface is live.
3. **For a scanner, a clean `keras_cv`/`keras_nlp` result is therefore sound**, not a gap:
   there is no config-time file read in those namespaces for a detector to miss. The one
   detector-coverage gap that remains is the one already documented for `keras` core —
   `TextVectorization` carrying the string-`vocabulary` read under its own class name, which a
   naive class-name rule misses (this project's proposed `KMS006` case (b)).

## Honest limits

- This is a **source-review completeness statement about config-time file I/O**, not a proof
  that the allowlisted namespaces are free of every deserialization risk. Marshalled-code and
  other non-file gadgets are a separate class (see the blindspot and allowlist-gadget docs).
- "Reachable via `from_config`" is judged from each object's `__init__`/`from_config`/
  `get_config`; dynamically registered third-party subclasses of these packages are out of
  scope by construction.
- Pinned to what was on master / the latest release on **2026-10-24**. A future layer that
  adds a config-supplied path read would extend this surface; re-run the per-directory read to
  re-confirm.
- No live, hosted or out-of-scope system was touched. Only open source files were read.
