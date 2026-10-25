# The nested-function recursion in Keras deserialization: a closed file-I/O frontier

*Made with AI agents working in the name of MV2 of Munim, Inc. Source review only — no
code was executed against any system and no novel vulnerability is claimed. This is an
honest negative result that closes the last open question in the config-time file-I/O map
for `keras-model-scan`. Verified against `keras-team/keras` `master` on 2026-10-24.*

## Why this document exists

Earlier studies in this repository enumerated the **config-time file-I/O surface** of a
`.keras` model — every place where loading a model config can make Keras read an
attacker-chosen file path or URL at deserialization time. Two companion maps closed the
layer surface (`KERAS_NAMESPACE_IO_SURFACE.md`) and the non-layer serializable surface
(`KERAS_NONLAYER_SERIALIZABLE_IO_SURFACE.md`). Both concluded that exactly **two families**
read a config-supplied path at `from_config`/`__init__`:

- **(A)** the keras-core lookup family `StringLookup` / `IntegerLookup` / `TextVectorization`
  (string `vocabulary`);
- **(B)** the `keras_hub` tokenizers `WordPiece` / `SentencePiece` / `BytePair`
  (`vocabulary` / `proto` / `merges`).

Both families are guarded by `serialization_lib.in_safe_mode()` on the latest release, and
both remain live under `safe_mode=False` or on Keras `<= 3.11.x` (the CVE-2025-12058 class).

One question remained genuinely open: the **nested-object recursion**. When
`deserialize_keras_object` resolves a nested `class_name:"function"` reference (a loss's
`fn`, a metric's `fn`, a layer's `activation`, an optimizer's nested object, a `Lambda`'s
`function`), could a nested reference name an *in-allowlist* callable that performs
file/URL I/O at resolution time — one that the top-level scan misses because it only
inspects the outer object? If such a path existed and were reachable under `safe_mode=True`
on the latest release, it would be a novel, payable gadget. This document answers it.

## What the source actually does

Two mechanisms matter, both read verbatim from
`keras/src/saving/serialization_lib.py` on `master` (2026-10-24).

### 1. The allowlist is centralized and depth-independent

Every `class_name:"function"` and `class_name:"class"` reference — at any nesting depth —
is resolved through a single helper:

```
def _retrieve_class_or_fn(
    name, registered_name, module, obj_type, full_config, custom_objects=None
):
```

Inside it, for any `keras`-namespace reference the by-name denylist fires first:

- `if module == "keras" or module.startswith("keras."):` → if the fully-qualified
  `api_name` is in `NON_MODELING_APIS` (the ~30-name frozenset on `master` that supersedes
  the earlier `LOADING_APIS`, covering `load_model`, `get_file`, `register_keras_serializable`
  and the rest), it **raises** rather than resolving.

Dynamic import is then restricted to exactly four packages:

- `package = module.split(".", maxsplit=1)[0]`
- `if package in {"keras", "keras_hub", "keras_cv", "keras_nlp"}:` … otherwise execution
  falls through to the final `raise TypeError("Could not locate {obj_type} '{name}'. …")`.

Because this check lives inside `_retrieve_class_or_fn`, and because **every** nested
reference — explicit recursive calls over lists/tuples/dicts and the re-entry that a
class's own `from_config` performs — routes through it, the same denylist and the same
four-package restriction apply at **every depth**. There is no shallower or more permissive
resolver reached at depth > 0. (`module_objects`, the only more-permissive lookup table, is
*not* threaded into nested calls, which makes nested resolution strictly more restrictive,
not less.)

### 2. A resolved function is returned, never invoked at load

When a `"function"` reference resolves, the result is handed back directly:

- `if isinstance(cls, types.FunctionType):` → `return cls`

The function object is **stored**, not **called**, during deserialization. So resolving a
nested `fn`/`activation` reference performs no file or network I/O by itself — resolution is
an import plus an attribute lookup. The only way a nested callable could do I/O *at load*
would be for some container class to **call** it inside its own `__init__`/`from_config`;
the mapped container families (losses, metrics, optimizers, LR schedules, initializers,
regularizers, constraints, dtype policies) all store the nested `fn`/schedule without
invoking it at construction. Lambdas — the one historically dangerous call path
(CVE-2025-1550) — remain gated directly by `if safe_mode:` before any Python-callable
deserialization, and nested calls thread the active value via the global `SafeModeScope`
(`safe_scope_arg = in_safe_mode()`).

## Conclusion — the frontier is closed (honest negative)

The nested-function recursion contributes **zero new** config-time file-I/O gadgets on the
latest Keras release:

- the namespace denylist (`NON_MODELING_APIS`) and the four-package restriction are applied
  at every recursion depth, not just the outer object;
- a resolved function is returned, not invoked, so nested resolution performs no load-time
  I/O;
- no mapped container class calls a nested callable with file/URL I/O at construction;
- lambda deserialization stays `safe_mode`-gated, and `safe_mode` is threaded into nested
  calls.

Combined with the two companion maps, the **entire config-time file-I/O surface of a
`.keras` model** — layers, non-layer serializables, and the nested-object recursion — is now
enumerated. It reduces to exactly families **(A)** and **(B)** above, both guarded by
`in_safe_mode()` on the latest release and both live only under `safe_mode=False` or on
Keras `<= 3.11.x`.

## What this means for `keras-model-scan`

Two accuracy notes follow for the scanner (neither is a new exploitable gadget):

1. **A nested out-of-allowlist `class_name:"function"` is not exploitable.** `KMS001`
   inspects the outer object's `class_name`, so it can miss a nested function whose module
   is outside the four packages — but Keras itself **rejects** such a file (the final
   `raise` in `_retrieve_class_or_fn`), so the file will not load. This is a scanner
   false-negative on a *non-loadable* file, not a security gap.

2. **The planned `KMS006` vocab-I/O detector should recurse into nested configs.** The real
   value of recursion is not catching rejected functions but catching the *in-allowlist*
   vocab-I/O classes of families (A)/(B) wherever they appear — e.g. a `StringLookup` or a
   `keras_hub` tokenizer nested inside a larger model config — not only at the top level.

## Limits

Source review of `keras-team/keras` `master` as of 2026-10-24; behavior on a pinned release
may differ and should be re-checked per release (a future commit that calls a nested
callable with a config path, or adds a path parameter to a mapped class, would reopen the
surface). No model was loaded and no system was probed. This is a negative result: it
narrows where a vulnerability could be, and reports honestly that this particular path does
not hold one.
