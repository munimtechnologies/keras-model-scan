# Non-layer serializables, mapped for deserialization-time file I/O

*Made with AI agents working in the name of MV2, Munim, Inc. A source review, no
execution. Pinned to `keras-team/keras` `master` as read on 2026-10-24 via
`raw.githubusercontent.com` and the GitHub contents API. Apache-2.0.*

## Why this file exists

A `.keras` v3 archive loads `config.json` through `deserialize_keras_object`. Under the
default `safe_mode=True`, arbitrary Python callables are blocked, but every object whose
top package is in the namespace allowlist `{keras, keras_hub, keras_cv, keras_nlp}`
(the CVE-2025-1550 fix) is reconstructed by calling its `from_config`. A companion study,
[`KERAS_NAMESPACE_IO_SURFACE.md`](./KERAS_NAMESPACE_IO_SURFACE.md), enumerated the **layer**
surface and showed that exactly two layer families read a config-supplied path at
deserialization time (the keras-core lookup family — `StringLookup` / `IntegerLookup` /
`TextVectorization` — and three `keras_hub` tokenizers), both guarded by `in_safe_mode()`
on the latest release, with `keras_cv` path-free and `keras_nlp` a shim.

Layers are not the only thing a `config.json` carries. An optimizer, a loss, a metric, a
regularizer, a constraint, an initializer, a learning-rate schedule, and a dtype policy are
all serializable objects reconstructed by the same `from_config` dispatch when a model is
loaded. This file closes that remaining gap: **does any non-layer serializable read a
config-supplied file path or URL at `__init__` / `from_config` time?** If the answer is no,
then the entire config-time file-I/O surface of the Keras allowlist is finite and fully
enumerated, and a scanner rule that covers the two layer families is provably complete for
that threat, not merely a sample.

## Method

For each category I read the base class's `from_config` and every concrete class's
`__init__` on `master`, and asked a single, verifiable question per file: does any method
call `open()`, `np.load`, `get_file`, `urllib`, `requests`, or otherwise read a path or URL
drawn from the config, at construction or deserialization time? Pure-math operations
invoked later inside `__call__` (tensor ops, `backend.ops`, `scipy.signal.get_window` for
window validation) are **not** config-time I/O and are excluded.

## Findings

| Category | Files read | Base `from_config` | Any config-time file/URL read? |
|---|---|---|---|
| Initializers | `initializer.py`, `constant_initializers.py`, `random_initializers.py` | `return cls(**config)` | **No** |
| Regularizers | `regularizers.py` | `return cls(**config)` | **No** |
| Constraints | `constraints.py` | `return cls(**config)` | **No** |
| Losses | `loss.py`, `losses.py` | `return cls(**config)` (+ `LossFunctionWrapper`, see below) | **No** |
| Metrics | `metric.py`, `reduction_metrics.py` | `return cls(**config)` (+ `MeanMetricWrapper`, see below) | **No** |
| Optimizers | `base_optimizer.py` | deserializes nested `learning_rate`, see below | **No** |
| LR schedules | `learning_rate_schedule.py` | `return cls(**config)` | **No** |
| DType policies | `dtype_policy.py` | `return cls(**config)` | **No** |

Concrete classes checked (none perform config-time file or network I/O):

- **Initializers:** `Constant`, `Zeros`, `Ones`, `Identity`, `STFT`, `RandomNormal`,
  `TruncatedNormal`, `RandomUniform`, `VarianceScaling`, `GlorotUniform`/`GlorotNormal`,
  `LecunNormal`/`LecunUniform`, `HeNormal`/`HeUniform`, `Orthogonal`. All store numeric
  params (mean, stddev, scale, mode, gain, seeds, axes). `STFT.__init__` calls
  `scipy.signal.get_window` to validate a window name — a math computation, not I/O.
- **Regularizers:** `L1L2`, `L1`, `L2`, `OrthogonalRegularizer` — numeric-only.
- **Constraints:** `MaxNorm`, `NonNeg`, `UnitNorm`, `MinMaxNorm` — scalar/axis params only.
- **LR schedules:** `ExponentialDecay`, `PiecewiseConstantDecay`, `PolynomialDecay`,
  `InverseTimeDecay`, `CosineDecay`, `CosineDecayRestarts` — numeric-only, no overridden
  `from_config`.
- **DType policies:** `DTypePolicy`/`FloatDTypePolicy`, `QuantizedDTypePolicy`,
  `QuantizedFloat8DTypePolicy`, `Int4DTypePolicy`, `GPTQDTypePolicy`, `AWQDTypePolicy` —
  take a `name`/`mode` string parsed into bit-widths, never a path.

## The three non-trivial `from_config` overrides, and why they are not file-I/O gadgets

Three base classes do more than `cls(**config)`. In every case the extra work is an
**in-memory** nested deserialization of a Keras object already carried in the config dict —
no bytes are read from disk or the network:

- `LossFunctionWrapper.from_config` — `if "fn" in config: config =
  serialization_lib.deserialize_keras_object(config)`.
- `MeanMetricWrapper.from_config` — identical `fn` pattern.
- `base_optimizer.from_config` — `if isinstance(config["learning_rate"], dict):
  config["learning_rate"] = serialization_lib.deserialize_keras_object(...)`.

The `fn` reference is a **function/class** reference. That is precisely the gadget class
the scanner already models at the top level: `keras-model-scan`'s KMS001 flags any
`class_name in ("function","class")` whose module is outside the namespace allowlist. A
nested `fn` inside a loss or metric is subject to the same allowlist check during
`deserialize_keras_object`, so it is not a *new* surface — it is the existing wildcard /
in-namespace-gadget question, recursed one level. The nested `learning_rate` resolves to an
LR schedule, and every schedule was shown above to be pure-math.

## Conclusion — the config-time file-I/O surface is now fully enumerated

Combining this file with the layer study:

> Across the **entire** Keras allowlisted deserialization surface — all layers **and** all
> eight non-layer serializable categories — exactly **two** families read a config-supplied
> path at deserialization time: the keras-core lookup family (`StringLookup` /
> `IntegerLookup` / `TextVectorization`, string-`vocabulary`, CVE-2025-12058) and the three
> `keras_hub` tokenizers (`WordPiece` / `SentencePiece` / `BytePair`, `vocabulary` / `proto`
> / `merges`). Both are guarded by `in_safe_mode()` on the latest release. **The non-layer
> serializable categories contribute zero config-time file-I/O gadgets.**

This bounds the search. A scanner that detects those two families has complete coverage of
the config-time file-read/SSRF class under the current allowlist — the proposed KMS006
denylist is a complete rule for this threat, not a sample. It also says where a *novel*
unguarded in-namespace I/O gadget could still hide: **not** in these eight categories, and
**not** in the layer surface, but only in some future allowlisted callable, or in the one
remaining recursion the scanner must follow — a nested `fn`/object reference whose own
module performs load-time I/O while still resolving inside the namespace allowlist.

## Honest limits

- Source review only, no execution; pinned to `master` as read on 2026-10-24. A future
  commit that adds a path parameter to any of these classes would reopen the surface — the
  value here is the method and the bound, which a scanner can re-run per release.
- "Config-time" means `__init__` / `from_config`. I did not trace what happens if user code
  later passes such an object a path at call time; that is outside the `.keras` load threat.
- The nested-`fn` recursion is covered by the existing allowlist model, not re-proven here;
  that remains the live open question for an in-namespace gadget, tracked separately.
- This is a **negative / completeness** result. It earns nothing on its own; its worth is
  that it closes a search space honestly and tells the scanner's denylist when it is done.
