<!--
Copyright 2026 Munim, Inc.
SPDX-License-Identifier: Apache-2.0
Text and data in this document are licensed CC BY 4.0.
Made with AI agents working in the name of MV2 of Munim, Inc.
-->

# A `.keras` import allowlist is gadget-bearing — and a scanner that mirrors it inherits the blind spot

*By MV2 of Munim, Inc. Made with AI agents working in his name. Source review only;
no model was loaded and no code was executed against any live or hosted system.
Sources read 2026-10-24.*

> **Update 2026-10-24 — read [`KERAS_DESERIALIZATION_IO_BLINDSPOT.md`](KERAS_DESERIALIZATION_IO_BLINDSPOT.md) first.**
> The `keras.utils.get_file` example used below has since been **closed by Keras**: it is
> denied by name during deserialization via `LOADING_APIS` (Keras ≤ 3.11.0) and
> `NON_MODELING_APIS` (master). The structural finding — a top-package allowlist cannot
> catch a dangerous callable *inside* the trusted namespace — is unchanged, but the
> *current, live* example is now CVE-2025-12058 (`StringLookup`/`IntegerLookup` vocabulary
> paths), its parallel in the keras_hub tokenizer file-read family, and a third surface in
> `keras.layers.TextVectorization`. The follow-up note gives the version-aware picture.

This is the **fourth axis** of the keras-model-scan coverage study, and the first on
the native `.keras` side rather than the pickle/[picklescan](https://github.com/mmaitre314/picklescan)
side. The first three axes compared the pickle scanner against picklescan:

- **Whole-module (wildcard) axis** — [`PICKLESCAN_COVERAGE_DIFF.md`](PICKLESCAN_COVERAGE_DIFF.md): 18 of 36.
- **Specific-name axis** — [`PICKLESCAN_SPECIFIC_AXIS.md`](PICKLESCAN_SPECIFIC_AXIS.md) and
  [`TORCH_GADGET_BLINDSPOT.md`](TORCH_GADGET_BLINDSPOT.md): the 9 `torch.*` gadget paths picklescan
  denies that a top-package allowlist marks benign.
- **Infection/report semantics** — [`INFECTION_SEMANTICS_DIFF.md`](INFECTION_SEMANTICS_DIFF.md).

The torch finding was about a benign-list that is too broad on the *pickle* side. This axis
shows the **same structural weakness exists on the `.keras` side**, where it mirrors a
*known, exploited* weakness in Keras's own deserialization guard — so a clean scan does not
mean a crafted `.keras` file is safe from the class JFrog disclosed.

## Background: Keras's fix for CVE-2025-1550 is a whole-namespace allowlist

CVE-2025-1550 let a crafted `config.json` inside a `.keras` archive name arbitrary Python
modules/functions to be instantiated and called during `load_model`, even with
`safe_mode=True`. Keras 3.9 added a module allowlist in `_retrieve_class_or_fn`:

```python
package = module.split(".", maxsplit=1)[0]
# loading is refused unless package in {"keras", "keras_hub", "keras_cv", "keras_nlp"}
```

JFrog ([*Is TensorFlow Keras "Safe Mode" Actually Safe?*](https://jfrog.com/blog/keras-safe_mode-bypass-vulnerability/))
showed this is a **necessary but not sufficient** fix: the allowlisted `keras` package
*itself* contains callables with load-time side effects. Their example is
`keras.utils.get_file`, which downloads an attacker-specified `origin` URL and extracts
tar/zip archives to the local filesystem — reachable by name from a crafted config without
any marshalled bytecode (so it also evades the `__lambda__` bytecode guard). The attack
primitive is: *trust a namespace, but the namespace is not gadget-free.*

> **Correction (2026-10-24):** Keras has since denied `get_file` (and six other
> loader/utility callables) by name via the `LOADING_APIS` frozenset in
> `serialization_lib.py` (present in v3.11.0), raising *"loading functions are not allowed
> during deserialization"*; master broadens this to `NON_MODELING_APIS` (~30 names). So the
> `get_file` load-time download primitive is **no longer reachable by name on Keras ≥ 3.11
> under safe mode**. It was live only on the 3.9–3.10 window. See the follow-up note.

## The finding: keras-model-scan copies the same allowlist, so it has the same blind spot

keras-model-scan's `KMS001` (the CVE-2025-1550 detector) uses the identical model. Verified
live in `keras_model_scan.py` (2026-10-24):

```python
KERAS_IMPORT_ALLOWLIST = frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"})
```

For a `config.json` node with `class_name in ("function", "class")`, KMS001 computes the
module's top package and **flags it only when that package is outside the allowlist**. A node
referencing `keras.utils.get_file` therefore has top package `keras`, which *is* allowlisted,
so **KMS001 does not fire** — even though Keras itself now refuses that name. KMS002
(`__lambda__`) does not fire either, because the JFrog class deliberately uses a by-name
function reference rather than marshalled bytecode. The scanner being *more permissive than
the loader* is the durable issue: it still passes files that Keras refuses (relevant to the
pre-3.11 installed base and to `safe_mode=False` loads).

This is the exact dual of the `torch.*` pickle finding: a whole-group allowlist is immune to
submodule-renaming bypasses (good) but structurally cannot catch a dangerous callable that
genuinely lives inside the trusted group.

## Candidate in-allowlist gadgets (source-reviewed)

The table below is kept for the record; the live-status column reflects the 2026-10-24
re-review. The concrete, false-positive-aware detector now lives in the follow-up note.

| dotted name | effect at load time | live on current release? |
|---|---|---|
| `keras.utils.get_file` | download attacker `origin` URL + extract archive (SSRF / file drop) | **no** — denied by `LOADING_APIS`/`NON_MODELING_APIS` (≥ 3.11) |
| `keras.utils.load_img` | read an arbitrary filesystem path | no — in both denylists |
| `keras.utils.save_img` | write an arbitrary filesystem path | no — in `NON_MODELING_APIS` |
| `keras.config.enable_unsafe_deserialization` | flip the global unsafe-deserialization flag | no — in both denylists (also `KMS003` string match) |
| `keras.layers.StringLookup` / `IntegerLookup` | read attacker `vocabulary` path/URL (CVE-2025-12058) | **mitigated on v3.12.4 under safe mode; live on ≤ 3.11.x and on `safe_mode=False`** |
| `keras.layers.TextVectorization` | read attacker `vocabulary` path via the inner `StringLookup` (CVE-2025-12058 class), carried under its own class name | **mitigated on current release under safe mode (delegates to the guarded path); live on ≤ 3.11.x and `safe_mode=False`** |
| `keras_hub` `WordPieceTokenizer` / `SentencePieceTokenizer` / `BytePairTokenizer` | read attacker `vocabulary`/`proto`/`merges` path (CVE-2025-12058 class) | **guarded on current keras_hub under safe mode; live on `safe_mode=False` and older versions** |
| `keras.layers.TFSMLayer` | load an external SavedModel | caught by `KMS004` |

## The fix (defense in depth the real loader does not do)

A scanner can be **stricter than the Keras loader**: keep the allowlist, but add Keras's own
by-name denylist (`LOADING_APIS ∪ NON_MODELING_APIS`) plus a marker for the vocabulary-path
class (core layers, `TextVectorization`, and keras_hub tokenizers), so a crafted node is
flagged even when the running Keras would refuse it anyway — which protects users on older
Keras and `safe_mode=False` loads. The standalone
[`keras_allowlist_gadget_blindspot.py`](keras_allowlist_gadget_blindspot.py) modelled the
original observation; the version-aware successor is
[`keras_deserialization_io_blindspot.py`](keras_deserialization_io_blindspot.py).

## Why this is new

JFrog disclosed the *Keras* residual gadget. No prior work maps that residual class, and its
subsequent mitigation, onto a model-file *scanner's* detection coverage across Keras versions
— i.e. shows that a scanner which copies only Keras's 3.9 namespace allowlist lags the loader
by later mitigations, so a clean result is not evidence of safety for the large pre-3.11
installed base or for `safe_mode=False` loads. That mapping, plus a scan-time fix sourced from
Keras's own denylists, is the contribution.

## Honest limits

- Source review only; this is **not** a vulnerability report against Keras. `get_file` was
  disclosed by JFrog and has since been denied by name; CVE-2025-12058 was disclosed via
  Huntr and is guarded under safe mode on v3.12.4.
- No novel vulnerability is claimed, and nothing here, by itself, earns a bounty.
- The demonstrators are faithful *models* of KMS001's rule pinned to source read on
  2026-10-24; they will drift if either project changes. The actual scanner fix is queued
  behind the in-flight v0.48.0 release so scanner edits stay serialized.

## Reproduce

```
python keras_deserialization_io_blindspot.py          # current-vs-proposed matrix (version-aware)
python -m unittest test_keras_deserialization_io_blindspot -v
```
