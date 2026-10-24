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

`get_file`'s signature, verified live in `keras/src/utils/file_utils.py` (master, 2026-10-24):

```python
def get_file(fname=None, origin=None, untar=False, md5_hash=None, file_hash=None,
             cache_subdir="datasets", hash_algorithm="auto", extract=False,
             archive_format="auto", cache_dir=None, force_download=False):
```

Keras has since added archive-member path-escape filtering (`filter_safe_zipinfos`,
`filter_safe_tarinfos`, `is_link_in_dir`, the tar `data` filter). Those narrow the
*post-download* escape, but the load-time **download of an attacker URL and write into the
cache dir (SSRF + controlled file drop)** remains an intended behaviour of an allowlisted
callable.

## The finding: keras-model-scan copies the same allowlist, so it has the same blind spot

keras-model-scan's `KMS001` (the CVE-2025-1550 detector) uses the identical model. Verified
live in `keras_model_scan.py` (v0.47.0, 2026-10-24):

```python
KERAS_IMPORT_ALLOWLIST = frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"})
```

For a `config.json` node with `class_name in ("function", "class")`, KMS001 computes the
module's top package and **flags it only when that package is outside the allowlist**. A node
referencing `keras.utils.get_file` therefore has top package `keras`, which *is* allowlisted,
so **KMS001 does not fire**. KMS002 (`__lambda__`) does not fire either, because the JFrog
class deliberately uses a by-name function reference rather than marshalled bytecode. The
result: a `.keras` file weaponised with the JFrog in-namespace gadget class scans **clean**.

This is the exact dual of the `torch.*` pickle finding: a whole-group allowlist is immune to
submodule-renaming bypasses (good) but structurally cannot catch a dangerous callable that
genuinely lives inside the trusted group.

## Candidate in-allowlist gadgets (source-reviewed, for the fix denylist)

Callables exported under the allowlisted namespaces that have load-time side effects. The
first is JFrog's; the rest are enumerated here by source review of `keras.utils` /
`keras.config` / `keras.layers` on master (2026-10-24) and are candidates for a
defense-in-depth denylist, not confirmed end-to-end exploit chains:

| dotted name | effect at load time | already caught? |
|---|---|---|
| `keras.utils.get_file` | download attacker `origin` URL + extract archive (SSRF / file drop) | **no** (KMS001 allowlists `keras`) |
| `keras.utils.load_img` | read an arbitrary filesystem path | no |
| `keras.utils.save_img` | write an arbitrary filesystem path | no |
| `keras.config.enable_unsafe_deserialization` | flip the global unsafe-deserialization flag | partly — `KMS003` matches the *string* in raw text, not a `function` node |
| `keras.layers.TFSMLayer` | load an external SavedModel | yes — `KMS004` by `class_name` |
| `keras.saving.load_model` / `keras.models.load_model` | recursively load another model file | no |

## The fix (defense in depth the real loader does not do)

A scanner can be **stricter than the Keras loader**: keep the allowlist, but add an
in-namespace *gadget denylist* so KMS001 flags a specific dotted callable (e.g.
`keras.utils.get_file`) even though its package is allowlisted. This closes the JFrog class
at scan time without reintroducing the submodule-bypass risk that the broad allowlist exists
to prevent. The standalone [`keras_allowlist_gadget_blindspot.py`](keras_allowlist_gadget_blindspot.py)
models both the current rule and the proposed rule; [`test_keras_allowlist_gadget_blindspot.py`](test_keras_allowlist_gadget_blindspot.py)
pins the invariant: the current rule marks `keras.utils.get_file` benign; the proposed rule
flags it while leaving genuinely benign `keras.*` nodes (e.g. `keras.layers.Dense`) benign.

## Why this is new

JFrog disclosed the *Keras* residual gadget. No prior work maps that known residual class onto
a model-file *scanner's* detection coverage — i.e. shows that a scanner which copies Keras's
own namespace allowlist copies the gap, so a clean result is not evidence against the JFrog
class. That mapping, plus the enumerated in-namespace gadget candidates and a scan-time fix
that is strictly safer than the loader, is the contribution. It is reproducible by reading
three open-source files (`keras_model_scan.py`, Keras `file_utils.py`, and the JFrog writeup)
with no execution.

## Honest limits

- Source review only; this is **not** a vulnerability report against Keras. `get_file` was
  disclosed by JFrog and Keras has hardened archive extraction since.
- The candidate list beyond `get_file` is enumerated from the API surface; each would need a
  verified local proof of concept before any claim of an exploit chain, and none is made here.
- The demonstrator is a faithful *model* of KMS001's rule pinned to the source read on
  2026-10-24; it will drift if either project changes. The actual scanner fix is queued
  behind the in-flight v0.48.0 release so scanner edits stay serialized.

## Reproduce

```
python keras_allowlist_gadget_blindspot.py            # prints the classification matrix
python -m unittest test_keras_allowlist_gadget_blindspot -v
```
