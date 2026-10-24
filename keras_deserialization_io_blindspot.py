# Copyright 2026 Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working in the name of MV2 of Munim, Inc.
"""Version-aware demonstrator for a `.keras` deserialization-time I/O blind spot.

This is a **standalone model** of a proposed keras-model-scan rule (KMS006), not the
production scanner. It exists so the invariant can be pinned by a self-contained unit
test with no repository imports.

Background (all facts source-reviewed live on 2026-10-24; no model was loaded and no
code was executed against any live or hosted system):

Keras hardened `.keras` deserialization in several steps, each firing only under the
default `safe_mode=True`:

  * v3.9    - a namespace allowlist in `_retrieve_class_or_fn` (CVE-2025-1550 fix):
              a `function`/`class` node is refused unless the module's top-level
              package is in `KERAS_IMPORT_ALLOWLIST`.
  * <=v3.11 - `LOADING_APIS`, a by-name denylist of loader/utility functions that are
              inside the allowlisted `keras` namespace but still dangerous (JFrog's
              `keras.utils.get_file` download/SSRF gadget and friends). Resolving one
              raises "loading functions are not allowed during deserialization".
  * <=v3.12.4 (latest release) - a `serialization_lib.in_safe_mode()` guard inside
              `IndexLookup.set_vocabulary`, closing CVE-2025-12058: the
              StringLookup/IntegerLookup `vocabulary` argument may be a filesystem path
              or URL that is read during `__init__`, giving arbitrary file read / SSRF.
  * master  - `NON_MODELING_APIS` (31 names) supersedes `LOADING_APIS`.

keras-model-scan's `KMS001` implements only the first step - the top-package allowlist.
It therefore passes CLEAN:

  1. a `function` node naming a `LOADING_APIS`/`NON_MODELING_APIS` callable
     (top package `keras` is allowlisted); and
  2. any preprocessing-layer node (class names like `StringLookup`) - `KMS001` only
     looks at `class_name in ("function", "class")`, so a layer node is never examined,
     and no other rule inspects its `vocabulary` config.

Both are live for users on Keras 3.9-3.11.x (the large installed base) and for *anyone*
who loads with `safe_mode=False` - routine for Lambda-bearing or legacy models - even on
v3.12.4. A legitimately *saved* model never carries a string `vocabulary` (Keras
`IndexLookup.get_config` stores a resolved list, or `None` when a path was used), so a
string `vocabulary` in a config node is a high-signal, low-false-positive attack marker.

This module models the current rule (allowlist-only) and the proposed rule (adds the two
upstream denylists plus the vocabulary-path marker) so a test can pin the difference.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- Keras's own structures, copied verbatim from upstream for the denylist ---------

# CVE-2025-1550 allowlist (keras/src/saving/serialization_lib.py), what KMS001 mirrors.
KERAS_IMPORT_ALLOWLIST = frozenset({"keras", "keras_hub", "keras_cv", "keras_nlp"})

# LOADING_APIS as of keras v3.11.0 (keras/src/saving/serialization_lib.py).
LOADING_APIS = frozenset(
    {
        "keras.config.enable_unsafe_deserialization",
        "keras.models.load_model",
        "keras.preprocessing.image.load_img",
        "keras.saving.load_model",
        "keras.saving.load_weights",
        "keras.utils.get_file",
        "keras.utils.load_img",
    }
)

# NON_MODELING_APIS as of keras master, 2026-10-24 (supersedes LOADING_APIS); the
# authoritative by-name denylist of non-modeling callables that live inside the
# allowlisted namespaces. Copied verbatim from upstream source.
NON_MODELING_APIS = frozenset(
    {
        "keras.backend.clear_session",
        "keras.config.enable_unsafe_deserialization",
        "keras.models.load_model",
        "keras.models.model_from_json",
        "keras.models.save_model",
        "keras.preprocessing.image_dataset_from_directory",
        "keras.preprocessing.image.load_img",
        "keras.preprocessing.image.save_img",
        "keras.preprocessing.text_dataset_from_directory",
        "keras.saving.deserialize_keras_object",
        "keras.saving.load_model",
        "keras.saving.load_weights",
        "keras.saving.register_keras_serializable",
        "keras.saving.save_model",
        "keras.saving.save_weights",
        "keras.saving.serialize_keras_object",
        "keras.utils.audio_dataset_from_directory",
        "keras.utils.clear_session",
        "keras.utils.deserialize_keras_object",
        "keras.utils.get_file",
        "keras.utils.image_dataset_from_directory",
        "keras.utils.load_img",
        "keras.utils.model_to_dot",
        "keras.utils.plot_model",
        "keras.utils.register_keras_serializable",
        "keras.utils.save_img",
        "keras.utils.serialize_keras_object",
        "keras.utils.text_dataset_from_directory",
        "keras.visualization.plot_bounding_box_gallery",
        "keras.visualization.plot_image_gallery",
        "keras.visualization.plot_segmentation_mask_gallery",
    }
)

# The union is what a scan-time denylist should carry (both historic and current names).
KERAS_NONMODELING_DENYLIST = LOADING_APIS | NON_MODELING_APIS

# Preprocessing layers whose __init__ -> set_vocabulary reads an attacker-controlled
# file path / URL at deserialization time (CVE-2025-12058). IndexLookup is the shared
# base; StringLookup and IntegerLookup are its public subclasses.
VOCAB_IO_LAYERS = frozenset({"StringLookup", "IntegerLookup", "IndexLookup"})


@dataclass(frozen=True)
class Verdict:
    """A single rule's decision for one config node."""

    flagged: bool
    rule: str  # "" when not flagged
    reason: str  # "" when not flagged


def _top_package(module: str) -> str:
    """Top-level package of a dotted module path (mirrors the scanner helper)."""
    return (module or "").split(".", 1)[0]


def _api_name(node: dict) -> str:
    """Fully-qualified callable name a `function`/`class` node resolves to.

    Keras builds this as `f"{module}.{name}"`; in a `.keras` config a `function` node
    carries the dotted name in `config` and the package in `module`.
    """
    module = node.get("module") or ""
    name = node.get("config")
    if not isinstance(name, str):
        name = node.get("class_name", "")
    if module and isinstance(name, str) and name.startswith(module + "."):
        return name
    if module and isinstance(name, str):
        return f"{module}.{name}" if "." not in name else name
    return name if isinstance(name, str) else ""


def classify_current(node: dict) -> Verdict:
    """Model of keras-model-scan KMS001 as shipped (v0.47.0): top-package allowlist only.

    Fires only for a `function`/`class` node whose module's top package is NOT in the
    allowlist. Anything inside the `keras` namespace, and every ordinary layer node, is
    treated as clean.
    """
    class_name = node.get("class_name")
    module = node.get("module")
    if class_name in ("function", "class") and module:
        if _top_package(module) not in KERAS_IMPORT_ALLOWLIST:
            return Verdict(True, "KMS001", f"non-Keras module {module!r}")
    return Verdict(False, "", "")


def classify_proposed(node: dict) -> Verdict:
    """Proposed version-aware rule set: KMS001 plus KMS006 (this module's contribution).

    KMS006 flags two in-namespace gadget shapes that the top-package allowlist misses but
    that Keras itself refuses (under safe_mode) in current versions:

      a. a `function`/`class` node resolving to a name in Keras's own
         LOADING_APIS / NON_MODELING_APIS denylist (e.g. `keras.utils.get_file`);
      b. a StringLookup/IntegerLookup/IndexLookup layer node whose `vocabulary` config is
         a string (a file path or URL), the CVE-2025-12058 arbitrary-file-read/SSRF marker.

    A scanner can be stricter than the loader: it flags these regardless of the target's
    Keras version or safe_mode setting, protecting the older installed base and anyone who
    loads with safe_mode=False.
    """
    # KMS001 first - a node from a disallowed namespace is still HIGH/MED.
    current = classify_current(node)
    if current.flagged:
        return current

    class_name = node.get("class_name")

    # KMS006 (a): in-namespace non-modeling callable (get_file class).
    if class_name in ("function", "class"):
        api = _api_name(node)
        if api in KERAS_NONMODELING_DENYLIST:
            return Verdict(
                True,
                "KMS006",
                f"in-namespace non-modeling API {api!r} "
                f"(Keras refuses this under safe_mode; live on <=3.10 or safe_mode=False)",
            )

    # KMS006 (b): vocabulary-path preprocessing layer (CVE-2025-12058).
    if class_name in VOCAB_IO_LAYERS:
        cfg = node.get("config")
        vocab = cfg.get("vocabulary") if isinstance(cfg, dict) else node.get("vocabulary")
        if isinstance(vocab, str) and vocab.strip():
            return Verdict(
                True,
                "KMS006",
                f"{class_name} vocabulary is a path/URL {vocab!r} "
                f"(CVE-2025-12058 file-read/SSRF; legit saves store a list, never a string)",
            )

    return Verdict(False, "", "")


# --- demonstrator ------------------------------------------------------------------

_DEMO_NODES = [
    {
        "name": "benign dense layer",
        "node": {"class_name": "Dense", "module": "keras.layers",
                 "config": {"units": 64}},
    },
    {
        "name": "benign StringLookup (inline vocabulary list)",
        "node": {"class_name": "StringLookup", "module": "keras.layers",
                 "config": {"vocabulary": ["a", "b", "c"]}},
    },
    {
        "name": "get_file function node (JFrog gadget class)",
        "node": {"class_name": "function", "module": "keras.utils",
                 "config": "keras.utils.get_file"},
    },
    {
        "name": "StringLookup vocabulary path (CVE-2025-12058)",
        "node": {"class_name": "StringLookup", "module": "keras.layers",
                 "config": {"vocabulary": "/etc/passwd"}},
    },
    {
        "name": "non-Keras function node (caught by KMS001 already)",
        "node": {"class_name": "function", "module": "os",
                 "config": "os.system"},
    },
]


def main() -> None:
    header = f"{'node':<48}{'current (KMS001)':<22}{'proposed (KMS006)'}"
    print(header)
    print("-" * len(header))
    for item in _DEMO_NODES:
        cur = classify_current(item["node"])
        pro = classify_proposed(item["node"])
        cur_s = cur.rule if cur.flagged else "clean"
        pro_s = pro.rule if pro.flagged else "clean"
        print(f"{item['name']:<48}{cur_s:<22}{pro_s}")


if __name__ == "__main__":
    main()
