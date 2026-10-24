# Copyright 2026 Munim, Inc.
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working in the name of MV2 of Munim, Inc.
"""Model of the Keras-style whole-namespace import allowlist and its blind spot.

Both Keras's own post-CVE-2025-1550 deserialization guard (Keras 3.9+, in
``_retrieve_class_or_fn``) and keras-model-scan's ``KMS001`` detector trust a
callable whenever its top-level package is one of
``{keras, keras_hub, keras_cv, keras_nlp}``. JFrog showed that the ``keras``
package itself ships callables with load-time side effects (e.g.
``keras.utils.get_file``, which downloads an attacker-supplied URL and extracts
archives), so a crafted ``config.json`` can name one of those callables and have
it executed at ``load_model`` time without any marshalled bytecode -- evading
both the namespace allowlist and the ``__lambda__`` bytecode guard.

This module is a faithful, source-dated *model* of that rule. It performs no I/O
and imports nothing but the standard library; it loads no model and executes no
Keras code. It exists to pin the invariant that a whole-namespace allowlist
cannot catch an in-namespace gadget, and to show a defense-in-depth rule that
can. Source read 2026-10-24: keras_model_scan.py v0.47.0 and Keras master.
"""

from __future__ import annotations

# Verbatim from keras_model_scan.py (v0.47.0) and Keras 3.9+ _retrieve_class_or_fn.
KERAS_IMPORT_ALLOWLIST = frozenset(
    {"keras", "keras_hub", "keras_cv", "keras_nlp"}
)

# Callables that live INSIDE the allowlisted namespaces and have load-time side
# effects (download / file read-write / unsafe-deserialization toggle / external
# SavedModel load). Source-reviewed against Keras master on 2026-10-24. The first
# entry is JFrog's disclosed gadget; the rest are candidates for a scan-time
# denylist, not confirmed end-to-end exploit chains.
KERAS_GADGET_CALLABLES = frozenset(
    {
        "keras.utils.get_file",  # downloads origin URL, extracts archives
        "keras.utils.load_img",  # reads an arbitrary filesystem path
        "keras.utils.save_img",  # writes an arbitrary filesystem path
        "keras.config.enable_unsafe_deserialization",  # flips global unsafe flag
        "keras.saving.load_model",  # recursive model load
        "keras.models.load_model",
    }
)


def top_package(module: str) -> str:
    """Return the top-level package of a dotted module path (KMS001's rule)."""
    return module.split(".", 1)[0] if module else ""


def classify_current(module: str, name: str = "") -> str:
    """Model keras-model-scan KMS001 (v0.47.0).

    A ``function``/``class`` config node is flagged only when its module's top
    package is outside the allowlist. An in-namespace gadget is marked benign --
    this return value *is* the blind spot.
    """
    if top_package(module) in KERAS_IMPORT_ALLOWLIST:
        return "benign"
    return "flag"


def classify_proposed(module: str, name: str = "") -> str:
    """Proposed defense-in-depth rule, strictly safer than the Keras loader.

    Keep the allowlist, but flag a specific dotted callable on the in-namespace
    gadget denylist even when its package is allowlisted.
    """
    dotted = f"{module}.{name}" if name else module
    if dotted in KERAS_GADGET_CALLABLES:
        return "flag"
    if top_package(module) in KERAS_IMPORT_ALLOWLIST:
        return "benign"
    return "flag"


# (module, name, human label) rows for the printed matrix.
_CASES = [
    ("keras.utils", "get_file", "JFrog in-namespace gadget (SSRF/file drop)"),
    ("keras.config", "enable_unsafe_deserialization", "unsafe-mode toggle"),
    ("keras.saving", "load_model", "recursive model load"),
    ("keras.layers", "Dense", "genuinely benign keras layer"),
    ("subprocess", "Popen", "outside-allowlist RCE (CVE-2025-1550 shape)"),
]


def matrix() -> list[dict]:
    """Return a provenance-labelled classification matrix for the cases above."""
    rows = []
    for module, name, label in _CASES:
        rows.append(
            {
                "module": module,
                "name": name,
                "label": label,
                "current": classify_current(module, name),
                "proposed": classify_proposed(module, name),
            }
        )
    return rows


if __name__ == "__main__":
    import json

    print(json.dumps({"source_read": "2026-10-24", "matrix": matrix()}, indent=2))
