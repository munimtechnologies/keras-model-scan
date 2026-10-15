# Copyright 2026 Munim, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file was made with AI by MV2 of Munim, Inc.
"""Machine-readable index of the benign / regression test corpora in this repo.

keras-model-scan ships a family of *static, no-execution* scanners for ML
model files, and alongside several of them a small corpus of hand-built
fixtures used as regression tests (benign files that must stay clean, plus
minimal precursor files that each scanner must flag). Those corpora grew one
per format; there was no single place that said which corpus belongs to which
scanner, which docs describe it, or which authoritative CVE map holds its
verified advisory identifiers.

This module is that single place. It is a pure cross-reference: every value is
a file that exists in the repository (a corpus module, a scanner module, a
documentation page, or an authoritative CVE map). It deliberately does **not**
re-assert CVE or CWE identifiers; those live, verified against GHSA/OSV/NVD, in
the cited ``*_cve_map.json`` files, which stay the single source of truth. Keep
it that way when extending this manifest: add a row that *points at* the maps,
never a second copy of an advisory identifier.

The module imports only the standard library and has no dependency on the
scanners or corpora it indexes, so it is cheap to import in CI and safe to use
as a build-time catalogue (for example, to assert that every corpus has a
matching scanner, or to generate a coverage table).

Made with AI by MV2 of Munim, Inc. Code is Apache-2.0; the catalogue data in
this file is also offered as CC BY 4.0.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple

__version__ = "0.22.0"

# The two authoritative CVE->detector maps that ship in this repository. Every
# corpus row below references exactly one of these; verified advisory
# identifiers live there, not here.
CVE_MAPS: Tuple[str, ...] = (
    "model_file_cve_map.json",
    "gguf_cve_map.json",
)

# One row per benign / regression corpus. Fields, all of which are repository
# paths or plain-English descriptions (never advisory identifiers):
#   key            - short stable slug for the corpus
#   title          - plain-English description of what the corpus exercises
#   corpus_module  - the *_corpus.py file holding the fixtures
#   scanner_module - the *_scan.py file the corpus is a regression test for
#   corpus_doc     - the *_CORPUS.md page, or None if the corpus has no own page
#   scan_doc       - a *.md page describing the scanner / its rules
#   cve_map        - the authoritative CVE map (one of CVE_MAPS) for this family
_ROWS: Tuple[Dict[str, Optional[str]], ...] = (
    {
        "key": "archive_bomb",
        "title": "Benign regression corpus for the decompression / archive-bomb scanner",
        "corpus_module": "archive_bomb_corpus.py",
        "scanner_module": "archive_bomb_scan.py",
        "corpus_doc": None,
        "scan_doc": "ARCHIVE_BOMB_SCAN.md",
        "cve_map": "model_file_cve_map.json",
    },
    {
        "key": "chat_template",
        "title": "Benign regression corpus for the chat-template (Jinja) SSTI scanner",
        "corpus_module": "chat_template_corpus.py",
        "scanner_module": "chat_template_scan.py",
        "corpus_doc": "CHAT_TEMPLATE_CORPUS.md",
        "scan_doc": "CHAT_TEMPLATE_SCAN.md",
        "cve_map": "model_file_cve_map.json",
    },
    {
        "key": "gguf_chat_template",
        "title": "Benign regression corpus for the GGUF-embedded chat-template SSTI scanner",
        "corpus_module": "gguf_chat_template_corpus.py",
        "scanner_module": "gguf_chat_template_scan.py",
        "corpus_doc": "GGUF_CHAT_TEMPLATE_CORPUS.md",
        "scan_doc": "GGUF_CHAT_TEMPLATE_SCAN.md",
        "cve_map": "model_file_cve_map.json",
    },
    {
        "key": "gguf_cve",
        "title": "Regression corpus of GGUF header memory-safety precursors for the GGUF scanner",
        "corpus_module": "gguf_cve_corpus.py",
        "scanner_module": "gguf_scan.py",
        "corpus_doc": None,
        "scan_doc": "GGUF_CVE_MAP.md",
        "cve_map": "gguf_cve_map.json",
    },
    {
        "key": "hf_config_injection",
        "title": "Benign regression corpus for the Hugging Face config-injection scanner",
        "corpus_module": "hf_config_injection_corpus.py",
        "scanner_module": "hf_config_injection_scan.py",
        "corpus_doc": "HF_CONFIG_INJECTION_CORPUS.md",
        "scan_doc": "HF_CONFIG_INJECTION_SCAN.md",
        "cve_map": "model_file_cve_map.json",
    },
    {
        "key": "onnx_external_data",
        "title": "Benign regression corpus for the ONNX external_data path-traversal scanner",
        "corpus_module": "onnx_external_data_corpus.py",
        "scanner_module": "onnx_external_data_scan.py",
        "corpus_doc": "ONNX_EXTERNAL_DATA_CORPUS.md",
        "scan_doc": "ONNX_EXTERNAL_DATA_SCAN.md",
        "cve_map": "model_file_cve_map.json",
    },
    {
        "key": "onnx_external_data_key",
        "title": "Benign regression corpus for the ONNX external_data unexpected-key scanner",
        "corpus_module": "onnx_external_data_key_corpus.py",
        "scanner_module": "onnx_external_data_key_scan.py",
        "corpus_doc": "ONNX_EXTERNAL_DATA_KEY_CORPUS.md",
        "scan_doc": "ONNX_EXTERNAL_DATA_KEY_SCAN.md",
        "cve_map": "model_file_cve_map.json",
    },
)

# Public, read-only view. Tuple of dicts so callers cannot mutate the catalogue
# in place by accident.
CORPORA: Tuple[Dict[str, Optional[str]], ...] = tuple(dict(r) for r in _ROWS)

_REQUIRED_KEYS: Tuple[str, ...] = (
    "key",
    "title",
    "corpus_module",
    "scanner_module",
    "corpus_doc",
    "scan_doc",
    "cve_map",
)


def keys() -> List[str]:
    """Return the stable slug of every corpus, in manifest order."""
    return [row["key"] for row in CORPORA]  # type: ignore[misc]


def get(key: str) -> Dict[str, Optional[str]]:
    """Return a copy of the row for ``key`` (raises KeyError if unknown)."""
    for row in CORPORA:
        if row["key"] == key:
            return dict(row)
    raise KeyError(key)


def corpus_modules() -> List[str]:
    """Return every ``*_corpus.py`` fixture module, in manifest order."""
    return [row["corpus_module"] for row in CORPORA]  # type: ignore[misc]


def scanner_modules() -> List[str]:
    """Return the ``*_scan.py`` scanner each corpus is a regression test for.

    The list may contain duplicates when two corpora exercise one scanner.
    """
    return [row["scanner_module"] for row in CORPORA]  # type: ignore[misc]


def docs() -> List[str]:
    """Return every documentation page referenced, de-duplicated and sorted."""
    pages = set()
    for row in CORPORA:
        if row["corpus_doc"]:
            pages.add(row["corpus_doc"])
        if row["scan_doc"]:
            pages.add(row["scan_doc"])
    return sorted(pages)


def by_cve_map(cve_map: str) -> List[Dict[str, Optional[str]]]:
    """Return copies of every row whose authoritative CVE map is ``cve_map``."""
    if cve_map not in CVE_MAPS:
        raise KeyError(cve_map)
    return [dict(row) for row in CORPORA if row["cve_map"] == cve_map]


def as_list() -> List[Dict[str, Optional[str]]]:
    """Return the whole manifest as a list of row copies."""
    return [dict(row) for row in CORPORA]


def to_json(indent: int = 2) -> str:
    """Serialise the manifest to a JSON string."""
    payload = {
        "name": "keras-model-scan-corpus-manifest",
        "version": __version__,
        "cve_maps": list(CVE_MAPS),
        "corpora": as_list(),
    }
    return json.dumps(payload, indent=indent, sort_keys=False)


if __name__ == "__main__":  # pragma: no cover - small CLI convenience
    print(to_json())
