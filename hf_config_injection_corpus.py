#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Made with AI by MV2 of Munim, Inc.
"""Benign regression corpus for Hugging Face config-injection detection.

This module generates a small, self-contained set of crafted — but completely
harmless — Hugging Face model configuration files that exercise every branch of
a config-injection scanner for CVE-2026-4372 / GHSA-29pf-2h5f-8g72
(transformers < 5.3.0, CWE-502 / CWE-94).

Background (all public):
    `transformers` selects an attention/experts kernel from the model config.
    An attacker who can edit a model's `config.json` can set the
    underscore-prefixed internal fields ``_attn_implementation_internal`` or
    ``_experts_implementation_internal`` to a value that reaches an import of
    attacker-named Python *without* the user passing ``trust_remote_code=True``.
    A legitimately serialised config never contains these fields, so their mere
    presence is a high-confidence injection indicator. The separate
    ``auto_map`` / ``custom_pipeline`` / ``auto_pipeline`` fields point to
    custom Python that runs only under ``trust_remote_code=True``; they are
    normal for custom-architecture models and are informational, not a vuln.

What this corpus is for:
    Every scanner needs a fixed, reproducible set of inputs with known-correct
    expected findings so a regression test can prove it still flags each vector
    and still leaves clean files clean. These files contain no executable
    payload of any kind — only JSON strings — so they are safe to commit, copy
    and share. Nothing here is a zero-day: every identifier is already public.

Pairs with ``hf_config_injection_scan.py`` (the scanner) in this repository.
The expected finding codes below match that scanner's HCI000/HCI001/HCI002/
HCI003 taxonomy.

Usage:
    python hf_config_injection_corpus.py --out-dir ./corpus_hf_config

Code: Apache-2.0. This docstring and the emitted manifest data: CC BY 4.0.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List, Optional

__version__ = "0.17.0"

# The field names a config-injection scanner keys on. Kept here so the paired
# test can assert the corpus (and nothing else) carries them.
HIGH_FIELDS = ("_attn_implementation_internal", "_experts_implementation_internal")
INFO_FIELDS = ("auto_map", "custom_pipeline", "auto_pipeline")

# A Hub-id-shaped value ("owner/repo"), used to exercise the scanner's
# "value matches the owner/repo Hub-id shape" note. It references a repo that
# does not exist; nothing is fetched or executed.
_HUB_ID_VALUE = "munim-inc/does-not-exist-benign-fixture"


def _clean_base() -> Dict[str, Any]:
    """A plausible, well-formed transformers config with no injection fields."""
    return {
        "architectures": ["LlamaForCausalLM"],
        "model_type": "llama",
        "hidden_size": 4096,
        "num_attention_heads": 32,
        "num_hidden_layers": 32,
        "vocab_size": 32000,
        "torch_dtype": "float16",
        "transformers_version": "5.2.0",
    }


# Each entry fully describes one corpus file: the file written, which fields
# make it interesting, and the finding a correct scanner must report. The
# `content` is either a dict (serialised as JSON) or, for the malformed case, a
# raw string written verbatim so it cannot parse as JSON.
CORPUS: List[Dict[str, Any]] = [
    {
        "filename": "clean_control.json",
        "expected_code": None,
        "expected_severity": "CLEAN",
        "trigger_fields": [],
        "cwe": [],
        "note": "Well-formed config with no injection fields; a scanner must leave it clean.",
        "content": _clean_base(),
    },
    {
        "filename": "attn_internal.json",
        "expected_code": "HCI001",
        "expected_severity": "HIGH",
        "trigger_fields": ["_attn_implementation_internal"],
        "cwe": ["CWE-502", "CWE-94"],
        "note": "Top-level _attn_implementation_internal: the CVE-2026-4372 attention-kernel vector.",
        "content": {**_clean_base(), "_attn_implementation_internal": "flash_attention_2"},
    },
    {
        "filename": "experts_internal.json",
        "expected_code": "HCI002",
        "expected_severity": "HIGH",
        "trigger_fields": ["_experts_implementation_internal"],
        "cwe": ["CWE-502", "CWE-94"],
        "note": "Top-level _experts_implementation_internal: the MoE-experts-kernel vector.",
        "content": {**_clean_base(), "model_type": "mixtral",
                    "_experts_implementation_internal": "megablocks"},
    },
    {
        "filename": "nested_attn_internal.json",
        "expected_code": "HCI001",
        "expected_severity": "HIGH",
        "trigger_fields": ["_attn_implementation_internal"],
        "cwe": ["CWE-502", "CWE-94"],
        "note": "Injection field inside a nested sub-config (text_config); exercises dict recursion.",
        "content": {
            **_clean_base(),
            "model_type": "llava",
            "text_config": {
                "model_type": "llama",
                "hidden_size": 4096,
                "_attn_implementation_internal": "eager",
            },
        },
    },
    {
        "filename": "nested_list_experts.json",
        "expected_code": "HCI002",
        "expected_severity": "HIGH",
        "trigger_fields": ["_experts_implementation_internal"],
        "cwe": ["CWE-502", "CWE-94"],
        "note": "Injection field inside a dict within a list; exercises list recursion.",
        "content": {
            **_clean_base(),
            "model_type": "ensemble",
            "sub_configs": [
                {"model_type": "llama", "hidden_size": 4096},
                {"model_type": "mixtral", "_experts_implementation_internal": "eager"},
            ],
        },
    },
    {
        "filename": "hubid_value.json",
        "expected_code": "HCI001",
        "expected_severity": "HIGH",
        "trigger_fields": ["_attn_implementation_internal"],
        "cwe": ["CWE-502", "CWE-94"],
        "note": "Injection field whose value matches the owner/repo Hub-id shape; exercises the Hub-id note.",
        "content": {**_clean_base(), "_attn_implementation_internal": _HUB_ID_VALUE},
    },
    {
        "filename": "model_index_experts.json",
        "expected_code": "HCI002",
        "expected_severity": "HIGH",
        "trigger_fields": ["_experts_implementation_internal"],
        "cwe": ["CWE-502", "CWE-94"],
        "note": "diffusers-style model_index with an injection field; exercises model_index.json handling.",
        "content": {
            "_class_name": "StableDiffusionPipeline",
            "_diffusers_version": "0.31.0",
            "unet": ["diffusers", "UNet2DConditionModel"],
            "vae": ["diffusers", "AutoencoderKL"],
            "_experts_implementation_internal": "megablocks",
        },
    },
    {
        "filename": "auto_map.json",
        "expected_code": "HCI003",
        "expected_severity": "INFO",
        "trigger_fields": ["auto_map"],
        "cwe": ["CWE-94"],
        "note": "auto_map points to custom Python under trust_remote_code; informational, not a vuln.",
        "content": {
            **_clean_base(),
            "model_type": "custom",
            "auto_map": {
                "AutoConfig": "configuration_custom.CustomConfig",
                "AutoModelForCausalLM": "modeling_custom.CustomForCausalLM",
            },
        },
    },
    {
        "filename": "custom_pipeline.json",
        "expected_code": "HCI003",
        "expected_severity": "INFO",
        "trigger_fields": ["custom_pipeline"],
        "cwe": ["CWE-94"],
        "note": "custom_pipeline names a remote pipeline module; informational, not a vuln.",
        "content": {**_clean_base(), "custom_pipeline": "my_pipeline"},
    },
    {
        "filename": "auto_pipeline.json",
        "expected_code": "HCI003",
        "expected_severity": "INFO",
        "trigger_fields": ["auto_pipeline"],
        "cwe": ["CWE-94"],
        "note": "auto_pipeline names a remote pipeline module; informational, not a vuln.",
        "content": {**_clean_base(), "auto_pipeline": "my_auto_pipeline"},
    },
    {
        "filename": "malformed.json",
        "expected_code": "HCI000",
        "expected_severity": "ERROR",
        "trigger_fields": [],
        "cwe": [],
        "note": "Not valid JSON (truncated); a scanner must report a parse error, not crash.",
        "content": '{"model_type": "llama", "hidden_size": 4096,',  # raw string: deliberately broken
    },
]


def find_fields(obj: Any, names: tuple) -> List[str]:
    """Return the subset of `names` that appear as a dict key anywhere in `obj`."""
    found: set = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in names:
                    found.add(key)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    return sorted(found)


def write_corpus(out_dir: str) -> Dict[str, Any]:
    """Write every corpus file plus manifest.json into `out_dir`.

    Returns the manifest dict that was written.
    """
    os.makedirs(out_dir, exist_ok=True)
    entries: List[Dict[str, Any]] = []
    for spec in CORPUS:
        path = os.path.join(out_dir, spec["filename"])
        content = spec["content"]
        if isinstance(content, str):
            # Malformed case: write the raw (invalid-JSON) bytes verbatim.
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(content, fh, indent=2, sort_keys=True)
                fh.write("\n")
        entries.append({
            "filename": spec["filename"],
            "expected_code": spec["expected_code"],
            "expected_severity": spec["expected_severity"],
            "trigger_fields": spec["trigger_fields"],
            "cwe": spec["cwe"],
            "note": spec["note"],
        })

    manifest = {
        "corpus": "hf_config_injection",
        "version": __version__,
        "cve": "CVE-2026-4372",
        "advisory": "GHSA-29pf-2h5f-8g72",
        "affected": "transformers < 5.3.0",
        "cwe": ["CWE-502", "CWE-94"],
        "high_fields": list(HIGH_FIELDS),
        "info_fields": list(INFO_FIELDS),
        "scanner": "hf_config_injection_scan.py",
        "finding_codes": {
            "HCI000": "ERROR - config file cannot be parsed as JSON",
            "HCI001": "HIGH - _attn_implementation_internal present",
            "HCI002": "HIGH - _experts_implementation_internal present",
            "HCI003": "INFO - auto_map / custom_pipeline / auto_pipeline present",
        },
        "note": "Benign regression corpus. No executable payload; JSON strings only. "
                "Made with AI by MV2 of Munim, Inc. Code Apache-2.0; manifest data CC BY 4.0.",
        "files": entries,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the benign HF config-injection regression corpus "
                    "(CVE-2026-4372). Made with AI by MV2 of Munim, Inc.",
    )
    parser.add_argument(
        "--out-dir", default="./corpus_hf_config",
        help="directory to write the corpus and manifest.json into",
    )
    args = parser.parse_args(argv)
    manifest = write_corpus(args.out_dir)
    highs = sum(1 for f in manifest["files"] if f["expected_severity"] == "HIGH")
    infos = sum(1 for f in manifest["files"] if f["expected_severity"] == "INFO")
    print(
        f"Wrote {len(manifest['files'])} files + manifest.json to {args.out_dir} "
        f"({highs} HIGH, {infos} INFO, 1 ERROR, 1 clean control)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
