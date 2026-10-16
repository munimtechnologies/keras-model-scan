# SPDX-License-Identifier: Apache-2.0
# Part of munimtechnologies/keras-model-scan by MV2, Munim, Inc.
# This file was made with AI.
"""Generate a small corpus of config files exercising the Hydra ``_target_``
config-injection detector in ``hydra_target_scan.py``.

Every "malicious" fixture carries an INERT payload (echo / a benign class path): the
files are only ever read as text/JSON by the static scanner and are never handed to
``hydra.utils.instantiate()``. The corpus documents an already-public vulnerability
class (CVE-2026-22584, CVE-2025-23304, GHSA-mwj6-rfh8-7qf4); it is for regression
testing a defensive scanner, not for exploitation.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Dict

# filename -> (content, expected_top_finding_id or None, note)
JSON_FIXTURES = {
    "clean_config.json": (
        {"model_type": "bert", "hidden_size": 768, "num_labels": 3},
        None,
        "benign HF config, no _target_",
    ),
    "exec_config.json": (
        {"model_type": "x", "scheduler": {"_target_": "builtins.exec",
                                           "_args_": ["print('inert')"]}},
        "HYD001",
        "builtins.exec as _target_ -> HIGH (CVE-2026-22584 class)",
    ),
    "subprocess_config.json": (
        {"callback": {"_target_": "subprocess.Popen", "_args_": [["echo", "inert"]]}},
        "HYD001",
        "subprocess.Popen as _target_ -> HIGH",
    ),
    "ossystem_nested_config.json": (
        {"a": {"b": [{"_target_": "os.system", "_args_": ["echo inert"]}]}},
        "HYD001",
        "os.system nested inside a list -> HIGH, tests recursive walk",
    ),
    "generic_target_config.json": (
        {"optimizer": {"_target_": "my_pkg.custom.Thing", "lr": 0.1}},
        "HYD002",
        "unknown dotted callable -> MEDIUM (presence is the risk signal)",
    ),
    "safe_optim_config.json": (
        {"optimizer": {"_target_": "torch.optim.Adam", "lr": 0.001}},
        "HYD002",
        "known-benign torch optimizer -> LOW severity HYD002 (allowlisted prefix)",
    ),
    "helper_only_config.json": (
        {"section": {"_partial_": True, "_recursive_": False, "value": 1}},
        "HYD003",
        "Hydra helper keys without _target_ -> INFO corroboration",
    ),
}

YAML_FIXTURES = {
    "train.yaml": (
        "trainer:\n  _target_: os.system\n  _args_:\n    - echo inert\n",
        "HYD001",
        "YAML _target_: os.system -> HIGH via dependency-free text scan",
    ),
    "model.yaml": (
        "model:\n  _target_: my_project.models.Encoder\n  dim: 512\n",
        "HYD002",
        "YAML generic _target_ -> MEDIUM",
    ),
}


def write_corpus(out_dir: str) -> Dict:
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"fixtures": []}
    for name, (content, expect, note) in JSON_FIXTURES.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            json.dump(content, f, indent=1)
        manifest["fixtures"].append({"file": name, "expect_top_id": expect, "note": note})
    for name, (content, expect, note) in YAML_FIXTURES.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write(content)
        manifest["fixtures"].append({"file": name, "expect_top_id": expect, "note": note})
    with open(os.path.join(out_dir, "corpus_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    m = write_corpus(args.out_dir)
    print(f"[hydra_target_corpus] wrote {len(m['fixtures'])} fixtures to {args.out_dir}")


if __name__ == "__main__":
    main()
