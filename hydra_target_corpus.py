# SPDX-License-Identifier: Apache-2.0
# Part of munimtechnologies/keras-model-scan by MV2, Munim, Inc.
# This file was made with AI.
"""Generate a small corpus of config files exercising the Hydra ``_target_``,
pyannote ``pipeline: name:`` and sentence-transformers ``modules.json`` ``type``
config-injection detectors in ``hydra_target_scan.py``.

Every "malicious" fixture carries an INERT payload (echo / a benign class path): the
files are only ever read as text/JSON by the static scanner and are never handed to
``hydra.utils.instantiate()``, ``Pipeline.from_pretrained()`` or
``SentenceTransformer(...)``. The corpus documents already-public vulnerability
classes (CVE-2026-22584, CVE-2025-23304, GHSA-mwj6-rfh8-7qf4, pyannote-audio
issues #2000 / #2019, CVE-2026-68770 / GHSA-jhr6-gm9c-rqjv); it is for regression
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
    "pipeline_json_config.json": (
        {"pipeline": {"name": "subprocess.Popen", "params": {"args": ["echo", "inert"]}}},
        "HYD004",
        "pyannote-style pipeline.name in JSON -> HIGH",
    ),
    # a non-modules.json file carrying a 'type' key must NOT raise HYD005
    "type_key_config.json": (
        {"model_type": "bert", "type": "my_pkg.custom.Module", "hidden_size": 8},
        None,
        "'type' outside modules.json is not a module class reference -> no finding",
    ),
}

# sentence-transformers modules.json fixtures (HYD005, CVE-2026-68770). The detector
# keys off the exact filename ``modules.json``, so each fixture is written as a
# ``modules.json`` inside its own subdirectory.
# subdir -> (content list, expected_top_finding_id or None, note)
MODULES_FIXTURES = {
    "st_clean": (
        [
            {"idx": 0, "name": "0", "path": "",
             "type": "sentence_transformers.models.Transformer"},
            {"idx": 1, "name": "1", "path": "1_Pooling",
             "type": "sentence_transformers.models.Pooling"},
        ],
        "HYD005",
        "all modules.json types inside the sentence_transformers namespace -> LOW only",
    ),
    "st_foreign": (
        [
            {"idx": 0, "name": "0", "path": "",
             "type": "sentence_transformers.models.Transformer"},
            {"idx": 1, "name": "1", "path": "custom", "type": "my_pkg.custom.Module"},
        ],
        "HYD005",
        "a modules.json type outside the ST namespace -> MEDIUM (CVE-2026-68770 class)",
    ),
    "st_exec": (
        [
            {"idx": 0, "name": "0", "path": "", "type": "subprocess.Popen"},
        ],
        "HYD005",
        "modules.json type resolving to a code-exec callable -> HIGH",
    ),
}


def modules_fixture_path(out_dir: str, subdir: str) -> str:
    """Absolute path of the modules.json written for a MODULES_FIXTURES entry."""
    return os.path.join(out_dir, subdir, "modules.json")

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
    "pyannote_clean.yaml": (
        "version: 3.1.0\n"
        "pipeline:\n"
        "  name: pyannote.audio.pipelines.SpeakerDiarization\n"
        "  params:\n"
        "    clustering: AgglomerativeClustering\n"
        "    segmentation_batch_size: 32\n"
        "params:\n"
        "  segmentation:\n"
        "    min_duration_off: 0.0\n",
        "HYD004",
        "pyannote pipeline class inside the pyannote namespace -> LOW only",
    ),
    "pyannote_popen.yaml": (
        "version: 3.1.0\n"
        "pipeline:\n"
        "  name: 'subprocess.Popen'  # inert fixture, never loaded\n"
        "  params:\n"
        "    args: [echo, inert]\n",
        "HYD004",
        "pipeline.name resolves to subprocess.Popen -> HIGH (issue #2000 class)",
    ),
    "pyannote_foreign.yaml": (
        "pipeline:\n"
        "  params:\n"
        "    threshold: 0.5\n"
        "  name: my_pkg.pipelines.Custom\n",
        "HYD004",
        "pipeline.name outside the pyannote namespace -> MEDIUM",
    ),
    "pyannote_preprocessor.yaml": (
        "pipeline:\n"
        "  name: SpeakerDiarization\n"
        "preprocessors:\n"
        "  audio:\n"
        "    name: os.system\n"
        "    params:\n"
        "      command: echo inert\n",
        "HYD004",
        "preprocessors.<key>.name -> HIGH; bare pipeline name -> LOW",
    ),
    "dataset.yaml": (
        "dataset:\n"
        "  name: subprocess.Popen\n"
        "pipeline_name: os.system\n"
        "name: os.system\n",
        None,
        "'name' keys outside pipeline/preprocessors are not class references",
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
    for subdir, (content, expect, note) in MODULES_FIXTURES.items():
        path = modules_fixture_path(out_dir, subdir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(content, f, indent=1)
        manifest["fixtures"].append({"file": f"{subdir}/modules.json",
                                     "expect_top_id": expect, "note": note})
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
