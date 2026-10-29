# nemo_container_scan.py — NVIDIA NeMo `.nemo` tar-container scanner

`nemo_container_scan.py` is a static, dependency-free detector for NVIDIA NeMo
`.nemo` checkpoints. It opens the tar container, finds the pickle-bearing weights
inside, and disassembles them — the layer other scanners miss because they do not
untar the `.nemo` first. It is part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan) toolkit.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

## What a `.nemo` file is

A `.nemo` checkpoint is a **tar archive** (uncompressed, or gzip/bz2/xz for older
releases) bundling:

- `model_config.yaml` — the model configuration,
- `model_weights.ckpt` — a `torch.save` of the state dict (a zip holding
  `data.pkl` for torch ≥ 1.6, or a bare pickle for the legacy format),
- optional artifacts (tokenizer, vocab).

`SaveRestoreConnector.restore_from` untars the archive and `torch.load`-s the
weights. That gives an attacker two separate footholds.

## Blind spot 1 — a pickle one container deep

Opcode-only pickle scanners and magic/extension routers operate on a `.pkl`/`.pt`
*file*. They do not untar the `.nemo`, so the `__reduce__` gadget inside
`model_weights.ckpt` is never disassembled. `.nemo` is one of the 22 pickle
loading paths catalogued by *The Art of Hide and Seek* (USENIX Security '26,
[arXiv:2508.19774](https://arxiv.org/abs/2508.19774), the PickleCloak framework).
The sibling detectors in this toolkit read config **text** only and, by their own
documented limit, "do not unpack `.nemo` or `.ckpt` files." This module closes
that gap by actually opening the tar.

## Blind spot 2 — arbitrary file write on extraction (CVE-2024-0129)

`_unpack_nemo_file` in `nemo/core/connectors/save_restore_connector.py` calls
`tar.extractall()` without sanitising member names. A `.nemo` whose member name
contains `../` (or is absolute) escapes the output directory and overwrites host
files during restore — **arbitrary file write**, which NVD notes can lead to code
execution and data tampering. Present before NeMo **r2.0.0rc0**; CVSS 6.3
(HiddenLayer) / 7.8 (NVD), CWE-22.

## Rules

| rule | severity | class | condition |
|------|----------|-------|-----------|
| **NEMO001** | high | CWE-502 | A pickle inside the `.nemo` tar (`model_weights.ckpt` or a nested torch-save zip entry) imports a code-execution callable. A scanner that does not untar never sees it; `restore_from` `torch.load`-s and runs it. |
| **NEMO010** | medium | CWE-502 | The container holds a pickle-bearing checkpoint that names nothing dangerous. Still a pickle a non-unpacking scanner skips and that `restore_from` unpickles; prefer a non-executable weights format. |
| **NEMO020** | high | CWE-22 (CVE-2024-0129) | A tar member name escapes the extraction root (absolute, or a `..` component). `restore_from`'s `tar.extractall()` writes it outside the output folder. |
| **NEMO021** | medium | CWE-22 (CVE-2024-0129) | A tar member is a symlink/hardlink whose target escapes the archive. Extraction follows it to write or overwrite a file outside the output folder. |

A bare `.pkl`/`.pt` file is out of scope here — that is `pickle_model_scan.py` /
`pytorch_checkpoint_scan.py`'s job. This module reports only when it successfully
opened a tar container, which is the blind spot above.

## What it does

It opens the tar **in memory** (bounded by `MAX_MEMBER_BYTES`, 256 MiB, and
`MAX_MEMBERS`), reads each regular member without extracting to disk, peels a
nested `torch.save` zip if present, and disassembles the inner pickle with the
standard library's `pickletools`. It never imports torch, NeMo or joblib, never
calls `extractall`, never writes to disk, and never unpickles or executes
anything. Members are walked one at a time (`tar.next()`), which tolerates the
malformed trailing-block quirk that trips `getmembers()` on some `.nemo` files.

## Usage

```bash
python nemo_container_scan.py model.nemo
```

Exit `1` on any high finding, `0` otherwise, `2` on usage error or unreadable
file. `scan_bytes(data, name=...)` and `scan_file(path)` return a list of finding
dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Honest limits

This is static source review, not exploitation. It flags imports, the container
layout and escaping member names; it does not prove a given file is exploitable
and runs no proof of concept. It peels one nested zip layer, bounds member sizes,
and reports — it does not open — formats it cannot read with the standard library.
The nuanced top-level-package gadget classification (the `torch.*` gadget paths
some denylists catch) lives in sibling modules in the same repo. The point is
narrow: **a `.nemo` is a tar, and `restore_from` treats the tar as transparent —
so a scanner should open it too.**
