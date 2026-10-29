# pytorch_checkpoint_scan.py — PyTorch checkpoint *container* scanner

Made with AI agents working in the name of MV2 of Munim, Inc. Licensed Apache-2.0.

`pickle_model_scan.py` in this toolkit classifies the opcodes of a **pickle
stream**. This module adds the layer underneath it: it recognises the
**container** a real `torch.save` checkpoint ships in, pulls the embedded
pickle(s) out of it, and reports code-execution imports *with the container in
mind*. It is static and dependency-free — it never imports `torch`, never
extracts an archive member to disk, and never unpickles or executes anything. It
reads bytes and disassembles opcodes with the standard-library `pickletools`.

## Why the container is a security signal

`torch.load` has two deserialisation paths:

| Container | How `torch.save` makes it | Unpickler |
|-----------|---------------------------|-----------|
| **Modern zip** | default since PyTorch 1.6; a ZIP whose `archive/data.pkl` is the object graph | restricted unpickler is wired in, so a dangerous callable is only reached with `weights_only=False` |
| **Legacy** | an old tar layout, or a bare non-zip pickle stream (e.g. a Hugging Face `pytorch_model.bin`) | handled by `_legacy_load` |

**CVE-2025-32434** (published 2025-04-17, CWE-502, CVSS 9.3/9.8,
GHSA-53q9-r3pm-6pq6, torch ≤ 2.5.1, fixed in 2.6.0) lives on exactly this seam.
On affected versions the `_legacy_load` path did **not** apply the restricted
unpickler, so `torch.load(path, weights_only=True)` — the call teams reached for
to load untrusted checkpoints *safely* — still executed whatever callable a
legacy-format file named. torch 2.6.0 fixed it and flipped the default to
`weights_only=True`.

So the same dangerous import means different things depending on the container,
and a legacy container is a risk surface even before you look at its imports.

## Rules

| Rule | Severity | CVE / CWE | What it means |
|------|----------|-----------|---------------|
| `PTC001` | high | CVE-2025-32434 (CWE-502) | A **legacy-format** checkpoint (tar or non-zip pickle) imports a code-execution callable. Reachable even by `torch.load(weights_only=True)` on torch ≤ 2.5.1. Do not load it; upgrade to torch ≥ 2.6.0. |
| `PTC002` | high | CWE-502 | A **modern zip** checkpoint imports a code-execution callable. Deserialised and run by `torch.load(weights_only=False)`. Load with `weights_only=True` on torch ≥ 2.6.0, or do not load it. |
| `PTC010` | medium | CVE-2025-32434 (CWE-502) | A **legacy-format** checkpoint holding a real pickled object graph with **no** dangerous import found. The container itself is the CVE-2025-32434 surface: on torch ≤ 2.5.1 it is deserialised even under `weights_only=True`. Prefer safetensors, or re-save in the modern zip format and use torch ≥ 2.6.0. Advisory — it prints but does not change the exit code. |

"Code-execution callable" means a pickle `GLOBAL` / `STACK_GLOBAL` naming a
process or eval sink: `os` / `posix` / `nt` / `pty` / `runpy` / `socket`,
`subprocess.*`, `ctypes.*`, `builtins.eval|exec|compile|__import__|getattr`,
`importlib.import_module`, `pickle.load(s)`, `numpy.load`, `pandas.read_pickle`,
and a handful of classic gadget pieces. Anything else combined with a
reconstruction opcode is left to `pickle_model_scan.py`.

## Usage

```bash
python pytorch_checkpoint_scan.py model.pt pytorch_model.bin another.pth
```

Exit code `1` if any **high** finding (PTC001/PTC002), `2` on a usage error or an
unreadable file, `0` otherwise (including advisory-only PTC010).

```python
import pytorch_checkpoint_scan as pcs

for f in pcs.scan_file("pytorch_model.bin"):
    print(f["rule"], f["severity"], f["cve"] or f["cwe"], f["message"])
```

`scan_bytes(data, name="")` and `scan_file(path)` each return a list of finding
dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Scope and honest limits

- This is **static source review**, not execution. It flags imports and
  container shape; it does not prove exploitability and does not run a PoC.
- It reports the **first** dangerous import path it sees per member; a file can
  carry more. Parsing stops gracefully at the trailing raw tensor bytes of a
  legacy stream, which is expected.
- The dangerous-import list is deliberately focused on clear process/eval sinks
  to keep false positives low; nuanced top-level-package gadget classification
  lives in `pickle_model_scan.py` (see `TORCH_GADGET_BLINDSPOT.md`).
- `PTC010` is intentionally broad: legacy-format checkpoints are now uncommon
  (modern `torch.save` defaults to zip), so flagging them as the CVE-2025-32434
  surface is useful rather than noisy. Suppress it if your pipeline knowingly
  ships legacy files on torch ≥ 2.6.0.
- Decompression-bomb and archive-symlink concerns are handled by
  `archive_bomb_scan.py` and `archive_symlink_scan.py`; this module caps member
  count and per-member read size and never writes archive contents to disk.

## References

- CVE-2025-32434 — PyTorch `torch.load(weights_only=True)` RCE via the legacy
  path, GHSA-53q9-r3pm-6pq6 (fixed in torch 2.6.0).
- CWE-502 — Deserialization of Untrusted Data.
