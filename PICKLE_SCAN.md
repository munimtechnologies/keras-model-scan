# pickle-model-scan

A static, **no-execution** scanner for pickle-based model files, part of the
`keras-model-scan` toolkit. It is the companion to the `.keras` scanner: where that
one reads a Keras `config.json`, this one reads the **pickle opcode stream** that
powers the most common real-world model-file remote-code-execution (RCE) vector.

Made with AI by MV2 of Munim, Inc. Standard library only (Python 3.8+). MIT licensed.

## Why

Loading an untrusted pickle runs arbitrary code: a crafted `__reduce__` can import
any module and call it during `pickle.load` / `joblib.load` / `torch.load` /
`numpy.load(allow_pickle=True)`. This is not theoretical — it is the mechanism behind
real advisories such as MONAI's `NumpyReader` RCE (object-dtype `.npy`), the
`msgpack-numpy` hidden-pickle RCE, and the broad class of poisoned PyTorch `.bin`
files on model hubs.

This tool **never unpickles, imports, or executes** anything. It disassembles the
opcode stream with the standard library's `pickletools.genops`, which parses bytes
without running them, and flags the opcodes behind those attacks.

## What it scans

- Raw pickles: `.pkl`, `.pickle`
- scikit-learn / joblib dumps: `.joblib` (incl. gzip/bz2/zlib-compressed)
- PyTorch archives: `.pt`, `.pth`, `.bin` (the pickle inside the ZIP, e.g. `data.pkl`)
- NumPy: `.npy` / `.npz` — flags **object-dtype** arrays whose data is a pickle
- Recognises and reports the **safe** formats — `safetensors` and `GGUF` have no
  code-execution surface — so you can confirm a file is the safe kind.

## Checks

| Rule | Severity | What it catches |
|------|----------|-----------------|
| PKL001 | CRITICAL | Dangerous import (`os`, `subprocess`, `builtins.eval`, …) **and** a REDUCE/BUILD/NEWOBJ opcode — loading can run code (CVE-2025-1550 class) |
| PKL002 | HIGH | Dangerous import with no execution opcode yet seen |
| PKL003 | MEDIUM | Import outside the known-safe model-reconstructor allowlist — review |
| PKL004 | HIGH | Deferred-call gadget (`functools.partial`, `operator.attrgetter`, …) |
| PKL007 | HIGH | **STACK_GLOBAL operands that cannot be resolved** from preceding string literals — a documented scanner-bypass (GHSA-9gvj-pp9x-gcfr / CVE-2025-71345) that this tool flags instead of silently passing |
| PKL010 | HIGH | NumPy object-dtype array (its data is a pickle) |
| PKL020 | INFO | safetensors — no code-execution surface (the safe format) |
| PKL022 | INFO | GGUF — data-only format, no code surface |
| PKL021 / PKL006 / PKL000 | LOW | Malformed safetensors header / unscannable compression (lz4, zstd) / truncated pickle stream |
| PKL030 | HIGH | Archive member escapes the extraction directory (Zip Slip) |

## Usage

```bash
# scan one file
python pickle_model_scan.py model.bin

# scan several, JSON output
python pickle_model_scan.py a.joblib b.pt --json

# CI / pre-load gate: exit 1 if anything at or above the threshold is found
python pickle_model_scan.py downloaded.pt --fail-on high || echo "do not load"
```

Exit codes: `0` clean (below threshold), `1` findings at/above `--fail-on`
(default `medium`), `2` a file was missing.

## Honest limitations

- A flag means a pattern worth human review, **not** proof of malice; a clean result
  is **not** a guarantee of safety. This is a static heuristic, not a sandbox.
- STACK_GLOBAL operand resolution uses the same "last two pushed strings" heuristic
  the mainstream scanners use. Rather than be bypassed silently, this tool emits
  **PKL007** when operands can't be resolved — but adversarial opcode reordering can
  still make a file suspicious-but-unclassified. When in doubt, don't load it; prefer
  `safetensors`.
- lz4/zstd-compressed containers are reported as unscanned (no stdlib codec);
  decompress them first.
