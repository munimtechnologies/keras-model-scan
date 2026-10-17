<!-- SPDX-License-Identifier: Apache-2.0 -->
# pickle_ext_registry_scan — the pickle import that hides its own name

Part of [keras-model-scan](https://github.com/munimtechnologies/keras-model-scan).
A static, no-execution detector for the **pickle extension-registry redirect**
vector, which the model-file scanners surveyed in the literature do not catch.
Made with AI by MV2 of Munim, Inc.

## The gap

Most pickle scanners decide whether a model file is dangerous by looking at the
**names it imports**: they read the `GLOBAL` / `STACK_GLOBAL` opcodes and compare
the `module.qualname` operands against a danger list (`os.system`,
`builtins.eval`, `subprocess.Popen`, …). keras-model-scan's own
`pickle_model_scan` does the same.

Pickle protocol 2 added a second way to resolve a global that **never puts the
name in the stream**. The opcodes `EXT1`, `EXT2` and `EXT4` carry only a small
integer *code*. At unpickle time the code is looked up in the process-wide
`copyreg` *extension registry* (`copyreg._extension_registry`), which maps codes
to `(module, qualname)` pairs. The registry is populated by
`copyreg.add_extension(module, qualname, code)` — or by mutating
`copyreg._inverted_registry` directly.

So an attacker can, inside one pickle:

1. import `copyreg.add_extension` and call it to register, say, code `1` →
   `("os", "system")` (or `("builtins", "eval")`); then
2. emit `EXT1 1`, which resolves to `os.system` **without the strings `os` or
   `system` ever appearing** in the file.

A names-only scanner sees step 2 as an opaque integer and reports nothing. This
is not a theoretical nicety: an independent 2026 evaluation
([DITTO, arXiv:2610.10735](https://arxiv.org/abs/2610.10735)) found that of the
open-source scanners it tested, ModelScan parsed these streams but did not model
the behaviour (a 100% false-negative on the extension-registry cases) and
fickling could crash on the EXT opcodes. The mechanism itself is standard CPython
behaviour documented in the [`pickle`](https://docs.python.org/3/library/pickle.html)
and `copyreg` modules.

## What this scanner does

It walks the pickle opcodes with `pickletools.genops`, which **decodes without
executing** the stream (no registry lookup, no object reconstruction, no code
run). It flags the *use of the mechanism itself*, which legitimate ML serializers
(`torch.save`, numpy, scikit-learn / joblib) never exercise:

| ID | Severity | What it flags |
|----|----------|---------------|
| `PXR001` | CRITICAL | An import of a `copyreg` extension-registry mutator — `add_extension`, `remove_extension`, `clear_extension_cache`, `_inverted_registry` or `_extension_registry`. The pickle can rewire a later `EXT` opcode to an arbitrary global at load time. |
| `PXR002` | HIGH | Use of an extension-registry opcode (`EXT1` / `EXT2` / `EXT4`). The global it resolves is not named in the stream, so a names-only scanner cannot see what it imports. |
| `PXR000` | LOW | A file that looks like a pickle could not be fully parsed — truncated, or deliberately malformed to defeat static scanning. |

It scans a raw pickle file, and also unpacks ZIP archives (e.g. the modern
`torch.save` `.pt` container, whose `data.pkl` carries the opcodes) and TAR
archives (e.g. NVIDIA NeMo `.nemo` bundles) and scans each pickle-looking member.

## Usage

```bash
python pickle_ext_registry_scan.py model.pkl checkpoint.pt bundle.nemo
```

JSON findings go to stdout; the exit code is `1` if anything is flagged, else `0`,
so it drops into CI or a pre-load gate.

## Honest limits

- **Review signal, not a verdict.** `EXT` opcodes and extension-registry use are
  almost unheard-of in real model files, so a hit should be treated as "do not
  load until a human has looked", not as proof of malice. If you have a
  legitimate producer that uses the extension registry, allowlist it.
- **Static and conservative.** The tool reports that the redirect *mechanism* is
  present; it does not and cannot resolve what a given `EXT` code would map to,
  because that depends on registry state built at load time. That is the point —
  the target is intentionally invisible in the file.
- `STACK_GLOBAL` operands are paired from the immediately preceding string
  pushes; a stream that routes them through the memo could evade the `PXR001`
  name match (the `PXR002` `EXT`-opcode flag still fires on the redirect's use).
- This is a **defensive detector built from already-public information**. It does
  not weaponize anything: it ships no exploit, and the mechanism it reports on is
  documented Python behaviour. No live or third-party system was scanned to build
  it; the tests use tiny hand-crafted and locally generated pickle bytes.

## Licence

Apache-2.0 (code); this document is CC BY 4.0.
— MV2, Munim, Inc.
