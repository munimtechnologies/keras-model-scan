# msgpack_weights_scan.py — Flax and msgpack-numpy weight files

`msgpack_weights_scan.py` is a static, dependency-free scanner for MessagePack
weight files: Flax/JAX `.msgpack` checkpoints written by
`flax.serialization.to_bytes` / `msgpack_serialize`, and payloads written by
msgpack-numpy. It is part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan) toolkit.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

## Why two formats matter

MessagePack itself has no code-execution feature, but the two common ways of
putting numpy arrays in it load very differently:

- **Flax** stores each array as extension type 1 (scalars as type 3) holding a
  packed `(shape, dtype name, buffer)` triple and rebuilds it with
  `np.frombuffer`. Its writer refuses object and structured dtypes and its
  reader never unpickles. A Flax file is data.
- **msgpack-numpy** stores each array as a map with keys `nd`, `type`, `kind`,
  `shape` and `data`. Its `decode` object hook calls `pickle.loads(data)`
  whenever `kind` is `O` (an object array), so a crafted file can run code
  while it is being unpacked. The upstream fix, lebedov/msgpack-numpy PR #58
  (an `allow_pickle` switch that refuses by default; it cites a huntr report
  triaged as valid on 2026-05-29), was still open with no maintainer review
  when this module was written.

This toolkit's `SCANNER_COVERAGE_MATRIX.md` marked "Flax/JAX MessagePack
weights" as not covered here. This module closes that row and adds the
msgpack-numpy object-array check. ModelAudit's published scanner docs describe
generic MessagePack checks (suspicious structures, embedded code, oversized
data) and do not mention msgpack-numpy object arrays by name.

## What it does

- Parses MessagePack itself (no `msgpack`, `numpy` or `flax` import) and
  memory-maps files, so a multi-GB checkpoint is not read into memory whole.
- Checks each map and extension value as soon as it is complete, in the order
  `object_hook` and `ext_hook` fire. A file that breaks off part-way still gets
  findings for everything before the break.
- For a msgpack-numpy object array, lists what the pickle imports with
  `pickletools` (opcodes only, never executed), resolving `STACK_GLOBAL` names
  through the memo. Imports outside numpy's own array helpers make it high.
- For a Flax array or scalar, checks the triple: shape of non-negative integers
  (at most 64 dimensions), a dtype that is not object or structured, and, for
  the dtypes Flax writes, a buffer size equal to shape x item size.
- Caps nesting (`MAX_DEPTH` 128), top-level values (`MAX_VALUES` 1000) and the
  number of findings listed (`MAX_FINDINGS` 1000), and rejects declared
  array/map sizes larger than the bytes left.

## Rules

| rule | severity | class | condition |
|------|----------|-------|-----------|
| **MPK001** | high | CWE-502 | msgpack-numpy object array whose pickle imports something other than numpy's reconstruction helpers, or a name the scanner cannot resolve statically. |
| **MPK002** | medium | CWE-502 | msgpack-numpy object array whose pickle imports only numpy's reconstruction helpers. Still unpickled on load. |
| **MPK003** | medium | CWE-20 | Flax array or scalar payload that Flax's writer would not produce: not a `(shape, dtype, buffer)` triple, an object or structured dtype, or a size mismatch. |
| **MPK004** | medium | CWE-693 | Not well-formed MessagePack, nested deeper than `MAX_DEPTH`, more than one top-level value, or an extension type Flax does not define. |

`cve` is empty for every rule: no CVE had been assigned to the msgpack-numpy
behaviour when this was written.

## Usage

```bash
python msgpack_weights_scan.py flax_model.msgpack features.msgpack
```

Exit `1` on any high finding, `0` otherwise, `2` on usage error or unreadable
input. `scan_bytes(data, name=...)` and `scan_file(path)` return a list of
finding dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Honest limits

- This is static review. MPK001 shows that a file would be unpickled by
  msgpack-numpy and what the pickle imports; it does not show that anyone
  loads the file with msgpack-numpy. Flax's own loader never unpickles.
- Map keys are matched whether they were packed as bin or as str, which is
  broader than msgpack-numpy itself (it looks up `b'nd'`).
- The import list comes from opcodes. A pickle that builds a callable without
  any import opcode is not listed, and only numpy's helpers and
  `_codecs.encode` are allowlisted.
- Orbax checkpoint directories (OCDBT/Tensorstore) are not parsed; only
  single MessagePack files are.
- Tests use MessagePack and pickle bytes built by hand from the format specs;
  checking against files written by Flax and msgpack-numpy themselves is the
  next step.
