# joblib_pickle_scan.py — compression-wrapped pickle container scanner

`joblib_pickle_scan.py` is a static, dependency-free detector for pickles that
have been **compressed**, so the file no longer begins with pickle magic and an
opcode-only scanner stops at byte 0. It is part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan)
toolkit. Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

## The blind spot

`joblib.dump(obj, "model.joblib", compress=("bz2", 4))` — the ordinary way a
scikit-learn estimator is saved — writes the **compressor's** magic bytes
instead of the pickle `PROTO` opcode (`80 04`):

| codec | leading bytes | stdlib-decompressible |
|-------|---------------|-----------------------|
| zlib  | `78 9c` / `78 da` (CM=8, header % 31 == 0) | yes (`zlib`) |
| gzip  | `1f 8b` | yes (`zlib`, wbits=31) |
| bzip2 | `42 5a 68` (`BZh`) | yes (`bz2`) |
| xz    | `fd 37 7a 58 5a 00` | yes (`lzma`) |
| lz4   | `04 22 4d 18` | **no** (lz4 not in the standard library) |

joblib integrates six decompression backends and peels the wrapper transparently
before unpickling, so `joblib.load` still executes a `__reduce__` payload — while
`pickletools.genops` fails at offset 0 and a magic/extension router reports
"no issues found".

This is a documented, reproduced evasion. Public proofs of concept show a
joblib-compressed `__reduce__` gadget bypassing **picklescan 1.0.4** and
**ModelScan** completely (0 detections), and it is one of the 22 pickle loading
paths catalogued by *The Art of Hide and Seek* (USENIX Security '26,
[arXiv:2508.19774](https://arxiv.org/abs/2508.19774), the PickleCloak framework),
which chains zip/tar/gzip/zlib/bz2/lzma/xz/lz4 transforms ahead of the pickle
deserialiser. ModelScan added transparent decompression in PR #375 in response;
this module is the standalone equivalent for this toolkit.

## What it does

It peels up to `MAX_LAYERS` (4) stdlib-decompressible wrappers in memory
(bounded by `MAX_DECOMPRESSED_BYTES`, 256 MiB), then disassembles the inner
pickle with the standard library's `pickletools`. It never imports joblib, never
writes to disk, and never unpickles or executes anything.

## Rules

| rule | severity | class | condition |
|------|----------|-------|-----------|
| **JLB001** | high | CWE-502 | A compression-wrapped stream (zlib/gzip/bz2/xz, possibly nested) decompresses to a pickle that imports a code-execution callable. Invisible to opcode-only scanners; `joblib.load` would deserialise and run it. |
| **JLB010** | medium | CWE-502 | A compression-wrapped stream decompresses to a real pickled object graph that names nothing dangerous. Still a hidden pickle a magic/extension router skips; treat the compressed container as part of the threat model. |
| **JLB012** | medium | CWE-502 | An lz4-frame-compressed container. lz4 is not in the standard library, so this scanner cannot decompress it to inspect, but `joblib.load` with the lz4 backend still unpickles it. Decompress with lz4 and re-scan, or treat the file as untrusted. |

A **bare** (uncompressed) pickle is out of scope here — that is
`pickle_model_scan.py`'s job. This module only reports when at least one
compression wrapper was present, which is precisely the blind spot. The `lzma`
"alone" format is intentionally not matched on its magic, because its `0x5d`
first byte collides with the pickle `EMPTY_LIST` opcode (`]`).

## Usage

```bash
python joblib_pickle_scan.py model.joblib model.pkl.gz
```

Exit `1` on any high finding, `0` otherwise (JLB010/JLB012 print but do not fail
the build). `scan_bytes(data, name=...)` and `scan_file(path)` return a list of
finding dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Honest limits

This is static source review, not exploitation. It flags imports and the
compression wrapper; it does not prove a given file is exploitable and runs no
proof of concept. It peels at most four layers and reports the first dangerous
import path. lz4-frame containers are reported as unscannable (JLB012) rather
than decompressed. Nuanced top-level-package gadget classification (the `torch.*`
gadget paths some denylists catch) lives in separate modules in the same repo.
The point is narrow and, we think, underserved: **a compressed pickle is still a
pickle, and `joblib.load` treats the compression wrapper as transparent — so a
scanner should too.**
