# pickle-model-scan

A static, **no-execution** scanner for pickle-based model files, part of the
`keras-model-scan` toolkit. It is the companion to the `.keras` scanner: where that
one reads a Keras `config.json`, this one reads the **pickle opcode stream** that
powers the most common real-world model-file remote-code-execution (RCE) vector.

Made with AI agents working for MV2 of Munim, Inc. Standard library only (Python 3.8+). Apache-2.0 licensed.

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
- scikit-learn / joblib dumps: `.joblib` (incl. zlib/gzip/bz2/xz/lzma-compressed),
  walked to the end since 0.4.0 (see below)
- PyTorch archives: `.pt`, `.pth`, `.bin` (the pickle inside the ZIP, e.g. `data.pkl`)
- NumPy: `.npy` / `.npz` — flags **object-dtype** arrays whose data is a pickle
- Recognises and reports the **safe** formats — `safetensors` and `GGUF` have no
  code-execution surface — so you can confirm a file is the safe kind. For a full
  header/offset integrity check of `.safetensors`, use `safetensors_scan.py` (the
  unified `model-file-scan` command routes `.safetensors` there automatically).

## Checks

| Rule | Severity | What it catches |
|------|----------|-----------------|
| PKL001 | CRITICAL | Dangerous import (`os`, `subprocess`, `builtins.eval`, …) **and** a REDUCE/BUILD/NEWOBJ opcode — loading can run code (CWE-502, deserialization of untrusted data) |
| PKL002 | HIGH | Dangerous import with no execution opcode yet seen |
| PKL003 | MEDIUM | Import outside the known-safe model-reconstructor allowlist — review |
| PKL004 | HIGH | Deferred-call gadget (`functools.partial`, `operator.attrgetter`, …) |
| PKL007 | HIGH | **STACK_GLOBAL operands that cannot be resolved** from string literals or memoized string literals — a documented scanner-bypass (GHSA-9gvj-pp9x-gcfr / CVE-2025-71325) that this tool flags instead of silently passing |
| PKL008 | MEDIUM | joblib array data could not be sized; the rest of the file was not analysed (0.4.0+; reported instead of stopping quietly) |
| PKL010 | HIGH | NumPy object-dtype array (its data is a pickle) |
| PKL020 | INFO | safetensors — no code-execution surface (the safe format) |
| PKL022 | INFO | GGUF — data-only format, no code surface |
| PKL021 / PKL006 / PKL000 | LOW | Malformed safetensors header / unscannable compression (lz4, zstd) / truncated pickle stream |
| PKL030 | HIGH | Archive member escapes the extraction directory (Zip Slip) |

**Correction (v0.5.0):** earlier versions cited the STACK_GLOBAL bypass under a
mistyped CVE number and tagged PKL001 with CVE-2025-1550. The bypass advisory
GHSA-9gvj-pp9x-gcfr is **CVE-2025-71325**, and CVE-2025-1550 is a Keras
Lambda-deserialization CVE unrelated to pickle, so PKL001 now carries the class
identifier **CWE-502**. `test_attribution.py` guards both.

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
- STACK_GLOBAL operand resolution follows string literals and memoized string
  literals (0.4.0). Rather than be bypassed silently, this tool emits **PKL007**
  when operands can't be resolved, so an unusual file can still be
  suspicious-but-unclassified. When in doubt, don't load it; prefer `safetensors`.
- lz4/zstd-compressed containers are reported as unscanned (no stdlib codec);
  decompress them first.

<!-- pkl-memo -->
## STACK_GLOBAL operands from the memo (0.4.0, November 2026)

At pickle protocols 4 and 5, an import is written as two strings and
`STACK_GLOBAL`. Python's pickler memoizes each string, and when the same
module name comes again (for example `numpy.ndarray`, then `numpy.dtype`) it
fetches it from the memo (`BINGET`) instead of writing it twice. Up to 0.2.1
this scanner treated any memo fetch as an unresolved operand and reported
PKL007 HIGH, so honest `paddle.save` files (`.pdparams`, `.pdopt`) and other
protocol-4/5 pickles were flagged.

Since 0.4.0 the scanner tracks the memo the way the unpickler fills it (`PUT`,
`BINPUT`, `LONG_BINPUT`, and `MEMOIZE` at the next free index). It resolves a
`STACK_GLOBAL` when the two opcodes that pushed its operands are string
literals or fetches of a memoized string literal, with only memo stores,
`FRAME` or `PROTO` in between. Everything else stays PKL007 HIGH: a memo slot
that holds no string, an index that was never stored, and operands that are
not the last two pushes. Checked in
[REALFILE_CHECK_PKL_MEMO_2026-11.md](REALFILE_CHECK_PKL_MEMO_2026-11.md)
(12 of 13 rows held; the miss led to the joblib section below).

<!-- pkl-joblib -->
## joblib.dump files are walked to the end (0.4.0, November 2026)

`joblib.dump` does not write a plain pickle. Each numpy array becomes a
`NumpyArrayWrapper` object, and right after that object's `BUILD` opcode
joblib writes the array itself, inside the stream: a padding-length byte,
padding and the raw bytes for a numeric array (joblib 1.2 and later; earlier
versions write no padding byte), or a complete, separate pickle with its own
memo for an object-dtype array. `joblib.load` reads them back the same way
(`joblib/numpy_pickle.py`, `NumpyArrayWrapper.read_array`).

Up to 0.2.1 the opcode walk stopped at the first array: at a numeric array it
hit bytes that are not opcodes (PKL000 LOW), and at an object array it walked
into the nested pickle with the outer memo (a false PKL007 HIGH) and then
ended quietly at the nested `STOP`. On honest scikit-learn files it read
about 12% of the stream, and it never saw the imports after the first array
([REALFILE_CHECK_PKL_DIAG_2026-11.md](REALFILE_CHECK_PKL_DIAG_2026-11.md)).

0.4.0 follows `joblib.load`. In streams that name `NumpyArrayWrapper` it keeps
a symbolic stack (values are described, never built) to see the wrapper's
state when its `BUILD` comes. For a numeric array it reads the padding byte
when the state has `numpy_array_alignment_bytes`, then skips
`prod(shape) * itemsize` bytes; the itemsize comes from the pickled dtype
(its `elsize` for flexible and structured types, else its type string, such
as `f8`). For an object-dtype array it walks the nested pickle with a fresh
memo and carries on after its `STOP`. If the size cannot be derived it
reports **PKL008 MEDIUM** ("joblib array data could not be sized; the rest of
the file was not analysed") instead of stopping quietly; a file that ends
inside an array gets PKL000 LOW. It also decompresses joblib's `xz` and
`lzma` files (standard library), next to zlib, gzip and bz2; lz4 stays
PKL006 LOW (unscanned).

`pickle_walk(data)` returns what the walk covered: the imports it resolved,
the byte offset of the outer `STOP`, and how many arrays it skipped or walked
as nested pickles. A walk that covers the whole file ends at its last byte.

Pre-registered check on files written by scikit-learn, pandas, numpy and
joblib, compared with the imports `joblib.load` really makes, and on
published Hub files: [research/PREREG_PKL_JOBLIB.md](research/PREREG_PKL_JOBLIB.md).
**Graded 16 of 16** in
[REALFILE_CHECK_PKL_JOBLIB_2026-11.md](REALFILE_CHECK_PKL_JOBLIB_2026-11.md):
the walk matched `joblib.load`'s imports on all 18 honest files; on 28
published joblib files a plain opcode walk read a median 0.4% of the bytes
and 0.4.0 read all 28 to the end; PKL007 false alarms went from 24 of 30
published files to none.
