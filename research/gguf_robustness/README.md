# GGUF reader robustness probe (Python `gguf-py`)

_Made with AI by MV2 of Munim, Inc. Code: Apache-2.0. Text and data: CC BY 4.0.
This is an offline proof-of-concept against local, inert files only. No live, hosted
or out-of-scope system was contacted at any point._

## What this is

A small, self-contained harness that asks one question about the **Python** GGUF
reader (`GGUFReader` from the PyPI `gguf` package, a.k.a. `gguf-py`):

> Can a crafted but tiny GGUF file make the reader **hang** or **blow up its
> allocation** — the crafted-size denial-of-service / out-of-bounds-read class
> (CWE-400 / CWE-125) that has published CVEs in the **compiled** GGUF readers?

Related published CVEs in other GGUF reader implementations (for context; all public
and, where noted, fixed):

- **CVE-2026-7482** — Ollama (Go), CVSS 8.8, fixed 0.17.1
- **CVE-2025-66960** — Ollama (Go), CVSS 7.5
- **CVE-2026-27940** — llama.cpp (C/C++)

Those live in compiled readers that do manual pointer/size arithmetic. The Python
reader sizes tensors through NumPy (`memmap` slice + `reshape`). Source review
predicts the Python path is structurally safe: a slice past end-of-file truncates
rather than over-reads, and a `reshape` to an impossible size raises a clean
`ValueError` instead of allocating. This harness turns that prediction into
**execution-verified** evidence.

## Result (verified in a sealed container, 2026-10-16)

**Verdict: `CLEAN_NEGATIVE`.** The well-formed control loads; none of the seven
malformed fixtures caused a hang or runaway allocation under a 1.5 GiB address-space
cap and a 30 s per-file timeout. Full machine-readable output is in
[`results.json`](results.json).

| fixture | declares | outcome |
| --- | --- | --- |
| `control_valid` | a normal 4-element F32 tensor | **loaded** (as expected) |
| `tensor_dims_overflow` | one tensor of 2^40 elements | rejected — `ValueError` (reshape) |
| `tensor_count_overflow` | 2^32 tensors, none supplied | rejected — `IndexError` |
| `kv_count_overflow` | 2^32 metadata pairs, none supplied | rejected — `IndexError` |
| `string_len_overrun` | a metadata string of 2^40 bytes, 4 supplied | **loaded** — reader tolerated it, no over-read |
| `array_len_overflow` | a metadata array of 2^40 elements, 1 supplied | rejected — `ValueError` |
| `data_offset_oob` | tensor data offset far past EOF | rejected — `ValueError` (reshape of size 0) |
| `bad_alignment` | `general.alignment = 0` | rejected — `ValueError` (non-zero power of two) |

Each file is tiny (32–106 bytes) and inert; every result returned in well under a
second. Six of the seven malformed files were rejected with a clean exception; the
seventh (`string_len_overrun`) was accepted without over-reading, allocating, or
crashing. In every case the dangerous outcome — a hang or an out-of-bounds /
over-allocating read — did **not** occur.

## Why this is worth publishing

Public write-ups treat each GGUF/safetensors size-confusion CVE in isolation. We
found no source-level, cross-reader synthesis showing that **the same attacker goal
(declare a huge size in a tiny file to force an over-read or over-allocation)
succeeds only against the compiled readers and is structurally neutralized in the
memory-safe ones** — NumPy `memmap`+`reshape` on the Python side, and (separately
measured) exhaustive up-front validation on the Rust `safetensors` side. This is an
honest **negative / synthesis** result: it tells defenders that for this specific
class, a Python `gguf` loading path is not where the risk lives, and it gives them a
reproducible way to re-check that themselves on any pinned version.

## Honest limits

- This covers **one bug class** (crafted-size DoS / OOB), not GGUF security in
  general. GGUF chat-template SSTI and other vectors are separate and are handled by
  other tools in this repository.
- `CLEAN_NEGATIVE` is evidence of resistance **for the `gguf` version installed in
  the run**, not a proof for all versions. The field `gguf_version` reads `"unknown"`
  only because the installed build did not expose `__version__`; pin and record the
  version when you reproduce.
- A clean scan guarantees nothing about files or code paths not exercised here.
- If a future run ever reports a `DOS_SIGNAL`, that is a **candidate** finding only:
  it must be re-checked against a pinned reader version and disclosed privately
  through the project's channel before any public mention.

## Reproduce

```bash
pip install -r requirements.txt          # gguf, numpy
python probe.py --out-dir ./out          # writes ./out/corpus/*, results.json, summary.md
python -m unittest -v                    # offline self-tests (reader test auto-skips if gguf absent)
```

The corpus builder (`builder.py`) is pure standard library, so the fixtures can be
regenerated and inspected with no third-party dependency; only the actual load step
(`load_one.py`) and the end-to-end probe need `gguf` + `numpy`.

## Files

- `builder.py` — writes the control + seven malformed GGUF fixtures (stdlib only)
- `load_one.py` — loads one file in a child process under a hard memory cap
- `probe.py` — generates the corpus, probes every file, writes `results.json` + `summary.md`
- `test_probe.py` — offline self-tests
- `results.json` — the verified output from the 2026-10-16 sealed-container run
- `requirements.txt` — `gguf`, `numpy`
