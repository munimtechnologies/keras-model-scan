# `nested_container_scan` — the layer every single-format scanner skips

Model-file scanners inspect the **outer** container of a model and stop there.
Attackers exploit exactly that: they put a dangerous payload one or more
compression / archive layers deeper, or behind a codec the scanner's standard
library cannot decode. The model loader still reaches the payload; the scanner
never sees it.

`nested_container_scan` walks the container tree and reports the full nesting
**path** to each hidden payload, plus members it cannot open and codecs it
cannot decode. It is a complement to the format-specific scanners in this
repository — once a payload is located, hand it to the matching one
(`pickle_model_scan`, `keras_model_scan`, `safetensors_scan`, …).

It is made with AI agents working in the name of MV2 of Munim, Inc., and is
offered as defensive tooling. Verify every advisory ID against its upstream
source before acting on it.

## Why this is needed (documented bypass class)

- **"The Art of Hide and Seek: Making Pickle-Based Model Supply Chain
  Poisoning Stealthy Again"** (Liu et al., USENIX Security 2026,
  arXiv:2508.19774) enumerates loading paths such as `gz→pkl`, `tar→pkl`,
  `zip→zip→pkl`, `gz→tar→pkl` and shows that widely used scanners cover only a
  small part of this surface.
- **CVE-2025-1945 / CVE-2025-1944** (Sonatype): ZIP flag-bit / local-header
  manipulation hides a pickle from the scanner while `torch.load` still loads
  it.
- **CVE-2025-10156** (JFrog): a ZIP member with a bad CRC makes the scanner
  raise and stop, leaving the archive unscanned while the loader reads it.
- Published measurements put ModelScan and PickleScan at **F1 ≈ 0** on several
  of these nested/evasive cases.

## What it does **not** do

It never executes, imports, unpickles or otherwise deserializes anything. It
reads a bounded prefix of each member and classifies it by **magic bytes**
(pickle protocol header, HDF5 signature, NumPy `\x93NUMPY`) or by file name
extension. It uses only the Python standard library (`zipfile`, `tarfile`,
`zlib`, `bz2`, `lzma`). It is not a pickle-opcode analyzer and does not detect
stacked/recursive **pickle** payloads (ShadowPickle, arXiv:2607.17503) — that
is a pickle-stream concern for `pickle_model_scan`. This module covers the
**archive / compression** nesting dimension.

## Rules

| Rule | Severity | Meaning |
|------|----------|---------|
| `NC001` | HIGH / MEDIUM | A dangerous payload is reachable only after a compression/archive path that single-format scanners miss: any path of length ≥ 2, or a single non-zip layer (`gz→pkl`, `tar→pkl`, …). HIGH when the payload is magic-confirmed (pickle/HDF5/NumPy), MEDIUM when inferred from the file name only. |
| `NC002` | MEDIUM | A container nested inside another container (archive-within-archive) — the chained structure the bypass relies on. |
| `NC003` | LOW | A defensive limit was hit: per-member cap, total-size cap, member-count cap, or maximum nesting depth (possible decompression bomb or anti-analysis nesting). |
| `NC010` | MEDIUM | A nested member uses a codec the standard library cannot decode (`zstd`, `lz4`); stdlib-based scanners skip it silently. Decode with that codec and rescan. |
| `NC011` | MEDIUM | A nested archive member could not be opened by the standard library (bad CRC, bad flag bits, malformed header, encryption). A loader with a different/tolerant decoder may still read it — the exact surface of CVE-2025-10156 and CVE-2025-1944. |
| `NC000` | INFO | No nested-container evasion detected. |

A payload sitting directly inside **one** ZIP (the ordinary PyTorch `.pt`
layout) is **not** flagged — that is the case the format scanners already
handle. The signal here is the *extra* hiding layer.

## Usage

```bash
# scan one or many files / directories
python nested_container_scan.py path/to/model.bin another_dir/

# machine-readable output
python nested_container_scan.py model.tar.gz --json

# fail CI when something at or above a severity is found
python nested_container_scan.py downloads/ --fail-on HIGH
```

As a library:

```python
import nested_container_scan as ncs

for f in ncs.scan_bytes(open("suspect.tar.gz", "rb").read(), "suspect.tar.gz"):
    print(f.rule, f.severity, f.location, f.message)
```

## Limits (honest)

- Detection is by magic / name, so a payload whose format this module does not
  recognize at a leaf will not be flagged as dangerous (though its nesting and
  any unreadable/undecodable wrappers still are).
- `zstd` and `lz4` members are reported, not decoded (no standard-library
  codec through Python 3.13); supply the decoded bytes to rescan them.
- Depth, per-member size, total size and member-count caps bound work on
  untrusted input; content beyond a cap is reported (`NC003`) but not scanned.
- Name-based rules (`NC001` MEDIUM) can over- or under-fire; treat them as a
  prompt to route the member to a format scanner, not as proof of malice.

## License

Apache-2.0. Copyright 2026 MV2, Munim, Inc.
