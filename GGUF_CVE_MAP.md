# GGUF model-file CVE map and regression corpus

A reproducible map from the public cluster of **GGUF parser memory-safety
advisories** to (1) the exact header field whose declared value drives the
overflow, (2) the weakness class (CWE), and (3) the static `gguf_scan.py` rule
(GG000–GG012) that flags the precursor **before any loader runs** — plus a tiny,
**benign, header-only** regression corpus you can feed to any GGUF reader.

- Code: `gguf_cve_corpus.py` — Apache-2.0.
- Data: `gguf_cve_map.json` — CC BY 4.0.
- Made with AI, by MV2 of Munim, Inc. Advisory IDs verified at their sources
  (Cisco Talos, GitHub Security Advisories, OSV/NVD, VulDB) on 2026-10-14.

## Why this exists

GGUF (the llama.cpp / Ollama / LM Studio / PowerInfer model container) has **no
code-execution surface of its own** — but hand-written C/C++ `ggml` readers and
derivatives have repeatedly turned a malformed **header** into a heap
out-of-bounds write/read through integer overflow. The values that trigger these
overflows all live in the file header, so a static pre-load check can flag them.
This map records which header field each advisory abuses and which `gguf_scan`
rule catches the precursor, and ships a corpus to regression-test the detection.

## The map

| Crafted file | Header field | `gguf_scan` rule | Coverage | Advisories |
|---|---|---|---|---|
| `kv_count_overflow.gguf` | `metadata_kv_count` | GG003 | full | CVE-2024-23605 |
| `tensor_count_overflow.gguf` | `tensor_count` | GG003 | full | CVE-2025-53630, CVE-2026-27940 |
| `array_len_overflow.gguf` | metadata array length | GG006 | full | CVE-2024-21825 |
| `string_len_overrun.gguf` | metadata string length | GG004 | full | CVE-2024-23496 |
| `tensor_dims_overflow.gguf` | tensor dimensions | GG009 | full | CVE-2026-33298 |
| `bad_alignment.gguf` | `general.alignment` | GG011 | full | (no CVE; GGML_PAD hardening) |
| `data_offset_oob.gguf` | tensor data offset | GG011 | partial | CVE-2026-108955 |

### Advisories

| CVE | Ref | Component | CWE | Fix |
|---|---|---|---|---|
| CVE-2024-21825 | TALOS-2024-1912 | GGUF `GGUF_TYPE_ARRAY`/`GGUF_TYPE_STRING` parsing | CWE-787 | ggml ≥ 2024-01-09 |
| CVE-2024-23496 | TALOS-2024-1913 / GHSA-w4wv-vq5v-xp26 | `gguf_fread_str` | CWE-190, CWE-787 | ggml ≥ 2024-01-09 |
| CVE-2024-23605 | TALOS-2024-1916 | `header.n_kv` handling | CWE-190, CWE-787 | ggml ≥ 2024-01-09 |
| CVE-2025-53630 | GHSA-vgg9-87g3-85w8 | `gguf_init_from_file_impl` | CWE-680, CWE-122 | commit `26a48ad` |
| CVE-2026-27940 | GHSA-3p4r-fq3f-q74v | `mem_size` (bypass of CVE-2025-53630 fix) | CWE-122 | build `b8146` |
| CVE-2026-33298 | ggml_nbytes advisory | `ggml_nbytes()` tensor-size | CWE-190, CWE-122 | build `b7824` |
| CVE-2026-108955 | VulDB VDB-416774 / PowerInfer#283 | PowerInfer `gguf_init_from_file` data_offset | CWE-125 | pending |

## Using the corpus

```bash
python gguf_cve_corpus.py --out-dir ./corpus --map ./gguf_cve_map.json
gguf-scan ./corpus --fail-on HIGH      # every crafted file should be flagged
```

Each crafted file is a **header only**: it merely *declares* an extreme value
(a metadata/array/string count near 2**64, a tensor-dimension product that
overflows, an out-of-bounds tensor offset, or a zero `general.alignment`). The
files contain **no tensor data and no exploit payload**. A naive parser
integer-overflows on the declared value; a bounds-checking parser (or
`gguf-scan`) rejects it.

## Honest limits

- Every CVE here is **already public**; nothing in this repository is a zero-day.
- The corpus is **header-only** and carries **no payload** — it exercises
  detection, not exploitation.
- `data_offset_oob.gguf` is marked **partial**: `gguf_scan` flags the unaligned
  offset (GG011), but validating that every tensor's data region lies within the
  file is a documented gap, not yet a dedicated rule.
- A clean scan **guarantees nothing** — it only means these specific precursors
  are absent from the header.

## Sources

- Cisco Talos TALOS-2024-1912/1913/1916 (CVE-2024-21825/-23496/-23605).
- GitHub Security Advisories GHSA-vgg9-87g3-85w8 (CVE-2025-53630),
  GHSA-3p4r-fq3f-q74v (CVE-2026-27940), GHSA-w4wv-vq5v-xp26 (CVE-2024-23496).
- NVD / OSV for CVE-2026-33298; VulDB VDB-416774 for CVE-2026-108955.
