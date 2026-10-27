# GGUF `ggml_nbytes` overflow recall: correction and completeness proof (CVE-2026-33298)

**Repository:** `munimtechnologies/keras-model-scan` (Apache-2.0)
**Date:** 2026-10-27 · **Supersedes** the quantized-type recall-gap claim in
`GGUF_NBYTES_OVERFLOW_CVE_2026_33298_RECALL_AUDIT.md` (same repo).
**Made with AI agents working in the name of MV2 of Munim, Inc.** Source review and
arithmetic only; no crafted file was executed (see *Method and limits*). Text: CC BY 4.0.

## TL;DR

The earlier audit of this repo's GGUF suite against the `ggml_nbytes` integer-overflow
CVEs claimed that **quantized** tensor types (Q4_K / Q6_K / Q8_0 …) could declare an
element count below `2^63` while their on-disk byte size exceeds `2^64`, slipping past
both `GG009` (element-count check) and `GDR002` (which deliberately skips quantized
types). It proposed adding a per-type byte-size guard to `GG009`.

**That gap is not reachable, so the proposed guard is unnecessary.** Working the
arithmetic through the *actual* ggml type traits shows the "silent `GG009` **and**
byte-overflow" region is empty for every quantized type, because **no ggml quantized
type packs more than ~1.14 bytes per element**. A byte-size overflow therefore always
forces an element count above `2^63-1`, which `GG009` already flags. The only types that
can overflow bytes while the element count stays under the `GG009` ceiling are the
block-size-1 types with ≥ 4 bytes/element (F32, I32, F64, I64) — and those are exactly
the types `GDR002` covers. The pair **`GG009` ∪ `GDR002` has complete recall** for the
`ggml_nbytes` byte-size overflow class (CVE-2026-33298). No code change ships.

## Background: the two CVEs and the two rules that bear on them

- **CVE-2026-33298** (GHSA-96jg-mvhq-q7q7): `ggml_nbytes` overflows `size_t` because the
  tensor byte size (`≈ elements × type_size / block_size`) wraps `2^64`. Published PoC:
  `F32`, `ne = [1024, 1024, 2^42 + 1, 1]`.
- **CVE-2026-116829**: the element-count product itself wraps to `0` inside
  `gguf_init_from_reader`.

Two rules in this repo bear on these, both re-verified from source at `main` on
2026-10-27:

- **`GG009`** (`gguf_scan.py`). In the tensor-info loop it accumulates the pure element
  count and flags an overflow precondition:
  ```python
  _INT64_MAX = (1 << 63) - 1
  product = 1
  for _d in range(n_dims):
      product *= r.u64()
  ...
  if product > _INT64_MAX:   # GG009 HIGH
  ```
  `product` is Python's arbitrary-precision integer, so it holds the **true** element
  count and never wraps. `GG009` never multiplies `product` by a type/element byte size.
- **`GDR002`** (`gguf_data_region_scan.py`). It bounds the tensor's data region, but only
  for types whose byte size is unambiguous (block size 1):
  ```python
  _EXACT_ELEM_SIZE = {0:4, 1:2, 24:1, 25:2, 26:4, 27:8, 28:8, 30:2}
  #                   F32 F16  I8   I16  I32  I64  F64  BF16
  elem_size = _EXACT_ELEM_SIZE.get(ttype)
  if elem_size is not None:
      nelem = 1
      for d in dims:
          nelem *= d
      nbytes = nelem * elem_size
      if start + nbytes > file_size:   # GDR002 HIGH
  ```
  Quantized types return `None` from `.get`, so `GDR002` is skipped for them (by design,
  to avoid a false positive from a mis-stated block size). `file_size` is the real
  on-disk length (not an attacker-declared field), and `nbytes` is a Python big integer,
  so for an overflowing tensor `nbytes ≈ 2^64` is vastly larger than any real file and the
  check fires.

CVE-2026-116829 (element-count wrap-to-0) is caught by `GG009`: the true product exceeds
`2^63-1`, so the HIGH fires regardless of how C would wrap. That part of the earlier
audit stands and is unaffected by this correction.

## The claim being corrected

The earlier audit stated (claim #3):

> 33298 for **quantized types** (Q4_K/Q6_K/Q8_0 — most real GGUF weights) is **MISSED**:
> GDR002 deliberately skips quantized types … and GG009 only tests element count vs
> INT64_MAX … A quantized tensor with elem count < 2^63 but byte size > 2^64 slips past
> the whole suite.

The flaw in that reasoning is that it never checked whether a quantized tensor can
*actually* satisfy "element count < 2^63 **and** byte size > 2^64" at the same time. It
cannot.

## The arithmetic

Let a tensor have element count `N = product(dims)` and a type with block size `B` and
type size `T` bytes. On disk the tensor is contiguous, so

```
ggml_nbytes  ≈  (N / B) * T  =  N * r,     where  r = T / B   (bytes per element)
```

(per-row padding is bounded and negligible at the scales involved, so `r` governs).

A **recall gap** means the suite is silent, i.e. both:

1. `GG009` silent:   `N ≤ 2^63 - 1`
2. byte overflow:    `N * r > 2^64 - 1`

Combine them. From (1), `N * r ≤ (2^63 - 1) * r`. For (2) to also hold we need
`(2^63 - 1) * r > 2^64 - 1`, i.e.

```
r  >  (2^64 - 1) / (2^63 - 1)  =  2 + 1/(2^63 - 1)  >  2.
```

**So a gap requires strictly more than 2 bytes per element.** Now look at the real ggml
type traits (authoritative: `gguf-py/gguf/constants.py`, `GGML_QUANT_SIZES`, `QK_K=256`):

| Type | block `B` | size `T` | `r = T/B` | > 2 ? | caught by |
|------|----------:|---------:|----------:|:-----:|-----------|
| F32  | 1 | 4   | 4.000 | yes | GDR002 (and GG009 for N>2^63) |
| F16  | 1 | 2   | 2.000 | no  | GG009 (overflow needs N>2^63) |
| BF16 | 1 | 2   | 2.000 | no  | GG009 |
| I8   | 1 | 1   | 1.000 | no  | — (can't overflow) |
| I16  | 1 | 2   | 2.000 | no  | GG009 |
| I32  | 1 | 4   | 4.000 | yes | GDR002 |
| I64  | 1 | 8   | 8.000 | yes | GDR002 |
| F64  | 1 | 8   | 8.000 | yes | GDR002 |
| Q4_0 | 32 | 18 | 0.563 | no  | GG009 |
| Q4_1 | 32 | 20 | 0.625 | no  | GG009 |
| Q5_0 | 32 | 22 | 0.688 | no  | GG009 |
| Q5_1 | 32 | 24 | 0.750 | no  | GG009 |
| Q8_0 | 32 | 34 | 1.063 | no  | GG009 |
| Q8_1 | 32 | 36 | 1.125 | no  | GG009 |
| Q2_K | 256 | 84  | 0.328 | no | GG009 |
| Q3_K | 256 | 110 | 0.430 | no | GG009 |
| Q4_K | 256 | 144 | 0.563 | no | GG009 |
| Q5_K | 256 | 176 | 0.688 | no | GG009 |
| Q6_K | 256 | 210 | 0.820 | no | GG009 |
| **Q8_K** | 256 | 292 | **1.141** | no | GG009 |
| IQ2_XXS…IQ4_XS | 32 or 256 | ≤ 136 | ≤ 0.531 | no | GG009 |
| TQ1_0 / TQ2_0 | 256 | 54 / 66 | ≤ 0.258 | no | GG009 |
| MXFP4 | 32 | 17 | 0.531 | no | GG009 |

The densest quantized type is **Q8_K at ~1.141 bytes/element**; every other quantized
type is below ~1.13. **No quantized type reaches `r > 2`.** Concretely, at the `GG009`
boundary `N = 2^63 - 1`, the largest quantized byte size is
`(2^63-1) * 1.141 ≈ 1.05 × 10^19 < 2^64 - 1 ≈ 1.845 × 10^19` — no overflow. For any
quantized type the byte size stays below `2^64` right up to the point where `GG009` fires
on the element count. There is no window.

The only types with `r > 2` are **F32, I32, I64, F64**, all of which are keys in
`_EXACT_ELEM_SIZE`, so `GDR002` evaluates them: their overflowing byte size (a Python big
integer `> 2^64`) exceeds the real `file_size`, and `GDR002` HIGH fires. The borderline
`r = 2` types (F16, BF16, I16) have no gap at all, because reaching `N * 2 > 2^64` already
requires `N > 2^63`, which trips `GG009`.

## Conclusion

For the `ggml_nbytes` byte-size overflow class (CVE-2026-33298):

- **Quantized types** (all `r < 2`): any byte overflow forces `N > 2^63 - 1` → **`GG009`
  catches it**. `GDR002` skipping quantized types costs **no** recall here.
- **Block-size-1 types** with `r ≥ 2`: `GG009` may be silent in a bounded `N` window, but
  **`GDR002` catches them** (they are all in `_EXACT_ELEM_SIZE`).

So **`GG009` ∪ `GDR002` has complete recall** for this CVE class under the stated model.
The per-type byte-size guard proposed in the earlier audit would, where it fired at all,
only duplicate `GDR002` on the block-size-1 types and would **never** add a detection for
a quantized type. **It is not shipped.** Avoiding an unnecessary 40-entry type-traits
table and its maintenance burden — code that can never improve recall — is the correct
outcome.

## Method and limits

- **This is a non-existence (completeness) result**, which a single crafted-file PoC can
  only ever *fail* to disprove, not establish. The proof rests on (a) the exact `GG009`
  and `GDR002` conditions, re-verified verbatim from source at `main` on 2026-10-27, and
  (b) the authoritative ggml `GGML_QUANT_SIZES` traits. Both are cited above.
- **Model:** `ggml_nbytes ≈ product(dims) × type_size / block_size` for a contiguous,
  on-disk GGUF tensor. Per-row padding is bounded and does not change the asymptotic
  bytes-per-element `r`, which is what the threshold `r > 2` depends on. A tensor stored
  non-contiguously is not representable in the GGUF on-disk layout.
- **Scope:** recall of *this repo's defensive scanner* for an upstream CVE that is already
  fixed in llama.cpp/ggml. This is not a new library vulnerability and nothing here is a
  live target. No file was run because the sandbox queue is congested; a PoC is not the
  right instrument for a completeness claim in any case.
- **Unchanged:** the earlier audit's claims #1 (CVE-2026-116829 wrap-to-0 caught by
  `GG009`) and #2 (the published F32 PoC caught by `GDR002`) both hold.

---
*Part of the open-source `munimtechnologies/keras-model-scan` toolkit (Apache-2.0).
Published by MV2 of Munim, Inc. This analysis was produced by AI agents working in his
name.*
