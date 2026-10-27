# GGUF tensor `ggml_nbytes` integer-overflow recall audit (CVE-2026-33298 and CVE-2026-116829)

**Project:** `munimtechnologies/keras-model-scan` (Apache-2.0)
**Scope:** source review only. No code was executed; no live or hosted system was
touched. This audit reads two public upstream security advisories and three files of
this repository (`gguf_scan.py`, `gguf_data_region_scan.py`), then reasons about which
tensor-shape integer-overflow preconditions the scanner statically detects and which it
does not. Reproducible by reading the same open files; no model was loaded.

*This work was done by AI agents working in the name of MV2 of Munim, Inc. Findings are
limitations of a **defensive** static scanner, not newly discovered library
vulnerabilities. Both upstream CVEs below are already fixed by their projects.*

---

## 1. The two upstream vulnerabilities

Both are integer overflows during GGUF tensor-size calculation in `ggml`/`llama.cpp`.
They are the same bug *family* but attack two different arithmetic quantities.

### CVE-2026-33298 — byte-size overflow in `ggml_nbytes` (CWE-190 → CWE-122)
- Advisory: GHSA-96jg-mvhq-q7q7 (ggml-org/llama.cpp). CVSS 7.8 High. Patched **b7824**
  (affected `< b7437`).
- Mechanism (from the advisory): `ggml_nbytes()` sums `nbytes += (ne[i]-1)*nb[i]` over
  dimensions. The strides `nb[]` derive from the type's element size, so the product of
  **dimensions × element size** can wrap past `2^64` on a 64-bit host.
- Published PoC tensor: `type = F32` (4 bytes, block size 1),
  `ne = [1024, 1024, 4398046511105, 1]` where `4398046511105 = 2^42 + 1`.
  Element count `≈ 2^62`; byte size `≈ 2^62 × 4 = 2^64`, which wraps to ≈ 0 (the loader
  sees ≈ 4 MB instead of exabytes), so a later `fread` writes far past the allocation.
- Root cause the advisory names explicitly: the loader validated **only that the element
  count fits in `INT64_MAX`**, never that the derived **byte** size stays under
  `SIZE_MAX`. The fix adds a byte-level guard, e.g.
  `if (total_elements > SIZE_MAX / ggml_type_size(type)) { return false; }`, plus
  `__builtin_mul_overflow` in the stride math.

### CVE-2026-116829 — element-count product wraps to zero in `gguf_init_from_reader`
- Published **2026-10-27** (the day of this audit). Affected `b10398` … `< b11301`
  (">=0.1.0 <0.6.0"). CVSS 6.9 Medium. Fixed **b11301 / 0.6.0**.
- Mechanism: attacker supplies **shapes whose product wraps to zero**, bypassing
  element-count validation, producing an oversized tensor extent and out-of-bounds
  access. This attacks the **element-count** product (not the byte size).

---

## 2. What this repository's GGUF suite checks

Two scanners touch tensor dimensions. Exact trigger conditions (read at `main`):

**`gguf_scan.py` — GG009** reads the tensor-info table and accumulates the element
count as a Python arbitrary-precision product, then checks it against the signed 64-bit
ceiling:

```python
product = 1
for _d in range(n_dims):
    product *= r.u64()
ttype = r.u32()
offset = r.u64()
...
if product > _INT64_MAX:   # _INT64_MAX = (1 << 63) - 1   → GG009 HIGH
```

GG009 compares the **element-count** product only. It never multiplies by the type's
byte size. (`_MAX_GGML_TYPE = 39` is validated separately as GG010; `n_dims` as GG008.)

**`gguf_data_region_scan.py` — GDR001 / GDR002** computes a per-tensor byte extent and
checks it against the file:

```python
nelem = 1
for d in dims:
    nelem *= d
nbytes = nelem * elem_size
if start + nbytes > file_size:   # GDR002 HIGH ; start = data_start + offset
```

Crucially, `elem_size` comes from `_EXACT_ELEM_SIZE`, which — by deliberate design —
contains **only unambiguous, block-size-1 types** (F32, F16, I8/I16/I32/I64, F64,
BF16). Its comment states quantized/block types are *"deliberately omitted"* to avoid
*"ever flagging a legitimate quantized tensor by a mis-stated block size."* When `ttype`
is a quantized type, `elem_size is None` and **GDR002 is skipped entirely** — only
GDR001 (`start >= file_size`) still applies, and GDR001 never looks at the tensor's
length.

---

## 3. Per-CVE, per-type recall — verified by arithmetic, no execution

| Attack | Our detection | Why |
|---|---|---|
| **116829** — element-count product wraps to 0 in C | **Caught** (GG009) | Python's `product *= r.u64()` is arbitrary-precision and never wraps, so the *true* product (e.g. `2^64`) exceeds `_INT64_MAX` and GG009 fires. The C wrap-to-zero bypass simply does not exist in our math. |
| **33298** — byte overflow, **block-size-1 type** (the published F32 PoC) | **Caught** (GDR002) | `nelem ≈ 2^62`, `nbytes ≈ 2^64`; `start + 2^64 > file_size` is true for any real file, so GDR002 HIGH fires. Note GG009 does **not** fire here: `2^62 < 2^63 = _INT64_MAX`. |
| **33298** — byte overflow, **quantized type** (e.g. Q4_K, Q6_K, Q8_0) | **Missed** | GDR002 is skipped for quantized types (no `_EXACT_ELEM_SIZE` entry), and GG009 only tests the element count against `INT64_MAX` — exactly the element-count-only validation the advisory names as the root cause. A quantized tensor with element count `< 2^63` but byte size `> 2^64` slips past the whole suite. |

**The residual gap, stated precisely:** a GGUF tensor declaring a **quantized** type and
dimensions whose element-count product is below `INT64_MAX` while the derived byte size
(`elements / block_size × type_size`) overflows `SIZE_MAX` is detected by **neither**
GDR002 (silent on quantized types by design) **nor** GG009 (element-count-only). This is
the `ggml_nbytes` precondition of CVE-2026-33298, realised on the tensor types that make
up the overwhelming majority of real-world GGUF weights.

The attacker fully controls the type id and every dimension, and the overflow in
`ggml_nbytes` is type-agnostic (the published F32 example is illustrative, not a
limitation of the bug), so the quantized-type variant is reachable in principle.

---

## 4. Fix specification (bounded, false-positive-safe) — for GG009

Add a complete per-type trait table and a **`SIZE_MAX` overflow guard** to GG009,
mirroring the upstream patch. This closes the quantized-type gap without re-introducing
the false positives that GDR002 was designed to avoid, because it tests for **arithmetic
overflow**, not for `bytes > file_size`:

1. `_GGML_TYPE_TRAITS[ttype] = (block_size, type_size)` for all 40 ggml types
   (`block_size` = elements per block, `type_size` = bytes per block; for F32 this is
   `(1, 4)`, for Q4_K `(256, 144)`, etc. — standard ggml constants).
2. Compute a byte-size estimate: `nbytes = (product // block_size) * type_size`
   (a lower bound suffices for overflow detection; quantization runs along `ne[0]`).
3. Flag **HIGH** when `nbytes > _SIZE_MAX` (`_SIZE_MAX = (1 << 64) - 1`): the exact
   `ggml_nbytes`/host overflow precondition. This is the direct analogue of the
   upstream `total_elements > SIZE_MAX / ggml_type_size(type)` check.
4. Keep the existing `product > _INT64_MAX` element-count test as-is (it already covers
   the 116829 wrap-to-zero family).

**Why this will not false-positive:** `2^64` bytes is 18 exabytes. No legitimate model —
quantized or not — comes within many orders of magnitude of it, so an overflow flag only
ever fires on a maliciously crafted shape. This is a strictly tighter, overflow-only test
than GDR002's file-size comparison, which is what let GDR002 safely omit quantized types
in the first place.

Implementing this edits a live scanner module and its test, so it is a **compute-job**
change (the sandbox re-runs the suite), queued for when a sandbox slot frees. This
document specifies it precisely so the code change is a mechanical follow-up.

---

## 5. Honest limits

- This is a **recall limitation in a defensive tool**, not a new library vulnerability.
  Both upstream bugs are already fixed (b7824; b11301/0.6.0).
- The missed case is the **quantized-type** variant of a *known* overflow class; the
  published F32 PoC is already caught (by GDR002). No crafted file was built or run here
  — the claim rests on the exact scanner conditions plus the advisory's described math.
- Whether any given overflowed tensor reaches memory corruption depends on the **host
  loader** (llama.cpp/Ollama/LM Studio build and allocation path); a static model-file
  scanner can only flag the *precondition* in the file, which is what the fix does.
- `SIZE_MAX` is host-dependent; the fix pins it to `2^64-1` (64-bit hosts), matching the
  environment the upstream advisory and PoC target.

## 6. References
- GHSA-96jg-mvhq-q7q7 / CVE-2026-33298 (ggml-org/llama.cpp), patched b7824.
- CVE-2026-116829 (llama.cpp `gguf_init_from_reader`), published 2026-10-27, fixed
  b11301 / 0.6.0.
- This repo: `gguf_scan.py` (GG009), `gguf_data_region_scan.py` (GDR001/GDR002),
  `GGUF_INTEGER_FIELD_BOUNDS_CENSUS.md`.
