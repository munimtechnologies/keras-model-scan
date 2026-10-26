# GGUF integer-field bounds-direction census (`gguf_scan.py` GG000–GG012)

*By MV2 of Munim, Inc. Work made with AI agents in MV2's name. Source review only;
no code was executed and no live system was touched. keras-model-scan `main`,
reviewed 2026-10-26.*

## Why this exists

The run that shipped
[`GGUF_OSS_SECURITY_2026_COVERAGE_AUDIT.md`](./GGUF_OSS_SECURITY_2026_COVERAGE_AUDIT.md)
found one confirmed false-negative in `gguf_scan.py`: rule **GG011**'s alignment
check (`if alignment == 0 or (alignment & (alignment - 1)) != 0:`) flags only zero
and non-power-of-two values, so a crafted `general.alignment = 0x80000000` (`2**31`,
a nonzero power of two) passes unflagged — the oss-security 2026 q2/546 **V-01**
trigger. That raised an obvious follow-up question that needs no new vulnerability
and no code execution to answer:

> Is `alignment` the **only** check in `gguf_scan.py` that trusts an attacker-chosen
> integer because its predicate has no range bound, or do sibling checks share the
> same shape?

This doc answers it by classifying **every numeric field** that `gguf_scan.py` reads
from the file by the *direction* of its bound (upper, lower, or predicate-only). The
result: V-01 is the sole genuine range-bound gap. Everything else is either a
correct-by-design equality/enum predicate or carries an upper bound. Two
coverage-map statements turn out to need a small correction; both are recorded here.

## Method

For each rule GG000–GG012 I read the exact `if ...:` trigger condition on `main` and
noted which file-sourced integer it tests and whether that integer is bounded above,
bounded below, or only tested by an equality / enum-membership / power-of-two /
divisibility predicate. Conditions are quoted verbatim as short lines (the one form
of quoting that reproduces reliably). All GGUF count/length/dimension fields are read
as unsigned (`u32`/`u64`) by `_Reader`, which matters for the lower-bound column.

## Census table

| Rule | File-sourced field | Exact trigger condition | Bound direction | Verdict |
|---|---|---|---|---|
| GG001 | magic / buffer len | `if len(raw) < 8 or raw[:4] != b"GGUF":` | len lower + bytes equality | correct-by-design |
| GG002 | version | `if ver_le in (1, 2, 3):` / `if version == 1:` | enum membership | correct-by-design |
| GG003 | `kv_count` | `if kv_count * _MIN_KV > file_size or kv_count > file_size:` | **upper ×2** | bounded |
| GG003 | `tensor_count` | `if tensor_count * _MIN_TI > file_size or tensor_count > file_size:` | **upper ×2** | bounded |
| GG004 | string / key / name len | `if n > r.end or n > file_size:` (and `key_len`, `name_len`) | **upper ×2** | bounded |
| GG005 | `depth` | `if depth > 64:` | **upper** | bounded |
| GG005 | `elem_type` / `vtype` | `if elem_type not in _KNOWN_VALUE_TYPES:` | enum membership | correct-by-design |
| GG006 | array `count` / `total` | `if count < 0 or total > (1 << 64) or total > r.end or total > file_size:` | **upper ×3** (+ dead lower, see below) | bounded |
| GG006 | composite array `count` | `if count > _ELEM_WALK_CAP:` | **upper** | bounded |
| GG007 | tensor `name_len` | `if name_len > _NAME_MAX:` | **upper** | bounded |
| GG008 | `n_dims` | `if n_dims > _NDIMS_HARD_CAP:` / `if n_dims > _NDIMS_SPEC_MAX:` | **upper** | bounded |
| GG009 | dim `product` | `if product > _INT64_MAX:` | **upper** | bounded |
| GG010 | tensor type `ttype` | `if ttype > _MAX_GGML_TYPE:` | **upper** | bounded |
| GG011 | `alignment` | `if alignment == 0 or (alignment & (alignment - 1)) != 0:` | zero + power-of-two predicate, **no upper** | **GAP (V-01)** |
| GG011 | `offset` | `if alignment and offset % alignment != 0:` | divisibility predicate, no range | see §Offset |
| GG012 | reader take/skip | `if n < 0 or self.pos + n > self.end:` | upper (vs buffer end) | bounded |

## Findings

### 1. V-01 (`alignment`, GG011) is the only genuine range-bound false-negative

Four fields are tested by predicate rather than by range: magic bytes, version,
array/value element types, and `alignment`. The first three are **correct by
design** — a magic number, a format version, and a GGML type id are each valid only
as specific discrete values, so equality / enum-membership is the right test and a
"range" would be meaningless. `alignment` is the odd one out: it is a *magnitude*
that feeds later size/offset arithmetic, so "is it a power of two" is necessary but
not sufficient. Without an upper bound, the whole band `2**16 … 2**31` (every power
of two) is representable via the `r.u32()` read and passes clean. That is exactly
V-01, and the census confirms no other field shares the shape.

The fix already specced in the oss-security audit doc stands unchanged: add
`_ALIGNMENT_MAX` and flag `alignment >= (1 << 16)` (MEDIUM) — `GGML_PAD` operates on
a 32-bit boundary, so no legitimate GGUF needs an alignment at or beyond 64 KiB.

### 2. The `offset` divisibility check is **not** a second gap

GG011's second clause (`if alignment and offset % alignment != 0:`) tests only
whether a tensor's `offset` is a multiple of `alignment`; it never bounds `offset`
against the file. On its own that would look like an out-of-bounds-offset
false-negative. It is not, because offset range is enforced by a **different rule in
a different module**: `gguf_data_region_scan.py` **GDR001** (HIGH) flags
`data_section_start + offset >= file_size`, and **GDR002** (HIGH) flags
`start + nbytes > file_size` for unambiguously sized types. So the OOB-offset class
(CVE-2026-108955, PowerInfer `gguf_init_from_file`) is covered — by GDR001, not by
GG011. The division of labour is sound: GG011 validates *alignment semantics*,
GDR001/002 validate *spatial containment*.

One interaction is worth recording honestly. Because GG011's offset clause uses the
file-declared `alignment` as its modulus, the unflagged V-01 value (`alignment =
2**31`) would also become the modulus: every real tensor offset (all `< 2**31`)
would then be reported non-aligned by GG011. This does **not** weaken GDR001's OOB
detection (GDR001 computes containment from `data_section_start + offset`
independently of `alignment`), so it is a *noise/clarity* consequence of V-01 inside
GG011's own output, not a new security hole. Fixing V-01 (flagging the oversized
alignment up front) removes the spurious offset noise as a side effect.

### 3. The `count < 0` clause in GG006 is dead code (unsigned read)

`count` in GG006 is read as an unsigned `u64`, so `count < 0` can never be true. The
clause is harmless but inert; the real protection for that field is the three upper
bounds beside it (`total > (1 << 64)`, `total > r.end`, `total > file_size`). This
is a code-clarity note, not a security finding. It is the only lower-bound test in
the whole scanner, and it reflects a signed-int habit applied to an unsigned field.

## Two small coverage-map corrections (`GGUF_CVE_MAP.md`)

The census surfaced two statements in `GGUF_CVE_MAP.md` that are accurate for the
crafted corpus file but overstate or mis-attribute coverage at the *attack-class*
level. Recording them here so the next code-editing run can correct the map
alongside the GG011 patch:

1. **`general.alignment` row is rated coverage `full`.** That is true for the corpus
   file `bad_alignment.gguf` (a non-power-of-two value, which GG011 catches). It
   overstates the alignment *attack class*: the power-of-two-but-oversized sub-case
   (V-01) is a false-negative. Suggested change: rate it `partial` and cite
   oss-security 2026 q2/546 V-01, pending the `_ALIGNMENT_MAX` fix that restores
   `full`.

2. **The `tensor data offset` / CVE-2026-108955 row is attributed to rule GG011.**
   GG011's offset clause is divisibility-only; the rule that actually bounds the
   offset against the file is **GDR001** in `gguf_data_region_scan.py`. Suggested
   change: attribute that row to GDR001 (with GDR002 for sized types), which makes
   the `partial` rating self-consistent — GDR001 covers "starts past EOF", GDR002
   covers "ends past EOF" for block-size-1 types, and quantized/block types are
   intentionally skipped.

Neither correction changes scanner behaviour; both make the map match what the code
actually does.

## Honest limits

- This is a coverage/attribution review of **our own tool and docs**, not a new
  vulnerability in llama.cpp, PowerInfer, or any other project. V-01 is public
  (oss-security 2026 q2/546); CVE-2026-108955 is public (VulDB VDB-416774 /
  PowerInfer#283).
- No code was executed this run. The conditions above were read from source; the
  "V-01 passes GG011" and "GDR001 catches the offset" conclusions are source-review
  conclusions. The before/after proof-of-concept for the GG011 fix is specced in the
  oss-security audit doc and remains pending a sealed sandbox slot.
- "Correct-by-design" verdicts assume the upstream GGUF spec's discrete-value
  semantics for magic, version, and type-id fields; if a future GGUF revision widened
  any of those to a range, that verdict would need revisiting.

## What this changes for the next run

1. The GG011 `_ALIGNMENT_MAX` fix (already specced) is confirmed as the single code
   change that closes the only range-bound false-negative in the scanner.
2. Bundle the two `GGUF_CVE_MAP.md` corrections above with that fix when a sandbox
   slot frees, so code and map ship together.
3. The census is reusable: any new numeric field added to `gguf_scan.py` should be
   checked against this table's "bounded above?" column before it is trusted in size
   or offset arithmetic.
