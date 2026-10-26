# GGUF oss-security 2026 advisory coverage: V-01 (unbounded `general.alignment`) is a confirmed false-negative in `gguf_scan.py` GG011

*Made with AI agents working in the name of MV2, Munim, Inc. Source review only; no code
was run against any system and no live target was touched. Text: CC BY 4.0.*

## What this is

On 2026-05-15 a researcher posted **"Multiple Vulnerabilities in llama.cpp GGUF Format
Parsers"** to oss-security (seclists.org/oss-sec/2026/q2/546), enumerating six flaws
(**V-01 … V-06**) in the GGUF parsers `gguf.cpp` (C/C++ core) and `gguf_reader.py`
(the gguf-py Python reference). None of the six carries an assigned CVE at the time of
writing. Our own `GGUF_CVE_MAP.md` maps the *numbered* GGUF CVEs (CVE-2024-21825/-23496/
-23605, CVE-2025-53630, CVE-2026-27940/-33298/-108955) but does **not** reference this
advisory.

This document does three things:

1. Maps each of the six advisory flaws against the rules `gguf_scan.py` already ships
   (GG000–GG012), stating honestly which are caught, which are caught *in effect*, and
   which are missed.
2. Reports one **confirmed false-negative** in our own tool: **V-01 passes GG011
   unflagged**, because GG011 checks only that `general.alignment` is a nonzero power of
   two, and the advisory's trigger value `0x80000000` (= 2³¹) *is* a nonzero power of two.
3. Gives the exact fix (an upper-bound check in GG011) and a sealed, header-only PoC
   spec that measures the before/after.

## Why this is new

Prior public work treats each GGUF parser CVE in isolation, or (as in the vendor advisory
and downstream write-ups) describes the parser bugs themselves. We found no prior work
that maps the May-2026 oss-security six-flaw advisory against any **static, pre-load GGUF
header scanner**, and in particular none that notes the subtle point that the common
hardening — *reject non-power-of-two alignment* — does **not** stop V-01, because the
advisory's own trigger value is itself a power of two. That observation is what turns a
"we already warn on bad alignment" assumption into a measurable coverage gap. The finding
is a quality gap in **our own** tool, not a new vulnerability in llama.cpp; the advisory
is already public and no exploit payload is produced here.

## Coverage of V-01 … V-06 against `gguf_scan.py`

| Flaw | Sev (adv.) | Parser | Trigger field | Our rule | Status |
|------|-----------|--------|---------------|----------|--------|
| **V-01** | CRITICAL | both | `general.alignment` with no upper bound (`0x80000000`, any value ≥ 2¹⁶) → `GGML_PAD` integer overflow on 32-bit → arbitrary file seek + OOB read | **GG011** | **MISS — confirmed false-negative** |
| V-02 | HIGH | C++ | `GGUF_MAX_STRING_LENGTH`/`GGUF_MAX_ARRAY_ELEMENTS` both 1 GiB → ~1 EB allocation / OOM | GG004, GG006 | Caught *in effect* for any file-bounded case (declared string/array length is cross-checked against file size; the pure upstream limit-tuning is not a header property) |
| V-03 | HIGH | Python | `n_dims = 0xFFFFFFFF` (C++ caps at `GGML_MAX_DIMS = 4`; Python has no check) → ~32 GB mmap read | **GG008** | **Caught** (`n_dims` compared against spec max 4 and a hard cap) |
| V-04 | MEDIUM | C++ | `n_tensors`/`n_kv` read as `int64_t`, implicit widen to `size_t` | GG003 | Caught *in effect* (counts exceeding the file footprint are flagged; a huge/negative count overruns the file) |
| V-05 | MEDIUM | C++ | `gguf_type` enum value cast from file without validation → `gguf_type_size()` returns 0 → divide-by-zero | **GG005** (+GG010) | **Caught** (unknown scalar/array value type flagged "not a GGUF value type (0-12)"; tensor type id checked 0–39) |
| V-06 | MEDIUM | C++ | `blck_size = 0` → `ne[0]/blck_size` divide-by-zero | GG010 | Caught *in effect* (a zero `blck_size` is reachable only via an out-of-range tensor type id, which GG010 flags) |

**Net:** five of six are caught or caught-in-effect by existing rules; **V-01 is a clean,
confirmed miss**, and it is the most severe flaw in the advisory.

## The confirmed false-negative (V-01 vs GG011)

GG011's alignment validation reads the key and applies exactly one test:

```python
alignment = r.u32()
# ...
if alignment == 0 or (alignment & (alignment - 1)) != 0:
    # Finding(rule="GG011", severity="MEDIUM",
    #         title="Invalid general.alignment",
    #         detail="... must be a nonzero power of two.")
    alignment = 32
```

Walk the advisory's trigger value `alignment = 0x80000000` (2³¹) through it:

- `alignment == 0` → **False** (it is nonzero).
- `alignment & (alignment - 1)` → `0x80000000 & 0x7FFFFFFF` → `0`, so `!= 0` → **False**.

The whole condition is **False**, so **no GG011 finding is emitted** and the header is
reported clean (GG000). Every large power of two the advisory calls out — `0x10000` (2¹⁶,
the stated 32-bit overflow boundary), `0x100000`, … up to `0x80000000` — is a nonzero
power of two and therefore sails through GG011. The `r.u32()` read caps the field at
`0xFFFFFFFF`, so the entire dangerous range 2¹⁶ … 2³¹ is representable and uncaught.

This mirrors the `BENIGN_TOP` submodule-shadow finding in the pickle scanner (see
`PICKLE_BENIGN_TOP_SUBMODULE_SHADOW_AUDIT.md`): a check that looks sufficient on its face
but whose predicate is satisfied by the exact malicious input.

## The fix (precise, mirrors existing GG011 structure)

Add an **upper-bound** check immediately after the power-of-two check, before the
`alignment = 32` reset, keyed to the advisory's 32-bit `GGML_PAD` overflow boundary:

```python
_ALIGNMENT_MAX = 1 << 16          # 65536; oss-sec/2026/q2/546 V-01 GGML_PAD 32-bit boundary

alignment = r.u32()
# ...
if alignment == 0 or (alignment & (alignment - 1)) != 0:
    # existing GG011 MEDIUM "Invalid general.alignment ... nonzero power of two"
    alignment = 32
elif alignment >= _ALIGNMENT_MAX:
    # NEW GG011 variant, MEDIUM:
    #   title="general.alignment is implausibly large"
    #   detail=f"general.alignment is {alignment}; values >= {_ALIGNMENT_MAX} can overflow "
    #          "GGML_PAD on 32-bit builds (oss-sec/2026/q2/546 V-01). Real GGUF files use 32."
    alignment = 32
```

Design notes, honestly stated:
- **Threshold.** Real GGUF files use the default alignment of 32; page-aligned variants
  stay well under 2¹⁶. The advisory names 2¹⁶ as the 32-bit overflow boundary, so 65536 is
  the principled cut that catches the whole dangerous range with essentially no false
  positives on legitimate files. If a future legitimate use of huge-page alignment emerges,
  make `_ALIGNMENT_MAX` configurable rather than raising it silently.
- **Severity.** Kept at MEDIUM to match the existing GG011 finding and because the overflow
  is reachable only on 32-bit builds; the detail string states that scope plainly. A
  deployment that only runs 64-bit inference can treat it as informational.
- **No new rule id.** It extends GG011 ("general.alignment hygiene"), consistent with how
  GG011 already carries both the "Invalid" and "Tensor offset not aligned" variants.

## Sealed PoC spec (header-only; nothing is loaded or executed)

Follow the existing `gguf_cve_corpus.py` pattern (hand-assembled, header-only GGUF files,
never passed to any loader):

1. **Control set (must stay clean):** valid headers with `general.alignment ∈ {32, 4096}`.
   Assert `gguf_scan` emits no GG011 finding for these, before and after the patch.
2. **V-01 set (reproduces the miss):** valid-except-alignment headers with
   `general.alignment ∈ {0x10000, 0x100000, 0x40000000, 0x80000000}`.
   - *Before the patch:* assert `gguf_scan` emits **zero** GG011 findings for all four
     (the current false-negative).
   - *After the patch:* assert `gguf_scan` emits a GG011 MEDIUM "implausibly large" finding
     for all four, and the control set still emits none.
3. **Regression guard:** assert the existing "Invalid general.alignment" finding still fires
   for `general.alignment = 0` and for a non-power-of-two like `48`.

Run as a `poc` compute job (no network on run steps): `python -m unittest -v` plus a small
driver that scans the crafted corpus and prints the finding counts. Ship together as
`gguf_scan` with a sibling `test_gguf_alignment_bound.py`, update `GGUF_CVE_MAP.md` with a
row for `general.alignment` upper bound → GG011 → oss-sec/2026/q2/546 V-01, and cut the
next scanner release.

## Honest limits

- This is a coverage gap in our own tool, **not** a new llama.cpp vulnerability: all six
  advisory flaws are already public, and no exploit payload is produced here.
- V-01's overflow is reachable on **32-bit** `GGML_PAD` arithmetic; 64-bit builds are not
  overflowed by a u32 alignment, though the oversized seek/pad is still anomalous and worth
  flagging before load.
- The "caught in effect" rows (V-02, V-04, V-06) are reasoned from each rule's predicate and
  the header-scanner threat model; they were not re-PoC'd here. Only V-01 is asserted as a
  concrete, reproduced false-negative, and even that assertion is a source-review conclusion
  pending the sealed PoC job above.
- The fix threshold is a defensible default, not a value blessed by the GGUF spec (the spec
  does not bound alignment); it is chosen to match the advisory's stated 32-bit boundary.

## Sources

- oss-security, "Multiple Vulnerabilities in llama.cpp GGUF Format Parsers", 2026-05-15:
  seclists.org/oss-sec/2026/q2/546
- `gguf_scan.py`, `GGUF_CVE_MAP.md`, `gguf_cve_map.json` in this repository
- Companion finding of the same shape: `PICKLE_BENIGN_TOP_SUBMODULE_SHADOW_AUDIT.md`
