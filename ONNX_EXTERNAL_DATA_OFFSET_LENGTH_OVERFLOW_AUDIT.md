# ONNX external-data `offset`/`length` recall: the overflow sub-case of CVE-2026-55832 that `onnx_external_data_scan.py` declines wholesale

**Author:** MV2, Munim, Inc. — work made with AI agents in MV2's name.
**Date:** 2026-10-27. **Method:** source review + arithmetic only (no execution).
**Status of the fix below:** *specified, not yet coded* — it edits the live scanner module
and its test, so it needs a sealed compute job (same posture as the OED006 symlink spec).

---

## 0. One-sentence finding

`onnx_external_data_scan.py` already parses every `external_data` key/value pair (including
`offset` and `length`) into its per-tensor `entries` list, but it lints **only** the
`location` string for path traversal (OED001–OED005) and discards `offset`/`length`
entirely — so the **offset/length denial-of-service angle of CVE-2026-55832** is declined in
full, even though its *integer-overflow* and *implausible-magnitude* sub-cases are statically
decidable from the `.onnx` file alone and need no access to the external data file.

This is a scanner-completeness / defense-in-depth refinement, **not** a new library
vulnerability. It targets unpatched and third-party (non-Python) ONNX loaders; the current
onnx Python reference is already hardened (see §5).

---

## 1. CVE-2026-55832 has two independent angles

CVE-2026-55832 (GHSA-h668-6x6g-f8r5, CWE-22, CVSS 6.1 `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L`)
is in `tract-onnx` (sonos/tract, Rust), in `get_external_resources` (`onnx/src/tensor.rs`)
and `MmapDataResolver` (`onnx/src/data_resolver.rs`), reached via `model_for_path`. Fixed in
tract 0.21.17 / 0.22.3 / 0.23.2. An untrusted ONNX model controls two things:

| Angle | Attacker field | Effect | Our status |
|---|---|---|---|
| **(A) Path traversal** | `external_data` → `location` | joins to the model dir without rejecting absolute / `..` paths → arbitrary **local file read** (contents land in model tensors / inference output) | **Covered** — OED001 (`..`), OED002 (absolute), OED003 (URL scheme), OED004 (NUL/control), OED005 (backslash) |
| **(B) Slice DoS** | `external_data` → `offset`, `length` | selects an **out-of-range mmap slice** → panic / out-of-range read → DoS | **Declined in full** by the scanner |

Angle (A) is fully mapped (see `ONNX_EXTERNAL_DATA_SCAN.md`). This audit is about angle (B).

## 2. Why angle (B) is currently declined

`ONNX_EXTERNAL_DATA_SCAN.md` states the offset/length DoS is *"not checked, since file size
is unknown without opening the file."* That is true for the **exact** bound
(`offset + length ≤ file_size`) — the scanner reads only the `.onnx` protobuf and never opens
the referenced data file. But it conflates two distinct sub-cases:

- **(B1) exact bound** — `offset + length ≤ file_size`. Genuinely needs the external file.
  Correctly out of scope for a pre-load file scanner. **Keep declining.**
- **(B2) integer overflow + implausible magnitude** — `offset`, `length`, or their sum is
  negative, malformed, outside a fixed-width integer range, or larger than any real file could
  ever be. **Decidable from the `.onnx` file alone**, because the values are decimal strings
  already present in the protobuf and already parsed by the scanner.

The scanner declines (B1) *and* (B2) together. (B2) is a real, catchable gap.

## 3. The values are already in hand (confirmed by source review)

In `_walk_tensor`, each `StringStringEntryProto` sub-field of an `external_data` entry is read
by protobuf field number (`_F_SSE_KEY = 1`, `_F_SSE_VALUE = 2`) and collected as
`entries.append((key, value))`. The lint loop then keeps only `key == "location"`. The
`offset` and `length` pairs are therefore **already decoded into `entries`** and simply
dropped. Adding (B2) is a lint over data the scanner already has — no new parsing, no new I/O.

Per the ONNX IR, `offset`/`length` are string-valued entries written as `str(int(x))` and
read back with `int()` (onnx `external_data_helper.py`: `self.offset = int(self.offset)` with
`if self.offset < 0`, `self.length = int(self.length)` with `if self.length < 0`, then
`data_file.seek(info.offset)` / `data_file.read(info.length)`). Python `int` is
arbitrary-precision, so the reference never overflows — but the **string in the file is
unbounded**, and a fixed-width (`u64`/`usize`) parser in a Rust/C++/Go loader does not share
that immunity.

## 4. Proposed rules (exact conditions)

For each `external_data` entry with `key ∈ {"offset", "length"}` and non-empty `value` string
`v`, and for the per-tensor pair `(offset, length)` when both are present:

- **OED007 — HIGH — CWE-190 (Integer Overflow) / CWE-20 (Improper Input Validation).**
  Fire if **any** of:
  - `v` is not a canonical non-negative base-10 integer — i.e. `v` fails
    `re.fullmatch(r"\d+", v)` (rejects empty, sign, whitespace, `0x`/hex, decimal point,
    thousands separators). The writer emits exactly `str(int(x))`, so any deviation is
    malformed input a signed loader may seek-backward on or an unsigned parser rejects.
  - the parsed value exceeds `INT64_MAX = (1 << 63) - 1`, for `offset` or `length`
    individually; **or**, for the tensor's `(offset, length)` pair, `offset + length`
    exceeds `UINT64_MAX = (1 << 64) - 1`. Either overflows or wraps a fixed-width accumulator
    in a non-arbitrary-precision loader (the tract class), defeating a naive
    `offset + length <= file_size` bound check.
  Message: `"external_data offset/length is malformed, negative, or exceeds 64-bit range
  (integer-overflow precondition for CVE-2026-55832 class slice DoS)"`.

- **OED008 — LOW / informational — CWE-400 (Uncontrolled Resource Consumption).**
  Fire if `offset` or `length` is a valid in-range integer but exceeds
  `PLAUSIBLE_MAX = (1 << 48)` bytes (256 TiB). No legitimate single external-data file
  approaches this; the value is a strong malformation / DoS signal that catches angle (B)
  **without** the file. Message: `"external_data offset/length is implausibly large
  (>2^48 bytes); cannot be bounds-checked pre-load but is a likely malformed/DoS value"`.

Both rules reuse the existing `MAX_FINDINGS` cap and emit through the same finding path as
OED001–OED005. `INT64_MAX`, `UINT64_MAX`, `PLAUSIBLE_MAX` are module constants (mirrors
`gguf_scan.py`'s `_INT64_MAX` and the `GGUF_INTEGER_FIELD_BOUNDS_CENSUS` approach).

## 5. Reachability (re-derived per the r193 lesson — do not ship a dead check)

The r193 lesson is: prove the gap is reachable against real constants before coding it.

- **tract-onnx (the CVE'd loader), Rust.** `MmapDataResolver` takes a slice of the mmap at
  `[offset, offset+length)`. An out-of-range slice panics → DoS (the CVE). A huge `length`
  (OED008) is exactly this class; `offset + length` overflowing `usize`/`u64` (OED007) either
  panics on a checked add or wraps to a small in-bounds value and silently returns the **wrong
  bytes** (data confusion). **Reachable**; OED007/OED008 are the statically-visible
  preconditions.
- **onnx Python reference (current `main`).** Now hardened: `_validate_external_data_file_bounds`
  rejects `offset < 0` / `length < 0` and checks `offset <= file_size`,
  `length <= file_size - offset` via `os.fstat`. So on the *current reference* this is
  defense-in-depth only. But the hardening is **runtime, file-dependent**, lives only in
  recent onnx, and does not help the many C++/Rust/Go/third-party loaders — precisely the
  population a pre-load scanner exists to protect. OED007/OED008 complement the upstream fix
  (they cover the overflow/implausibility sub-case a file-size check still misses on a wrap)
  rather than duplicating it.
- **Negative values.** Python `int("-1")` is accepted by the language but rejected by the
  reference's `< 0` guard; a Rust `u64::from_str("-1")` errors; a signed loader seeks
  backward. All anomalous → OED007 flags, correctly, across loaders.

## 6. Sealed PoC spec (poc job; run steps have no network)

Build three minimal single-tensor ONNX protobufs by hand (no `onnx` dependency needed to
*emit* the bytes; the scanner also parses the wire format itself):

1. `offset_overflow.onnx` — one `TensorProto` with `data_location = EXTERNAL`, `external_data`
   = `{location:"w.bin", offset:"0", length:"18446744073709551615"}` (`2^64-1`). Expect
   **OED007** (exceeds `INT64_MAX`; pair sum overflows `UINT64_MAX`).
2. `offset_implausible.onnx` — `{location:"w.bin", offset:"0", length:"281474976710657"}`
   (`2^48 + 1`). Expect **OED008**, and **no** OED007 (in int64 range).
3. `offset_malformed.onnx` — `{location:"w.bin", offset:"-1", length:"0x10"}`. Expect two
   **OED007** hits (negative; non-decimal).
4. Negative control `clean.onnx` — `{location:"w.bin", offset:"0", length:"1024"}`. Expect
   **no** OED007/OED008 finding (regression guard against false positives on legitimate data).

Assert each expected rule id fires on 1–3 and that 4 is clean, that OED001–OED005 are
unaffected, and that the full existing test suite stays green. Pure-stdlib, poc (no network),
well under 1 GB.

## 7. Honest limits

- **Not a live bug on patched targets.** tract ≥ 0.21.17 and current onnx reject this at
  runtime; on them a finding is defense-in-depth. The value is for unpatched / older / third-
  party loaders and for pre-distribution hygiene.
- **(B1) stays out of scope.** Exact `offset + length ≤ file_size` needs the external file;
  the scanner never opens it. OED007/OED008 deliberately cover only the file-independent
  sub-case.
- **Completeness, not exploitation.** Like the rest of this toolkit, the rule flags a
  suspicious shape, not a confirmed exploit.
- **`PLAUSIBLE_MAX = 2^48` is a heuristic**, chosen two orders of magnitude above the largest
  real single-file tensor stores to keep false positives at zero; it is informational (LOW).

## 8. Prior art — why this is new

- The repo's own `ONNX_EXTERNAL_DATA_SCAN.md` explicitly declines **all** offset/length
  checking; no prior rule distinguishes the file-independent overflow sub-case (B2) from the
  file-dependent bound (B1).
- Public write-ups of CVE-2026-55832 describe the tract bug and its path-traversal angle; none
  specify a **pre-load, file-independent** static check for its offset/length DoS angle.
- `onnx.checker` validates that external files *exist* at the declared size at save/check time
  (needs the files); it does not lint the `.onnx` offset/length strings for integer-overflow
  magnitude in isolation.
- The GGUF side of this toolkit has integer-field-bounds work (GG009 element-count overflow,
  `GGUF_INTEGER_FIELD_BOUNDS_CENSUS`), but there is no equivalent for ONNX external-data
  offset/length here or, to our knowledge, in any other pre-load ONNX scanner.

## 9. Next step

Ship OED007 + OED008 as a sealed compute job (scanner edit + test + an OED row in
`model_file_cve_map.json` for CVE-2026-55832 angle B), then cut the next `keras-model-scan`
release. Queued behind the four jobs already waiting on Blade memory; not re-filed here.

---

*Code in this repository is Apache-2.0; this document's text is CC BY 4.0.
Made with AI agents working in MV2's name; MV2, Munim, Inc.*
