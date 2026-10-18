# gguf_data_region_scan

A static pre-load check that flags **GGUF tensors whose declared data region falls
outside the file** — the out-of-bounds read class of CVE-2026-108955. It reads only
the GGUF magic, header, metadata key/value table and tensor-info table. It never
reads the tensor data, never memory-maps, never executes, imports, unpickles or
deserializes anything, and bounds-checks every structural read so a hostile file is
reported rather than crashed on.

## The gap this closes

GGUF carries no code-execution surface, but a malformed GGUF can still corrupt the
*loader*. Every tensor info declares an `offset` into the file's data section. On the
default memory-mapped load path, a loader computes
`mmap_base + data_section_start + offset` and returns that pointer **without checking
it stays inside the file**. A crafted GGUF whose tensor offset points past
end-of-file makes the loader hand back a pointer outside the mapping: an
out-of-bounds read of process memory the moment the tensor is touched.

This is **CVE-2026-108955** (Tiiny-AI PowerInfer `gguf_init_from_file` in `ggml.c`;
VulDB VDB-416774; CWE-125 out-of-bounds read; disclosed 2026-10-13). The reported
proof of concept sets a GGUF v3 tensor's offset field beyond the file size while
leaving every other field benign; under default flags the loader succeeds silently,
and the tensor's data pointer lands out of bounds. With `--no-mmap` the same file
errors instead. The documented mitigation is exactly *"add offset validation and
boundary checks when loading GGUF models."* The same root cause mirrors the upstream
llama.cpp GGUF tensor-offset issue, so this is a **class across GGUF loaders**, not
one project's bug.

keras-model-scan's GGUF integrity validator (`gguf_scan.py`) already caps header and
metadata counts (GG003/GG006), tensor-dimension element overflow (GG009) and tensor
offset **alignment** (GG011) — but it does not check that a tensor's data region
lies *within the file*. Its own CVE map records this as a gap. `gguf_data_region_scan`
fills precisely that gap, as a standalone module (the repo keeps one concern per
module, e.g. `safetensors_scan` + `safetensors_index_scan`).

## Rules

| Rule   | Severity | Meaning |
|--------|----------|---------|
| GDR000 | INFO     | No GGUF tensor data-region issues found (or the input is not a GGUF file). |
| GDR001 | HIGH     | Tensor data region **starts** at or beyond end-of-file: `data_section_start + offset >= file_size`. The CVE-2026-108955 out-of-bounds class (CWE-125). Applies to every tensor type. |
| GDR002 | HIGH     | Tensor data region **ends** beyond end-of-file: `start + nbytes > file_size`, for a plainly-sized (block-size-1) tensor type only. |
| GDR010 | MEDIUM   | GGUF structure truncated or implausible before the data region (bad counts, oversized dim count, array it cannot parse, or EOF mid-table); bounds could not be validated. |

### Why GDR002 covers only block-size-1 types

GDR002 computes an exact tensor size and is emitted **only** for types whose byte
size is unambiguous and block-size 1 — F32, F16, I8, I16, I32, I64, F64, BF16.
Quantized/block types (Q4_K, Q8_0, the IQ family, …) are deliberately skipped by
GDR002 so a legitimate quantized tensor is never flagged on a mis-stated block size.
GDR001 still covers those types: an out-of-file *offset* is caught regardless of
tensor type.

## Usage

```bash
python gguf_data_region_scan.py model.gguf
python gguf_data_region_scan.py models/ --json
python gguf_data_region_scan.py model.gguf --fail-on HIGH   # exit 1 on a finding
```

Exit code is 1 when a finding at or above `--fail-on` is present, else 0.

## Honest limits

- This is a **pre-load integrity check**, not a guarantee of safety. It validates the
  tensor data-region geometry only. Pair it with `gguf_scan` (counts, dims, types,
  alignment), `gguf_chat_template_scan` (template injection) and the format-specific
  scanners for the rest of a GGUF's attack surface.
- It does not detect a loader that *is* patched; it tells you whether a given file
  would drive an unpatched, mmap-default loader out of bounds.
- A GGUF whose header cannot be parsed yields GDR010 (not a pass): the file is flagged
  as unvalidated, not cleared.
- Data-region overlap between tensors and partial-region reads inside the file are out
  of scope; only out-of-file regions are flagged.

## Provenance

Part of `keras-model-scan` by MV2, Munim, Inc. This module and its tests were written
by AI agents working in MV2's name. Licensed under Apache-2.0.
