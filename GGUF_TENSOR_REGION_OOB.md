# GGUF tensor data-region out-of-bounds: CVE family and detector coverage

A GGUF file carries no code-execution surface, but a malformed tensor-info table can
still drive an *unpatched loader* into reading memory outside the file. The root cause
is always the same shape: a tensor declares a `offset` (and an implied byte length from
its dims and type) that the loader trusts without checking it stays inside the file.
Under the default memory-mapped load path the loader returns a pointer past the mapping,
or the conversion/quantization path reads past the end of the tensor buffer — an
out-of-bounds read of adjacent process memory (CWE-125).

This note is a cross-project map of that CVE family to the static detectors in
`keras-model-scan`, with honest coverage limits. Every detector here is static: it reads
only the GGUF magic, header, metadata key/value table and tensor-info table, never the
tensor data, and never memory-maps, executes, imports, unpickles or deserializes
anything.

## The CVE family

| CVE | Project / sink | Root cause (documented) | CVSS |
|-----|----------------|-------------------------|------|
| CVE-2026-108955 (VulDB VDB-416774) | Tiiny-AI PowerInfer `gguf_init_from_file` (`ggml.c`) | Tensor data `offset` not validated against file size; on the default mmap path the loader hands back a pointer past end-of-file. Disclosed 2026-10-13. | 5.3 |
| CVE-2026-7482 "Bleeding Llama" (GHSA-x8qc-fggm-mpqg) | Ollama GGUF loader + quantizer (`fs/ggml/gguf.go`, `server/quantization.go` `WriteTo`/`ConvertToF32`) | Two gaps, each sufficient: (1) the loader did not check that `tensorOffset + tensor.Offset + tensor.Size()` stays within the file; (2) the quantization path did not verify the buffer returned for a tensor matched the size declared in the header. A crafted GGUF whose tensor offsets/sizes exceed the file makes `/api/create?quantize=F32` read past the real buffer into adjacent heap (env vars, API keys, other users' prompts). Fixed in Ollama 0.17.1 (PR #14406): verify each tensor's end offset against the actual file size, plus a length check in the quantizer. | 8.8–9.1 |

These are the same structural bug across different loaders — an out-of-file tensor data
region — so a single static pre-load check is a drop-in defence regardless of which
loader will consume the file.

## What the detectors catch

`gguf_data_region_scan` (shipped v0.40.0) is the module for this class. Its rules:

| Rule | Severity | Condition | Tensor types |
|------|----------|-----------|--------------|
| GDR001 | HIGH | Data region **starts** at or beyond EOF: `data_section_start + offset >= file_size`. | **All** types. |
| GDR002 | HIGH | Data region **ends** beyond EOF: `start + nbytes > file_size`. | **Block-size-1 types only** (F32, F16, BF16, F64, I8/I16/I32/I64). |
| GDR010 | MEDIUM | Structure truncated/implausible before the data region; bounds could not be validated. | n/a |

Mapping to the CVE family:

- **CVE-2026-108955** (offset past EOF) — caught by **GDR001**, for every tensor type.
- **CVE-2026-7482** gap (1), the loader's `offset + Size() > file` check — caught by
  **GDR001** (offset itself past EOF, all types) and by **GDR002** (end past EOF) for
  block-size-1 types. The documented Bleeding Llama path is `quantize=F32` →
  `ConvertToF32`, whose **source tensor is read as F16/F32** — exactly the block-size-1
  case GDR002 computes exactly. So a GGUF crafted to drive the practical, disclosed
  exploit path out of bounds is flagged **pre-load**, statically, before Ollama ever
  touches it.

## Honest limit: quantized/block-type end offsets

GDR002 is emitted **only** for block-size-1 types, where the exact byte length is
unambiguous (`n_elements * type_size`). For quantized/block types (Q4_0, Q8_0, the K-quant
family Q4_K/Q5_K/Q6_K, the IQ family, MXFP4, …) GDR002 is deliberately **not** emitted:
their exact byte length depends on per-type block constants, and a scanner that gets one
of those constants wrong would false-positive on legitimate models — Q4_K_M is the single
most common GGUF quantization in the wild, so a wrong constant there would be worse than
the gap it closes.

Consequence: a crafted GGUF whose out-of-bounds tensor uses a **quantized source type and
whose offset still starts inside the file** (so GDR001 does not fire) but whose declared
block count runs past EOF is **not** flagged by end-offset today. GDR001 still catches the
common case (an out-of-file *offset*, any type), and the disclosed Bleeding Llama path
(F32/F16 source) is fully covered by GDR002.

Closing the quantized-end-offset case fully requires the exact ggml `type_traits` table
(block size and byte size per type), validated against real quantized files so no
legitimate model is mis-flagged. That is future work for a run with a sandbox that can
load real GGUFs; it should not be shipped from hand-copied constants.

## Relationship to the GGUF integer-overflow cluster

This region-OOB class is **distinct** from the GGUF header integer-overflow cluster
(CVE-2024-21825, CVE-2024-23496, CVE-2024-23605, CVE-2025-53630, CVE-2026-27940,
CVE-2026-33298), which `gguf_scan` already covers via GG003/GG004/GG006/GG009/GG011
(count caps, dimension-element overflow, offset alignment). Those are overflow bugs in
*parsing the header/metadata*; the region-OOB class is about the *tensor data region*
geometry after the header parses cleanly. CVE-2026-108955 belongs to the region-OOB class
(`gguf_data_region_scan` GDR001), not to the overflow cluster, even where a combined CVE
list groups them together.

## Usage

```bash
python gguf_data_region_scan.py model.gguf
python gguf_data_region_scan.py models/ --json
python gguf_data_region_scan.py model.gguf --fail-on HIGH   # exit 1 on a finding
```

Pair it with `gguf_scan` (header/metadata integrity), `gguf_chat_template_scan`
(template injection) and the other format scanners for the rest of a GGUF's surface. A
static pre-load check reports a hostile file; it does not tell you whether the loader that
will consume it is patched.

## Provenance

Part of `keras-model-scan` by MV2, Munim, Inc. This document was written by AI agents
working in MV2's name. CVE facts are from NVD, GitHub Security Advisories (GHSA) and VulDB
as cited above; verify against those sources. Licensed under Apache-2.0.
