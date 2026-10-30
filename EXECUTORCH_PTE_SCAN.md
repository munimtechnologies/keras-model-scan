# executorch_pte_scan.py — ExecuTorch .pte program files

`executorch_pte_scan.py` is a static, dependency-free scanner for ExecuTorch
`.pte` files. It is part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan) toolkit.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

## Why structure is the risk in a .pte file

A `.pte` file holds no pickle and no Python. It is a FlatBuffer (identifier
`ET12`, `schema/program.fbs`) of execution plans, tensors, operator calls and
backend delegates. When the program has data segments, an `eh00` extended
header at offset 8 gives the program size, where the segment data starts
(`segment_base_offset`) and how long it is (`segment_data_size`). Constant
weights, initial values of mutable tensors, named data and backend delegate
blobs live in those segments.

The runtime trusts what it reads: tensor sizes, memory-planned offsets,
segment offsets and the indexes between tables. In 2025 Meta published a
series of ExecuTorch advisories about loading malformed programs: heap
buffer overflows, integer overflows that lead to overlapping or too-small
allocations, and out-of-bounds reads (CVE-2025-30402, CVE-2025-30404,
CVE-2025-30405, CVE-2025-54949, CVE-2025-54950, CVE-2025-54951,
CVE-2025-54952; fixed in 0.7.0). The advisories don't say which fields each
bug used, so this module does not claim to detect any one of them. It checks
the whole class: every size and reference in the file against the region it
points into.

ModelAudit's ExecuTorch scanner (promptfoo/modelaudit, `executorch_scanner.py`,
read 2026-10-30) treats a `.pte` mostly as a zip and pickle container (the
PyTorch Mobile `.ptl` layout). For a binary program it runs a signature check
and a raw byte scan, and does not walk the FlatBuffer. Viewers do parse it:
battlecook/omni-viewer-core (TypeScript) reads the FlatBuffer and warns about
segments it can't locate or that run past the end of the file, and Arm's
Model Explorer extension displays programs. This module goes further for CI:
it checks each tensor's computed size against the buffer or segment it lands
in, and every index between tables, and fails the job on a high finding.

## What it does

- Parses the FlatBuffer itself (no `executorch`, `torch` or `flatbuffers`
  import) with bounds-checked reads limited to `program_size`, and
  memory-maps files.
- Reads the `eh00` header (`length >= 24`; `segment_data_size` when
  `length >= 32`, as `exir/_serialize/_program.py` writes it) and checks the
  declared extent against the file size.
- Recomputes every tensor's byte size the way `calculate_nbytes` does:
  dimension by dimension, element size from `ScalarType`.
- Checks each tensor's data the way the runtime finds it:
  - planned tensors (`allocation_info`): `memory_id - 1` indexes the planned
    buffers, so `memory_id` must be at least 1 and below
    `len(non_const_buffer_sizes)`, and `offset + nbytes` must fit in
    `non_const_buffer_sizes[memory_id]`; the 64-bit offset is
    `memory_offset_low | memory_offset_high << 32`;
  - constants (`data_buffer_idx > 0`, no allocation) through
    `constant_segment` offsets, or the deprecated `constant_buffer`;
  - initial values of mutable tensors through `mutable_data_segments[0]`.
- Checks every segment against the segment data, every `SubsegmentOffsets`
  and `named_data` segment index, every delegate's processed-data reference
  (`INLINE` to `backend_delegate_data`, `SEGMENT` to `segments`), and every
  instruction's operator, delegate, value and jump index.
- Tensors with `extra_tensor_info.location == EXTERNAL` take their data from
  a separate file, so their data references are not checked.

## Rules

| rule | severity | class | condition |
|------|----------|-------|-----------|
| **PTE001** | high | CWE-190 | Sizes that are negative or overflow: a tensor dimension below 0, a tensor of 2**63 bytes or more, a negative `non_const_buffer_sizes` entry, or segment base + offset + size past 64 bits. |
| **PTE002** | high | CWE-125 | Data references outside their region: a segment past the segment data, `segment_base_offset` inside the program, a constant or mutable tensor past its segment, a sub-segment offset past its segment, a legacy constant past its buffer, or a planned tensor past its memory-planned buffer. |
| **PTE003** | medium | CWE-829 | Backend delegate: the named backend's native code parses an ahead-of-time compiled blob at load, and this scanner can't read inside it. Listed once per backend id with blob size, compile spec count and a total. |
| **PTE004** | medium | CWE-129 | Out-of-range indexes: operator, delegate, value, tensor-list, jump destination, segment, `memory_id`, `data_buffer_idx`, delegate data index, an unknown `ScalarType` or instruction type. |
| **PTE005** | medium | CWE-693 | Not a well-formed `ET12` program, a file shorter than its extended header says, data segments with no segment base offset, or more than 1000 findings. |

PTE001, PTE002 and PTE004 each report once, with a count and the first three
examples. `cve` is empty for every rule: each rule covers a class of
problems, not one advisory.

## Usage

```bash
python executorch_pte_scan.py model.pte
```

Exit `1` on any high finding, `0` otherwise, `2` on usage error or unreadable
input. `scan_bytes(data, name=...)` and `scan_file(path)` return a list of
finding dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Honest limits

- Static review only. A finding means the file is inconsistent with itself.
  Current runtimes reject many of these files at load. Runtimes before 0.7.0
  had the memory-safety bugs above. Either way, a genuine export never
  contains them.
- PTE003 lists delegates; it does not judge them. XNNPACK, Core ML, Vulkan,
  QNN and other backends are normal. The blob is opaque, so a bug in a
  backend's own blob parser is out of reach.
- Memory planning reuses memory for tensors whose lifetimes don't overlap, so
  overlapping planned tensors are normal and not flagged. Each planned
  tensor is checked only against the bounds of its own buffer.
- Jump destinations are allowed up to the number of instructions (inclusive).
  Dynamic-shape tensors are sized by their upper-bound `sizes`, as the
  runtime does.
- The layout comes from reading ExecuTorch's schema and runtime source
  (`schema/program.fbs`, `scalar_type.fbs`, `exir/_serialize/_program.py`,
  `runtime/executor/program.cpp`, `method_meta.cpp`,
  `tensor_parser_exec_aten.cpp`, main, 2026-10-30). Tests use programs built
  by hand from that schema. A check against files written by `exir` itself is
  pre-registered and queued.
