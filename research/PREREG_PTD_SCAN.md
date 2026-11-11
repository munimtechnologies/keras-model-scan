# Pre-registration: ExecuTorch `.ptd` files get their own scanner (job ptd-scan-v1)

Filed 11 November 2026, before the job runs. Made with AI agents working in
the name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## The gap

ExecuTorch can keep a program's weights outside the `.pte` program, in a
`.ptd` file (`ExecutorchBackendConfig(external_constants=True)`, LoRA
adapters, backend named data). Up to model-file-scan 0.14.0 (release
v0.60.0):

- a folder scan skips `.ptd` files without a word (the extension is not in
  the walk list);
- a `.ptd` named on the command line goes to the pickle scanner, which has
  nothing to say about a FlatBuffer.

So the weights half of an ExecuTorch export is never checked.

## What a `.ptd` is (read from ExecuTorch's source, not from any exploit)

- `extension/flat_tensor/serialize/flat_tensor.fbs`: a FlatBuffer with file
  identifier `FT01`; root table `FlatTensor {version, segments:
  [DataSegment {offset, size}], named_data: [NamedData {key, segment_index,
  tensor_layout {scalar_type, sizes, dim_order}}]}`.
- `extension/flat_tensor/serialize/serialize.py`: a 40-byte `FH01` header
  (length, flatbuffer_offset, flatbuffer_size, segment_base_offset,
  segment_data_size) is inserted at offset 8 and padded to 48 bytes; segments
  follow, aligned to 128 bytes by default. The writer emits schema version 0.
- `extension/flat_tensor/flat_tensor_data_map.cpp` (the runtime loader):
  checks the header, that the file is as long as the header says, the
  identifier, the root offset, the schema version, that `segments` and
  `named_data` exist, each `segment_index`, and each segment against
  `segment_data_size`. Its own comment says it does not run full FlatBuffer
  verification. `create_tensor_layout` reads `dim_order` with the length of
  `sizes`, and reads both vectors without a null check.

## The change under test

`executorch_ptd_scan` 0.1.0 (new, standard library only) parses the whole
FlatBuffer with bounds checks, applies the loader's checks and adds the
ones a consumer relies on. Rules:

| rule | severity | CWE | when |
|---|---|---|---|
| PTD001 | high | CWE-190 | a negative dimension, a tensor of 2**63 bytes or more, or offset arithmetic past 64 bits |
| PTD002 | high | CWE-125 | a segment past `segment_data_size`, segment data that begins inside the FlatBuffer, or a tensor layout that needs more bytes than its segment holds |
| PTD003 | medium | CWE-129 | a `segment_index` past the segment table, an unknown `scalar_type`, a layout without `sizes` or `dim_order`, a `dim_order` whose length differs from `sizes` or that has an entry past the rank, or an entry without a key |
| PTD004 | medium | CWE-693 | not a file the loader accepts: no `FT01`, no `FH01` header or a short one, shorter than its header says, root offset outside the FlatBuffer, schema version above 0, no `segments` or `named_data`, a malformed FlatBuffer, or findings capped |
| PTD005 | low | CWE-694 | two entries with the same key (the loader returns the first) |

model-file-scan 0.15.0 routes `.ptd` to it, so folder scans now include
`.ptd` files. 38 new unit tests: 32 for the scanner and 6 for routing. The
test files are honest-shaped FlatBuffers built field by field, plus
single-field integrity changes. Nothing is ever loaded or executed.

## The job (sealed container, CPU only)

Setup (network): download v0.60.0 twice (`tree` is patched, `base` is not);
install ExecuTorch with CPU-only torch; list every `executorch`-tagged model
on the Hugging Face Hub and, for up to 40 `.ptd` files (one per model first,
most downloaded first), fetch only the header and the FlatBuffer with HTTP
Range requests. Each local copy is extended to the file's true length with
zeros, and the weights are never downloaded. The scanner reads only the
header and the FlatBuffer, so it sees what it would see in the full file.

Run (no network): ExecuTorch writes honest `.ptd` files: S1 (its serializer,
seven entries over six dtypes plus a raw blob), S2 (empty payload), and E1/E2/E3
(torch.export -> to_executorch with external constants: float32, float16,
and the XNNPACK partitioner). Ground truth is ExecuTorch's own
`FlatTensorSerializer.deserialize` and `_deserialize_to_flat_tensor`. Then:
patch `tree`, run both full suites, grade.

## Rows (each is reported as held, failed or untestable)

- **G1 (gate):** at least 3 `.ptd` files written by ExecuTorch in the job
  are read back by both ExecuTorch deserializers. If not, H1, H2, H4 and H5
  are untestable.
- **H1 (no false positives):** `executorch_ptd_scan` reports **zero
  findings** on every G1 file and on every Hub file that ExecuTorch's
  deserializer reads.
- **H2 (reads what ExecuTorch reads):** on every file in H1, the scanner's
  parse equals ExecuTorch's: the same version, the same (offset, size)
  segment table, and the same named entries in order (key, segment_index,
  scalar_type, sizes, dim_order). On G1 files, the bytes of each segment
  also hash the same as the deserializer's buffers.
- **H3 (the files work):** for every export fixture (E1 to E3) that
  ExecuTorch's runtime loads with its `.ptd` and runs, the output matches
  eager PyTorch (atol 1e-5, or 1e-3 for float16). Untestable if no runtime
  entry point runs.
- **H4 (routing):** patched `route("model.ptd") == "executorch_ptd"`, a
  folder walk of the fixtures includes every G1 `.ptd`, and `scan_path`
  returns nothing on each. What v0.60.0 does with the same files is
  recorded: we expect the walk to skip them and an explicit path to go to
  the pickle scanner.
- **H5 (integrity on real files):** on each G1 file, four single-field
  changes each give exactly the expected rule set: drop the last byte ->
  {PTD004}; header magic `FH00` -> {PTD004}; `segment_data_size` minus 1 ->
  {PTD002} (only on files whose last segment ends exactly at
  `segment_data_size`; others are skipped and counted); root offset 2 ->
  {PTD004}.
- **S1 (no regressions):** the patch applies (every edit matches once), the
  base suite passes, the patched suite passes, and it runs at least 38 more
  tests than the base.

Measured and reported, not graded: how many open `executorch` models ship
`.pte`, `.ptd`, or both; how many `.ptd` files were fetched; and any Hub file
that ExecuTorch's own deserializer cannot read.

## Release rule

Release v0.61.0 (model-file-scan 0.15.0, executorch_ptd_scan 0.1.0) only if
G1 holds and S1, H1, H2, H4 and H5 all held, and H3 did not fail. Every
row is published whatever the outcome. If H1 or H2 fails, each flagged file
is read against `flat_tensor.fbs` and the loader. A scanner bug gets its own
pre-registered fix, and a real problem in a published file is reported
privately to its owner, never in public first.

## Honest limits

- Hub files are checked from their header and FlatBuffer only. Weight
  contents are never read, and this scanner does not judge them.
- The ExecuTorch version is whatever `pip install executorch` gives on the
  day; the version is recorded.
- The writer fixtures are small models made for this test, so the Hub
  sample is the only measure of real published files.
