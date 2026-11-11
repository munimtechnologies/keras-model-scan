# Pre-registration: ExecuTorch programs on the Hugging Face Hub (job pte-census-v1)

Written 2026-11-11, before the job runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## Why

`executorch_pte_scan` (which `model-file-scan` uses for `.pte` files) checks ExecuTorch `.pte`
programs for sizes, offsets and indexes that point outside their region: the
classes behind the loader memory-safety bugs ExecuTorch fixed in 0.7.0
(CVE-2025-30402, -30404, -30405, -54949, -54950, -54951, -54952). Until now it
has been checked only on four files we wrote ourselves
([REALFILE_CHECK_TFL_PTE_2026-10.md](../REALFILE_CHECK_TFL_PTE_2026-10.md)),
which says plainly that this is "not a false-positive rate measured over a
corpus of published models". The census of 11 November 2026
([RESULTS_PT2_CENSUS_2026-11.md](../RESULTS_PT2_CENSUS_2026-11.md)) found that
851 of 862 open `executorch`-tagged models ship a `.pte`, so the Hub has a
real corpus. We did not find a published scan of that corpus by any scanner.

The question: on honest published `.pte` files, how often does the scanner
raise integrity findings (which would be false alarms), and how often does
its MEDIUM "backend delegate" note (PTE003) make the default
`--fail-on medium` gate fail?

## Method (research/pte-census/)

- **Sample.** Open (not gated, not private) models with the Hub tag
  `executorch`, sorted by downloads, up to 3,000 (public API, no login). Every
  `.pte` file in them, ordered by model downloads, then model id and file
  name, at most 3 files per model; the first 450 are probed.
- **Bytes.** One HTTP Range request reads each probed file's first 64 bytes and
  its length. The scanner reads only the `eh00` extended header (first 40
  bytes) and the FlatBuffer program (the first `program_size` bytes); for data
  segments it compares offsets and sizes with the file length and never reads
  their bytes. So for each `ET12` file the job fetches the first
  `program_size` bytes (the whole file when it has no extended header), if
  that is at most 25 MB, within 1.5 GB in total.
- **Scan.** In a sealed container with no network, each file is rebuilt as a
  sparse file: those bytes at offset 0, its true length, zeros after. It is
  scanned by `executorch_pte_scan` 0.1.0 from the released v0.59.0 tree,
  unchanged. Up to 40 files of at most 25 MB are also downloaded whole and
  scanned whole, to check that the sparse rebuild gives the same findings.
- Nothing is loaded or executed. The "default gate" is computed from the
  findings' severities (any MEDIUM or higher), as `model-file-scan` applies
  `--fail-on medium`.

## Rows (all predictions written now)

| Row | Prediction |
|---|---|
| G1 | gate: at least 100 `.pte` files from at least 30 models are scanned. If not, R1-R5 are untestable |
| E1 | every file also downloaded whole gets exactly the same findings whole and as a sparse rebuild (needs at least 10 such files, else untestable). If E1 fails, R1-R5 are untestable |
| R1 | at most 2% of scanned files get any integrity finding (PTE001, PTE002 or PTE004) |
| R2 | at most 5% of scanned files get PTE005 (not a well-formed program, truncated, or segments without a base offset) |
| R3 | at least 70% of scanned files get PTE003 (a backend delegate blob) |
| R4 | `XnnpackBackend` is the delegate named in the most files, strictly ahead of the next |
| R5 | at least 70% of scanned files fail the default `--fail-on medium` gate |
| R6 | at least 95% of probed files carry the `ET12` file identifier (needs 100 probed files) |

Recorded without prediction: how many open `executorch` models ship `.pte`,
`.ptd` and both; identifiers; how many files have an extended header; file
and program sizes; files per rule; delegate names by files; files with no
finding; the same counts on one file per model; every integrity or PTE005
finding with its model, file and evidence; why files were skipped.

## What we will do with the result (fixed now)

- **R1 or R2 fails:** each flagged file is read against ExecuTorch's own
  program schema and loader source (reading only). A scanner mistake gets its
  own pre-registered fix; a file that really is malformed is reported as
  measured, without guessing at intent.
- **R3 and R5 hold:** the default gate stops most honest `.pte` files because
  of PTE003 alone. Whether PTE003 should stay MEDIUM (like PKL040 for
  TorchScript) or move lower for some backends is decided in a separate
  pre-registration, with this census as its evidence. Nothing changes in this job.
- Every row is reported as graded, held or not.

## Limits

One day's Hub listing; the most downloaded models dominate; at most 3 files
per model, and files of one model are not independent (the per-model view is
recorded for that reason). Programs over 25 MB are skipped and counted. A
`.ptd` data file (ExecuTorch's separate weights or delegate data) is counted
but not scanned: the scanner does not read `.ptd`. A clean scan says the
structure is consistent, not that the program is safe; PTE003 says a backend's
native code parses a blob the scanner cannot read.
