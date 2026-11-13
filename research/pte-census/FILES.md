# pte_census_files.json: per-file data of job pte-census-v1

This adds the per-file data behind
[RESULTS_PTE_CENSUS_2026-11.md](../../RESULTS_PTE_CENSUS_2026-11.md) and
[pte_census_summary.json](pte_census_summary.json), so every count in that
write-up can be checked file by file, and so later checks can draw files
that the census did not use.

## What it is
One entry for each of the 450 published ExecuTorch program files (`.pte`)
that the census scanned. They come from 171 open (not gated, not private)
Hugging Face models tagged `executorch`, taken most-downloaded first with at
most 3 files per model. Each entry has:

- `n`, `model`, `rfilename`, `rank`, `downloads`, `library`, `pte_in_model`:
  which file this is and where it ranked in the Hub listing (November 2026)
- `size`, `plan`, `identifier`, `has_header`, `program_size`,
  `segment_data_size`: file size and the header fields read from its first
  64 bytes, plus which bytes were fetched
- `findings`: what `executorch_pte_scan` 0.1.0 (model-file-scan v0.60.0)
  reported for the file, exactly as returned

## How to read the findings
These are honest files published by their authors, and **a finding here is
not a claim that any model is unsafe**.

- **PTE003** (433 files) means the program hands part of the model to a
  hardware backend (XNNPACK, Core ML, Vulkan and others) as a compiled blob.
  The scanner can't read inside that blob, so it lists it instead. It is a
  visibility notice, not a defect in the file.
- **PTE004** (15 files) was a false positive in the scanner: these files use
  dtype 9 (ComplexFloat), which the ExecuTorch runtime accepts. A fix is
  pre-registered in
  [research/PREREG_PTE_DTYPE_FIX.md](../PREREG_PTE_DTYPE_FIX.md) and ships
  only if every pre-registered row holds.
- **PTE005** (8 files) is reported as measured.

The census also showed that 438 of the 450 files fail model-file-scan's
default `--fail-on medium` gate, almost all because of PTE003 alone. That is
a problem with the gate, and it is being worked on with a separate,
pre-registered check.

## Method and limits
Files were read as bytes only; nothing was loaded or executed. For files
with an extended header, only the program bytes were fetched, and each file
was rebuilt as a sparse file of its true length. 40 of 40 files that were
also downloaded whole scanned the same (row E1). The sample is limited to
the most-downloaded models as listed on the day of the run, and download
counts and file lists on the Hub change over time.

Made with AI agents working in the name of MV2 of Munim, Inc.
(mv2@munimtech.com). The data is CC BY 4.0, and the repository code is
Apache-2.0.
