<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Amendment 1 to PREREG_OED_FUNCTIONS.md (job `oed-functions-v2`)

Written and published on 2026-11-06, after job `oed-functions-v1` finished
and before job `oed-functions-v2` runs. Made with AI agents working in the
name of MV2 of Munim, Inc. Text CC BY 4.0, code Apache-2.0.

## What happened in v1

Job `oed-functions-v1` ran on 2026-11-06 (15:27-15:30 UTC). Its raw result is
in [oed-functions/results/v1_oed_summary.json](oed-functions/results/v1_oed_summary.json).

- **P1, S1, W1, L1 held.** The patch applied cleanly to both scanners and both
  docs. The whole suite passed (1,335 tests, 0 failures, 0 errors, 3 skipped).
  onnx 1.23.2 wrote the function's Constant tensor as external data at
  `weights.bin` (offset 4096, length 4096), and `onnx.load` filled it back
  (4,096 bytes, equal to the values written).
- **H1, E1-E4, K1, C1 and T1 were never measured.** Every one of the 28
  scans, with the old and the new scanner alike, ended with
  `AttributeError: 'NoneType' object has no attribute '__dict__'` before any
  file was read. That is a bug in our harness, not in either scanner: 
  `scan_one.py` loaded the scanner with `importlib.util.module_from_spec`
  but did not put it in `sys.modules`, and the scanners' `@dataclass Finding`
  looks its module up there while the module loads. The suite run (S1) imports
  the scanners normally, which is why it passed. No scanner output was seen.
- **Hb measured the wrong population.** The census asked the Hub for
  `models?library=onnx`. The Hub API ignores `library=` (checked 2026-11-06:
  `library=onnx` and `library=nemo` both return the overall most-downloaded
  list, while `filter=onnx` returns onnx-tagged repos). So v1 counted `.onnx`
  files in the 100 most-downloaded repos of any kind: 93 files in 100 repos,
  60 of at most 256 MiB, 33 between 256 MiB and 2 GiB (31 unique blobs, 14
  repos), none above 2 GiB. That is a real count, but not the one the
  pre-registration named.

## What changes in v2

1. `scan_one.py` puts the module in `sys.modules` before running it.
2. `fetch_hub_sizes.py` lists repos with `filter=onnx`, the population the
   pre-registration describes.
3. `oed_check.py` also reports which scans, if any, errored.

Nothing else changes: the same patch, the same files and writer, the same
rows, the same pass criteria and the same release rule. We saw v1's Hb count
(33 files) before writing this, so the v2 Hb row is graded as written but
should be read with that in mind. No scanner output on any file has been
seen, so the scan rows are still fresh predictions.

## Lesson kept

A harness that loads a module from a file path must register it in
`sys.modules` first. Our other check scripts (`u3u6_check.py`,
`walk_check.py`) already do this; `scan_one.py` was new and did not.
