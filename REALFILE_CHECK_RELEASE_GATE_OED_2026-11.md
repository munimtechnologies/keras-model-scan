<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Release gate graded: the ONNX external-data fix ships (job `gate-oed-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0.
Graded 7 November 2026 (UTC). Pre-registration:
[research/PREREG_RELEASE_GATE_OED.md](research/PREREG_RELEASE_GATE_OED.md),
committed before the job ran (2026-11-07 10:39 to 10:42 UTC, sealed
`python:3.12` container, no network in the run steps). Raw results:
[research/release-gate/results-oed/](research/release-gate/results-oed/).

## Result

**3 of 3 graded rows held. The release rule holds.**

| Row | Prediction | Result |
|---|---|---|
| G0 | `main` has `nemo_container_scan` >= 0.2.0 and the candidate manifest | held (0.2.0; manifest present; no wait needed) |
| G1 | the candidate applies: both scanners 0.1.0 on `main`, five files copied, both 0.2.0 after | held |
| G2 | whole suite on the overlaid tree: 0 failures, 0 errors | held: **1,354 run, 0 failures, 0 errors, 3 skipped** |

Tests run and skipped came out exactly as predicted (1,354 and 3).

The gate downloaded `main` after v0.53.0 and the candidate commit (tarball
826,561 bytes). No commit has touched `main` since, so the candidate files
are published to their places unchanged (same bytes as job
`oed-functions-v2` wrote; SHA-256 in `apply_report.json`) and released as
**v0.53.1**: `onnx_external_data_scan` 0.2.0 and
`onnx_external_data_key_scan` 0.2.0. What the fix does and its own
pre-registered check (13 of 13 held) are in
[REALFILE_CHECK_OED_FUNCTIONS_2026-11.md](REALFILE_CHECK_OED_FUNCTIONS_2026-11.md).

The copies in `research/candidates/oed-functions/` stay as the record of
what the gate tested (the publishing lane cannot delete files). Their test
module is named `candidate_test_...` so no runner collects it.

## Limits

The gate re-runs existing tests on a combined tree. It adds no new check of
the fix itself. `model-file-scan` stays 0.12.0 (module-only release).
