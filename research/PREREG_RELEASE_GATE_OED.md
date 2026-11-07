<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Pre-registration: release gate for the ONNX external-data fix (job `gate-oed-v1`)

Written and published on 2026-11-07, **before** job `gate-oed-v1` runs.
Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Scripts: [research/release-gate/](release-gate/).

## Why a gate

Each fix in this repo is checked in a sealed job against the `main` of the
day. Two fixes were checked on the same tree (v0.52.1): `nemo_container_scan`
0.2.0 (job `nemo-big-v1`, 12 of 12 held) and `onnx_external_data_scan` /
`onnx_external_data_key_scan` 0.2.0 (job `oed-functions-v2`, 13 of 13 held).
Both pre-registrations say a fix that ships after another release is first
re-tested on the new `main`. The NeMo fix ships first (v0.53.0). The ONNX
fix waits for this gate.

The gate is generic. A fix that passed its own check is published as a
candidate in `research/candidates/<name>/` with a `manifest.json` naming the
live versions it was checked against, the versions it brings, and where each
file goes. The gate downloads `main`, lays the candidates over it, and runs
the whole suite. Several candidates can be gated together, so one gate run
can clear a batch.

## Steps

1. Setup (network): wait until `main` has `nemo_container_scan` 0.2.0 or
   later and `research/candidates/oed-functions/manifest.json`, then download
   `main`. numpy is installed, as in the earlier suite runs.
2. Run (no network): `apply_candidates.py` refuses to lay a candidate over a
   file whose version on `main` is not the one it was checked against (here
   both scanners 0.1.0), copies the files, and checks the versions after
   (both 0.2.0). The candidate test module becomes
   `test_onnx_external_data_functions.py`.
3. `run_tests.py` runs the whole suite. `gate_check.py` grades the rows.

## Predictions (graded rows)

| Row | Prediction |
|---|---|
| G0 | `main` carries `nemo_container_scan` >= 0.2.0 and the candidate manifest when the tree is downloaded |
| G1 | the candidate applies: both scanners on `main` are 0.1.0, all five files copy, both are 0.2.0 after |
| G2 | the whole suite on the overlaid tree: 0 failures, 0 errors |

Reported, not graded: tests run, predicted **1,354** (1,325 on v0.52.1, plus
13 in `test_nemo_container_scan_big.py`, plus 16 in
`test_onnx_external_data_functions.py`), and **3** skipped.

**Release rule:** if G0, G1 and G2 hold, and `main` has not changed in any
file the candidate touches since the gate downloaded it, the candidate files
are published to their places from the candidate folder and released
(both scanners 0.2.0). If any other release ships between the gate and that
publish, the gate is run again. Any failed row is published as it came out.

## Honest limits

The gate re-runs existing tests on a combined tree. It adds no new check of
the fix itself; that was job `oed-functions-v2`.
