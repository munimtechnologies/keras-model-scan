# Real-file check: u3 and u6 weights in openvino_ir_scan, re-run (graded, released in v0.52.1)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 6 November 2026 (UTC). Pre-registration:
[research/PREREG_OVI_U3U6_V2.md](research/PREREG_OVI_U3U6_V2.md), committed
before job `ovi-u3u6-v2` ran (2026-11-06 18:55 to 18:59 UTC). Raw results:
[research/ovi-u3u6-v2/results/u3u6_summary.json](research/ovi-u3u6-v2/results/u3u6_summary.json).
First run: [REALFILE_CHECK_OVI_U3U6_2026-11.md](REALFILE_CHECK_OVI_U3U6_2026-11.md).

## Result

**13 of 13 graded predictions held. None were skipped.** The suite ran on
the tree that already carried v0.52.0 (`fetch.combined` true: model-file-scan
0.12.0 on `main`). So, as the release rule says, `openvino_ir_scan` 0.1.2
ships in **v0.52.1** with the job's patched files.

Up to 0.1.1, `openvino_ir_scan` had no bit width for OpenVINO's u3 and u6
element types, so it skipped both size checks on any Const of those types.
0.1.2 catches a declared size that is too small (OVI005) and a bit size that
overflows (OVI004) for u3 and u6, as it already did for u1, u2, u4, i4, nf4
and u8. It raises nothing on any of the 32 honest files OpenVINO 2026.4.1
wrote.

## Versions

`openvino_ir_scan` 0.1.1 (live `main`, release v0.52.0) and the patched
0.1.2. OpenVINO 2026.4.1, numpy 2.5.4. Container `python:3.12`; the run
steps had no network.

## Rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once to the scanner, the old test's version pin and the doc; second pass no-op; nothing lost | held |
| V1 | original 0.1.1, patched 0.1.2 | held |
| L1 | u3/u6 Consts from `save_model`: declared size = 3 x ceil(n / 8) (u3), 3 x ceil(n / 4) (u6) | held for all 8 |
| L2 | declared size never below ceil(n x bits / 8) | held |
| H1 | 0.1.1 on all 32 honest files: no finding | held |
| H2 | 0.1.2 on all 32 honest files: no finding | held |
| Ta | 0.1.1 on "short" copies: u3/u6 no finding (the gap); every other type exactly OVI005 | held |
| Tb | 0.1.2 on "short" copies: every type exactly OVI005 | held |
| Oa | 0.1.1 on "huge" copies: u3/u6 no finding (the gap); every other type exactly OVI004 | held |
| Ob | 0.1.2 on "huge" copies: every type exactly OVI004 | held |
| R0 | OpenVINO `read_model` loads every honest u3/u6 file | held (8 of 8) |
| S1 | full unit-test suite on the patched tree | held: 1,325 run, 0 failures, 0 errors, 3 skipped |
| S2 | the new test module alone exits 0, at least 6 tests | held: 6 tests |

## What changed since the first run

Only the test side. `test_openvino_ir_scan.test_version` pinned
`__version__ == "0.1.1"` exactly, which made S1 fail in the first run. It
now checks for a minimum version (`>= 0.1.2`). The fix itself is the one
the first run checked.

## Limits

One OpenVINO release, which writes only the 3-byte "split" layout. The tight
layout (OpenVINO PR #37430, milestone 2026.5) is covered by hand-written unit
tests only. The models contain only Consts, so this check covers declared
sizes, not inference. It covers our own scanner, not OpenVINO. The runtime
was only asked to read honest files.
