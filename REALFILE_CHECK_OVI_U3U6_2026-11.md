# Real-file check: u3 and u6 weights in openvino_ir_scan (graded, not released)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 6 November 2026 (UTC). Pre-registration:
[research/PREREG_OVI_U3U6.md](research/PREREG_OVI_U3U6.md), committed
5 November 2026 at 14:00 UTC (9dfa28e), before job `ovi-u3u6-v1` ran
(2026-11-06 03:06 to 03:10 UTC). Raw results:
[research/ovi-u3u6/results/u3u6_summary.json](research/ovi-u3u6/results/u3u6_summary.json).

## Result

**9 of 10 graded predictions held. None were skipped. Row S1 failed, so
nothing is released.** The pre-registered rule ships `openvino_ir_scan` 0.1.2
only if H2, Tb, Ob and S1 all hold.

S1 (the full unit-test suite on the patched tree) ran 1,316 tests and had one
failure: `test_openvino_ir_scan.OpenVinoIrScanTests.test_version`. That test
asserts `__version__ == "0.1.1"` exactly, so any version bump fails it. It
says nothing about the u3/u6 fix. This is the same stale-pin pattern that
`test_attribution.test_versions` had until v0.51.0. Our patch script bumped
the version but did not update the old test, and we did not check the tests
for exact version pins before predicting S1. That was our mistake.

Everything the fix is about held. Version 0.1.1 had no bit width for u3 or
u6, so it skipped both size checks on a Const of either type. Version 0.1.2
catches a declared size that is too small (OVI005) and a bit size that
overflows (OVI004) for u3 and u6, as it already did for the other packed
types. It raises no finding on any honest file OpenVINO 2026.4.1 wrote.

## Versions

`openvino_ir_scan` 0.1.1 (live `main` at 9dfa28e) and the patched 0.1.2;
OpenVINO 2026.4.1, numpy 2.5.4. Container `python:3.12`; the run steps had no
network.

## Rows

| # | prediction | result |
|---|---|---|
| L1 | u3/u6 Consts from `save_model`: declared size = 3 x ceil(n / 8) (u3), 3 x ceil(n / 4) (u6) | held for all 8 (for example u3 n=10: 6 bytes; u6 n=10: 9 bytes) |
| L2 | declared size never below ceil(n x bits / 8) | held (u3 n=10: 6 vs 4; u6 n=10: 9 vs 8) |
| H1 | 0.1.1 on all 32 honest files: no finding | held |
| H2 | 0.1.2 on all 32 honest files: no finding | held |
| Ta | 0.1.1 on "short" copies: u3/u6 no finding (the gap), every other type exactly OVI005 | held (u3 and u6 silent; i4, nf4, u1, u2, u4, u8 OVI005) |
| Tb | 0.1.2 on "short" copies: every type exactly OVI005 | held (u3 and u6 now OVI005) |
| Oa | 0.1.1 on "huge" copies: u3/u6 no finding, every other type exactly OVI004 | held |
| Ob | 0.1.2 on "huge" copies: every type exactly OVI004 | held |
| R0 | OpenVINO `read_model` loads every honest u3/u6 file | held (8 of 8) |
| S1 | full unit-test suite with 0.1.2: no failure or error | **failed**: 1,316 run, 1 failure (`test_version` pins "0.1.1"), 0 errors, 3 skipped |

## Next

The fix is unchanged. A second job, `ovi-u3u6-v2`, also changes the old
test's exact pin to a minimum-version check, waits until v0.52.0 is on `main`
so the suite runs on the tree that would be released, and re-runs every row
above. Its pre-registration is
[research/PREREG_OVI_U3U6_V2.md](research/PREREG_OVI_U3U6_V2.md). The fix
ships only if that run holds.

## Limits

One OpenVINO release, which writes only the 3-byte "split" layout. The tight
layout (OpenVINO PR #37430, milestone 2026.5) is covered by hand-written unit
tests only. The models contain only Consts, so this check covers declared
sizes, not inference. It covers our own scanner, not OpenVINO. The runtime
was only asked to read honest files.
