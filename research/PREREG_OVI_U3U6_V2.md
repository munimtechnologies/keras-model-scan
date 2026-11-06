# Pre-registration: u3 and u6 in openvino_ir_scan, re-run (ovi-u3u6-v2)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 6 November 2026 (UTC), before job `ovi-u3u6-v2` ran. Scripts:
[research/ovi-u3u6-v2/](ovi-u3u6-v2/). The first run's predictions and
reasoning are in [PREREG_OVI_U3U6.md](PREREG_OVI_U3U6.md). Its result is in
[REALFILE_CHECK_OVI_U3U6_2026-11.md](../REALFILE_CHECK_OVI_U3U6_2026-11.md).

## Why a re-run

The first run held 9 of 10 rows. S1 failed only because
`test_openvino_ir_scan.test_version` asserts `__version__ == "0.1.1"`
exactly. The fix itself is unchanged. This run changes three things:

1. `patch_ovi.py` also replaces that exact pin with a minimum-version check
   (`>= 0.1.2`), in the style `test_attribution` has used since v0.51.0. It
   also adds a "u3 and u6" section to `OPENVINO_IR_SCAN.md`, before "Prior
   art and honest limits", or at the end if that heading is missing. Each of
   the three edits must apply exactly once, a second pass must change nothing,
   and no line may be lost except the replaced ones. Otherwise nothing is
   written. The script always exits 0, and its result is row P1.
2. The setup step waits, for up to 60 minutes, until `main` carries
   model-file-scan 0.12.0 (release v0.52.0, the variant-index fix), and then
   downloads it. The full suite then runs on the tree that would be released.
   Whether it got that tree is reported (`fetch.combined`).
3. Rows P1 (patch), V1 (versions) and S2 (the new test module alone) are
   added. A failed P1 makes every other row **not run**.

## Predictions

| # | prediction |
|---|---|
| P1 | the patch applies under the rules above to `openvino_ir_scan.py`, `test_openvino_ir_scan.py` and `OPENVINO_IR_SCAN.md` |
| V1 | the original reads 0.1.1 and the patched scanner reads 0.1.2 |
| L1 | u3/u6 Consts written by `save_model`: declared size = 3 x ceil(n / 8) for u3 and 3 x ceil(n / 4) for u6 |
| L2 | the same: declared size is never below ceil(n x bits / 8) |
| H1 | 0.1.1 on every honest file: no finding |
| H2 | 0.1.2 on every honest file: no finding |
| Ta | 0.1.1 on the "short" copies: u3 and u6 no finding; every other type exactly OVI005 |
| Tb | 0.1.2 on the "short" copies: every type exactly OVI005 |
| Oa | 0.1.1 on the "huge" copies: u3 and u6 no finding; every other type exactly OVI004 |
| Ob | 0.1.2 on the "huge" copies: every type exactly OVI004 |
| R0 | OpenVINO `read_model` loads each honest u3/u6 file |
| S1 | the full unit-test suite on the patched tree: no failure or error |
| S2 | `test_openvino_ir_scan_u3u6` alone exits 0 and runs at least 6 tests |

The setup, files, element types (u1, u2, u3, u4, u6, i4, nf4, u8), counts
(8, 10, 12, 16) and edits are the same as in the first run.

## Grading and release

- A model that OpenVINO's Python API cannot build or save is **not run**,
  never held or failed. An API or network error means the affected rows were
  not run.
- **Release rule:** if P1, V1, H2, Tb, Ob, S1 and S2 all hold, and
  `fetch.combined` is true (the suite ran on a tree that already had
  v0.52.0), then release **v0.52.1** with the job's patched
  `openvino_ir_scan.py`, `test_openvino_ir_scan.py`,
  `test_openvino_ir_scan_u3u6.py` and `OPENVINO_IR_SCAN.md`. If everything
  holds but `combined` is false, a full-suite job on the combined tree runs
  first. If any of those rows fails, there is no release, and the failure is
  written up.

## Limits

These are the same as in the first run. One OpenVINO release (the newest on
PyPI at run time) writes only the 3-byte layout, and the tight layout is
covered by hand-written unit tests. The models contain only Consts. The check
covers our own scanner, not OpenVINO.
