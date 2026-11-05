# Pre-registration: OpenVINO u3 and u6 weights in openvino_ir_scan

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 5 November 2026 (UTC), before job `ovi-u3u6-v1` ran.

## Why

We compared our own scanner's tables with upstream (an audit we repeat each
quarter). OpenVINO's `element::Type_t` (master, `element_type.hpp`, read
5 November 2026) has 26 element types. `openvino_ir_scan` 0.1.1's
`_BITWIDTH` covers 22 of them. `dynamic` and `string` need no bit width,
which leaves two gaps: **u3** and **u6**. For a Const of either type, OVI004
(the element count times bit width reaches 2^64) and OVI005 (declared `size`
smaller than the data needs) are silently skipped. Only the range check
(OVI003) and the negative-dimension check still run. The scanner fails open
on these checks for such weights.

OpenVINO up to 2026.4 stores u3/u6 in 3-byte units: 8 u3 or 4 u6 values per
3 bytes, rounded up. PR #37430 (merged 11 September 2026, milestone 2026.5)
switches to a tight bit stream of ceil(n x bits / 8) bytes. Our size formula,
`(n * bits + 7) >> 3`, is the tight size, and the tight size is never larger
than the split size. So adding `"u3": 3, "u6": 6` should accept honest files
in either layout and catch a declared size below the minimum.

Same-day checks of our other tables found no gap: `safetensors_scan` 0.3.0
lists all 22 safetensors dtypes, and `tflite_model_scan` keeps no
operator-code or tensor-type table that could go stale.

## Setup

A sealed `python:3.12` container. Setup downloads our live `main` and the
newest `openvino` and `numpy` from PyPI (2026.4.1 on 5 November). The run
step has no network.

1. `patch_ovi.py` saves the original scanner (0.1.1), adds the two bit widths
   and bumps it to 0.1.2. The new test, `test_openvino_ir_scan_u3u6.py`, uses
   only the standard library and hand-written IR. The patch must apply once,
   lose no line, and change nothing on a second pass.
2. `run_tests.py` runs the full unit-test suite on the patched tree.
3. `u3u6_check.py` writes, in a child process each, one Const-only model per
   element type (u1, u2, u3, u4, u6, i4, nf4, u8) and count (8, 10, 12, 16)
   with `openvino.save_model`. It reads each Const's declared `size` back
   from the .xml. It makes two edited copies of every n = 10 model: the
   declared size set one byte below ceil(n x bits / 8) ("short"), and the
   shape set to [2^62, 16] ("huge"). Then it scans everything with 0.1.1
   and 0.1.2.

## Predictions

| # | case | prediction |
|---|---|---|
| L1 | u3/u6 Consts written by 2026.4.1 | declared size = 3 x ceil(n / 8) for u3 and 3 x ceil(n / 4) for u6 (split layout) |
| L2 | the same | declared size is never below ceil(n x bits / 8) |
| H1 | 0.1.1 on every honest file | no finding |
| H2 | 0.1.2 on every honest file | no finding |
| Ta | 0.1.1 on the "short" copies | u3 and u6: no finding (the gap); every other type: exactly OVI005 |
| Tb | 0.1.2 on the "short" copies | every type, u3 and u6 included: exactly OVI005 |
| Oa | 0.1.1 on the "huge" copies | u3 and u6: no finding; every other type: exactly OVI004 |
| Ob | 0.1.2 on the "huge" copies | every type: exactly OVI004 |
| R0 | OpenVINO `read_model` on the honest u3/u6 files | each loads |
| S1 | full unit-test suite with 0.1.2 | no failure or error |

## Grading

- A model that OpenVINO's Python API cannot build or save is **not run**,
  never held or failed. A row whose files are missing is also not run.
- Ta/Oa need at least one control type; if none was written, the row is not
  run.
- R0 only checks that honest files load. The runtime is not given edited
  files: this checks our scanner, not OpenVINO.
- If H2, Tb, Ob and S1 hold, `openvino_ir_scan` 0.1.2 ships with its test in
  the next release, and `OPENVINO_IR_SCAN.md` gets the two types and both
  layouts. If L1 fails because 2026.4.1 already writes the tight layout, the
  fix is unchanged and the report says so.

## Limits

One OpenVINO release, which writes only the split layout. The tight layout
is covered by the hand-written unit tests, not by files OpenVINO wrote.
Const-only models: the check covers declared sizes, not inference.
