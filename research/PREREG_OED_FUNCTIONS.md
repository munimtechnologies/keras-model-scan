<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Pre-registration: ONNX external-data scanners and local functions (job `oed-functions-v1`)

Written and published on 2026-11-06, **before** job `oed-functions-v1` runs.
Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0.

## What we found by reading source (not yet run)

1. **Local functions are skipped.** `onnx_external_data_scan` 0.1.0 and
   `onnx_external_data_key_scan` 0.1.0 walk only `ModelProto.graph` (field 7).
   onnx's own loader goes further: `load_external_data_for_model` loads every
   tensor that `external_data_helper._get_all_tensors` returns, and that
   includes attribute tensors of nodes in `ModelProto.functions` (field 25,
   `FunctionProto.node` = 7). `onnx.save_model(..., save_as_external_data=True,
   convert_attribute=True)` writes those tensors as external data. So an
   honest writer produces external-data locations that the 0.1.0 gates never
   read. `training_info` graphs (field 20) are not walked by either scanner;
   onnx itself does not walk them either, but other tools may.
   (onnx main `onnx/external_data_helper.py`; field numbers from
   `onnx/onnx.in.proto`, read 2026-11-06.)
2. **Big inline models are only partly read.** `onnx_external_data_scan` 0.1.0
   reads at most 256 MiB. In an honest inline model larger than that, the
   `graph` field runs past the read, the reader stops quietly, and the result
   is clean without the graph being checked. A single ONNX protobuf can be up
   to 2 GiB.

## The fix under test (0.2.0 of both scanners)

- Walk `FunctionProto.node` (7) and `FunctionProto.attribute_proto` (11) of
  every local function, and both `TrainingInfoProto` graphs
  (`initialization` = 1, `algorithm` = 2).
- `onnx_external_data_scan`: read up to 2 GiB in 16 MiB chunks, parse through a
  `memoryview` (no slice copies), and report **OED006** (MEDIUM, "file larger
  than the scan limit") instead of a silent clean result when a file is bigger.
- New test module `test_onnx_external_data_functions.py` (standard library
  only). No test pins an exact version of either module (checked:
  `test_attribution.py`, both existing ONNX test modules).

## Files (written inside the sealed job, onnx 1.23.2)

Honest files come from `onnx.save_model`. Planted copies are made by editing
one `external_data` entry of a proto read with `load_external_data=False` and
writing its bytes directly. No planted file is ever loaded by onnx.

| Case | What it is |
|---|---|
| honest_func | model with a local function whose Constant holds a 4096-byte tensor; saved with `convert_attribute=True`, `location="weights.bin"` |
| honest_plain | same graph without functions, one external initializer |
| honest_train | honest_func plus a training_info initialization graph with an inline initializer |
| h4_big_honest | a 272,000,000-byte inline UINT8 initializer, then a small external tensor at `after.bin` |
| e1_func_parent | honest_func with the function tensor's location set to `../outside.bin` |
| e2_func_attrproto_abs | honest_func plus a function default attribute (`attribute_proto`) tensor at `/abs/w.bin` |
| e3_train_backslash | honest_plain plus a training_info initializer at `..\t.bin` |
| e4_big_after_cap | h4 with the small tensor at `../after.bin` (past the first 256 MiB) |
| k1_func_key | honest_func with an extra external_data key `owner` on the function tensor |
| c1_graph_parent | honest_plain with its graph initializer at `../g.bin` (control: no regression) |

## Predictions (graded rows)

| Row | Prediction |
|---|---|
| P1 | the patch applies cleanly to both scanners and both docs (each edit once, a second pass changes nothing, no line lost, the code compiles) |
| S1 | the whole keras-model-scan suite passes with the patched files |
| W1 | onnx's writer stores the function's Constant tensor as external data (`data_location` 1, location `weights.bin`), and the graph initializer at `weights.bin` |
| L1 | `onnx.load` on honest_func fills that function tensor from `weights.bin` (4096 bytes, equal to the values written) |
| H1 | 0.2.0 reports nothing on honest_func, honest_plain, honest_train and h4_big_honest; key 0.2.0 reports nothing on the first three |
| E1 | 0.1.0: no findings; 0.2.0: exactly {OED001} |
| E2 | 0.1.0: no findings; 0.2.0: exactly {OED002} |
| E3 | 0.1.0: no findings; 0.2.0: exactly {OED001, OED005} |
| E4 | the `../after.bin` string sits past byte 268,435,456; 0.1.0: no findings; 0.2.0: exactly {OED001} |
| K1 | key 0.1.0: no OEK001; key 0.2.0: OEK001 for key `owner` only |
| C1 | {OED001} from both 0.1.0 and 0.2.0 |
| T1 | 0.2.0 scans the 272 MB honest file in under 60 s with under 1024 MB peak RSS |
| Hb | among `.onnx` files in the 100 most-downloaded Hugging Face repos tagged `library=onnx` (file list metadata only, nothing downloaded), at least 10 are larger than 256 MiB and at most 2 GiB |

**Release rule:** if P1, S1, W1, L1, H1, E1-E4, K1 and C1 hold, the patched
files, the new test module and a graded report are published and released
(onnx_external_data_scan 0.2.0, onnx_external_data_key_scan 0.2.0). If a
release of other modules ships first, the suite is re-run on the new main
before publishing. T1 and Hb are reported either way. Any failed row is
published as it came out.

## Prior art

promptfoo's ModelAudit already walks `model.functions` (their nodes and
`attribute_proto`) and both `training_info` graphs when it looks for external
data (`modelaudit/scanners/onnx_scanner.py` on main, read 2026-11-06). This
fix brings our gate up to that coverage; it is not a new kind of check.

## Honest limits

- These are coverage gaps in our own CI gates, found by reading source. The
  check uses files that onnx 1.23.2 writes; it does not test how any loader
  handles a planted file.
- Current onnx releases check external-data paths themselves, so a finding is
  defence in depth for a pipeline, not a claim about a live bug in onnx.
- The Hub census reads public file-size metadata only. It shows how common
  big single-file models are; it does not say anything about their contents.
