# Real-file check: TFLite and ExecuTorch scanners, October 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

This grades two sealed-sandbox jobs that build model files with the **real
converters** and scan them with the toolkit's stdlib-only scanners. Each
expectation was **pre-registered** before the jobs ran, in
[`research/PREREG_TFL_PTE_REALFILE_2026-10.md`](research/PREREG_TFL_PTE_REALFILE_2026-10.md);
the check script is
[`research/realfile_check_tfl_pte.py`](research/realfile_check_tfl_pte.py). A
converter refusal would have been "NOT TESTED", not a pass. Neither converter
refused.

Both jobs ran in a `python:3.12` container with no network during the scan
steps (the converters and the scanner ran offline; only `pip` had network).

**Result: 8 of 8 pre-registered predictions held.** The scanners raised no
false alarms on normal converter output and flagged exactly the pre-registered
cases, naming the real ops and backends.

## TensorFlow Lite (job `tfl-realfile-v1`)

Versions: tensorflow 2.21.0, `tflite_model_scan` 0.1.0 (fetched from `main`).
A `tf.Module` computing `relu(x @ W + 1)`.

| # | Prediction | Result | Evidence |
|---|-----------|--------|----------|
| T1 | Default (builtins-only) conversion: no findings | **PASS** | `got []` |
| T2 | `SELECT_TF_OPS`-only conversion: TFL003 only (no TFL002, no TFL005) | **PASS** | `got ['TFL003']` for MatMul, AddV2, Relu, Identity |
| T3 | Each TFL003 names an op that also appears in that file's `custom_code` list without its `Flex` prefix | **PASS** | custom codes `['FlexMatMul','FlexAddV2','FlexRelu','FlexIdentity']` |

T2 confirms that in **real converter output** the `custom_code` suffix, the
FlexBuffer options name and the embedded `NodeDef` op all agree, so the
disagreement the scanner reports as TFL002 marks a file edited after
conversion, not normal output. It also confirms the FlexBuffer and NodeDef
readers decode converter-written options (no TFL005).

## ExecuTorch (job `pte-realfile-v1`)

Versions: torch 2.15.0+cpu, executorch 1.5.1+cpu, `executorch_pte_scan` 0.1.0.
An `nn.Linear(4, 3)` exported with `torch.export` -> `to_edge` ->
`to_executorch`.

| # | Prediction | Result | Evidence |
|---|-----------|--------|----------|
| P1 | Portable-kernel export: no findings | **PASS** | `got []` |
| P2 | XNNPACK-lowered: exactly PTE003, message names `XnnpackBackend` | **PASS** | `PTE003 ... XnnpackBackend [plan 0 delegate 0: segment 1, 720 bytes, 0 compile specs]` |
| P3 | The portable file has an `eh00` header with a non-zero segment base offset | **PASS** | header `(program_size 1464, base 1536, data_size 60)`, file 1596 bytes |
| P4 | Portable file with its last 16 bytes cut off: exactly PTE005 | **PASS** | `PTE005 ... shorter than its extended header says [... file size 1580]` |
| P5 | Portable file with `segment_base_offset` rewritten to `program_size - 8`: exactly PTE002 | **PASS** | `PTE002 ... [segment_base_offset 1456 lies inside the 1464-byte program]` |

P2 confirms that the real XNNPACK lowering produces exactly one backend
delegate (`XnnpackBackend`) with a 720-byte compiled blob in a data segment,
and that the scanner inventories it without trying to read inside it. P3-P5
confirm the `eh00` extended-header parse (program size, segment base offset,
segment data size) against a file written by ExecuTorch itself, and that the
truncation and base-inside-program checks fire on real bytes, not only on
hand-built ones.

The module's full unit suite (35 tests for ExecuTorch, 27 for TFLite) also ran
green inside the container against the same scanner code.

## Honest limits

Each case is one small file per prediction. These checks establish that the
scanners agree with real converter output and fire on the specific
malformations pre-registered; they are not a false-positive rate measured over
a corpus of published models, and they do not prove a crafted file is
exploitable in any runtime. The malformed ExecuTorch cases (P4, P5) were made
by editing bytes of a real file, so they test the parser, not a converter
path. Static review only: nothing was loaded or executed.
