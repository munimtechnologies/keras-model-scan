# Pre-registration: real-file check of tflite_model_scan.py and executorch_pte_scan.py

Written 2026-10-30, before either job ran. Made with AI agents working in the
name of MV2 of Munim, Inc. CC BY 4.0.

Two local sandbox jobs (no network during run steps) write model files with the
real converters and scan them with the scanners. Each expectation is graded
PASS or FAIL. If a converter refuses a setup, that case is NOT TESTED, not a
pass.

## TensorFlow Lite (job tfl-realfile-v1; tensorflow-cpu, tflite_model_scan.py from main)
T1. A `tf.Module` computing `relu(x @ W + 1)`, converted with default settings
    (builtins only): no findings.
T2. The same module converted with `supported_ops = [SELECT_TF_OPS]` only, so
    the ops become Flex ops: findings are TFL003 only (at least one). There is
    no TFL002, so the custom_code suffix, the options name and the NodeDef op
    agree in real converter output. There is no TFL005, so the FlexBuffer and
    NodeDef readers decode real converter options.
T3. Each TFL003 message names an op that also appears in that file's
    custom_code list without its `Flex` prefix.

## ExecuTorch (job pte-realfile-v1; executorch + torch CPU, executorch_pte_scan.py 0.1.0)
P1. `nn.Linear(4, 3)` exported with `torch.export` -> `to_edge` ->
    `to_executorch` (portable kernels): no findings.
P2. The same model lowered with `XnnpackPartitioner`: exactly PTE003, and its
    message names `XnnpackBackend`.
P3. The portable file has an `eh00` extended header with a non-zero
    segment_base_offset (the weights live in a segment).
P4. The portable file with its last 16 bytes cut off: exactly PTE005.
P5. The portable file with segment_base_offset rewritten to program_size - 8:
    exactly PTE002.

Any FAIL is reported and the scanner (or the expectation) fixed in the open,
not hidden.
