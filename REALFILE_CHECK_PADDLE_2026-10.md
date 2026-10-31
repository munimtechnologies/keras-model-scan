# Real-file check: PaddlePaddle program scanner, October 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`paddle_program_scan.py` was written and unit-tested against hand-encoded
programs. This check asks whether it reads programs written by Paddle itself
the same way. The expectations were written down before the job ran, in
[research/PREREG_PADDLE_REALFILE.md](research/PREREG_PADDLE_REALFILE.md), which
also fixed the grading rule: a case where Paddle's own API refuses to build
the file is reported as **not run**, never as held or failed.

The job (`paddle-realfile-v2`) ran in a sealed `python:3.12` container on
31 October 2026 (UTC), with network for `pip install paddlepaddle` only and no
network while programs were built and scanned. Programs were only serialized
and scanned; none was run as a model. PIR mode and legacy mode each ran in
their own process, because Paddle reads `FLAGS_enable_pir_api` at import.

**Result: 6 of 6 predictions that ran held; 1 was not run (P5).** No false
alarm on the two programs `paddle.jit.save` wrote, and each crafted case was
flagged by exactly the predicted rule with the predicted evidence.

Versions: `paddlepaddle 3.3.1` (CPU wheel), `paddle_program_scan 0.1.0`.

| # | Mode | Prediction | Result | Evidence |
|---|------|-----------|--------|----------|
| P1 | PIR | `paddle.jit.save` of a Linear+ReLU layer writes a program file; no findings | **PASS** | wrote `inference.json` + `inference.pdiparams`; `[]` |
| P2 | PIR | that file with one op renamed to `save_combine` and given `file_path=/tmp/p_edit`: exactly one PDL001 | **PASS** | `inference.json (PIR): op 1.save_combine, file_path /tmp/p_edit` (renamed op: `1.data`) |
| P3 | legacy | `paddle.jit.save` writes a program file; no findings | **PASS** | wrote `inference.pdmodel` + `.pdiparams` + `.pdiparams.info`; `[]` |
| P4 | legacy | the same edit through Paddle's own `framework_pb2`: exactly one PDL001 | **PASS** | `inference.pdmodel block 0: op save_combine, file_path /tmp/p_edit` (renamed op: `feed`) |
| P5 | legacy | a static `Program` with a `save_combine` op (`/tmp/p5`): exactly one PDL001 | **NOT RUN** | Paddle refused to build it: `Output Y cannot be found in operator save_combine` |
| P6 | legacy | a static `Program` with a `load_combine` op (`/tmp/p6`): exactly one PDL002 | **PASS** | `model block 0: op load_combine, file_path /tmp/p6` |
| P7 | legacy | a static `Program` built with `paddle.static.py_func`: exactly one PDL003 | **PASS** | `model block 0: op py_func, forward_callable_id 0` |

**Why P5 did not run.** The check script appended a `save_combine` op with
no outputs. In Paddle 3.3.1, `Block.append_op` runs the op's variable-type
inference at once, and `save_combine` declares an output `Y`, so Paddle raised
`(NotFound) Output Y cannot be found in operator save_combine` before any file
existed. That is a mistake in the check script, not something the scanner
saw. P4 already covers PDL001 on a legacy program Paddle wrote and parsed
back through its own protobuf classes; P5 would have added a program built
from scratch.

**The op names Paddle actually wrote.** The PIR program from P1 names its
ops `1.add`, `1.data`, `1.fetch`, `1.matmul`, `1.relu` and `p` (parameters).
The dialect prefix sits before the last `.`, and the scanner matches on the
part after it, which is why P2's `1.save_combine` was recognised. No change to
the matching is needed.

## The unit-test step

The job also re-ran `test_paddle_program_scan.py` from the folder it was filed
in, and that step exited 1: 21 of 23 tests passed and 2 raised `TypeError:
_jop() got multiple values for argument 'name'`. Those two errors were in a
**test helper**, not the scanner: the helper took its op name as a parameter
called `name`, and two PIR tests also passed a `name=` attribute. The
published test file renames the parameter to `op_name`; the scanner module is
byte-for-byte the one this job checked, and the publishing pipeline ran the
published test file and committed only after it passed.

## Honest limits

- One file per prediction, built by this job, not a corpus of published
  Paddle models. This is not a false-positive rate on real-world programs.
- P2 and P4 were edited copies of real files, so they test the scanner's
  walk over Paddle's real layout, not a file Paddle would write on its own.
- One Paddle release (3.3.1, CPU).
- A finding says a program asks for something a reviewer should look at (a
  stored file path, a registered Python callable). It does not show that any
  program loading it is exploitable.
- Static review only: no program was run.
