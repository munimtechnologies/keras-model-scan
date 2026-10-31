# Real-file check: PaddlePaddle program scanner, October 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`paddle_program_scan.py` was written and unit-tested against hand-encoded
programs. This check asks whether it reads programs written by Paddle itself
the same way. The expectations were written down before the job ran, in
[research/PREREG_PADDLE_REALFILE.md](research/PREREG_PADDLE_REALFILE.md), which
also fixed the grading rule: a case where Paddle's own API refuses to build
the file is reported as **not run**, never as held or failed.

## Update, 31 October 2026: P5 ran and held (7 of 7)

The first job left P5 not run because the check script built an invalid
`save_combine` op (see below). The script was fixed in one place and re-run
as job `paddle-realfile-v3`: P5's `save_combine` op now gets the RAW output
variable `Y` that Paddle 3.3.1 requires. The predictions, the scanner and the
grading rule were not changed. The job downloaded `paddle_program_scan.py` and
its test file from this repository's `main` branch, so it checked the
published code.

**Result: all 7 pre-registered predictions held.** P1-P4, P6 and P7 gave the
same rules and evidence as in the first job, and P5 gave exactly one PDL001:
`model block 0: op save_combine, file_path /tmp/p5`. The published unit tests
also passed in the same container (23 of 23).

The script is in
[research/realfile_check_paddle.py](research/realfile_check_paddle.py) (v3).
It never calls a Paddle executor. The job log shows one
`New Executor is Running` line from inside `paddle.jit.save` in legacy mode,
while Paddle exported the clean P3 model. No crafted program was run.

## First run (job `paddle-realfile-v2`)

The job ran in a sealed `python:3.12` container on 31 October 2026 (UTC). It
had network only for `pip install paddlepaddle`, and none while programs were
built and scanned. Programs were only serialized and scanned; none was run as
a model. PIR mode and legacy mode each ran in their own process, because Paddle
reads `FLAGS_enable_pir_api` at import.

**Result then: 6 of 6 predictions that ran held; 1 was not run (P5).** There
was no false alarm on the two programs `paddle.jit.save` wrote, and each
crafted case was flagged by exactly the predicted rule with the predicted
evidence.

Versions: `paddlepaddle 3.3.1` (CPU wheel), `paddle_program_scan 0.1.0`.

| # | Mode | Prediction | Result | Evidence |
|---|------|-----------|--------|----------|
| P1 | PIR | `paddle.jit.save` of a Linear+ReLU layer writes a program file; no findings | **PASS** | wrote `inference.json` + `inference.pdiparams`; `[]` |
| P2 | PIR | that file with one op renamed to `save_combine` and given `file_path=/tmp/p_edit`: exactly one PDL001 | **PASS** | `inference.json (PIR): op 1.save_combine, file_path /tmp/p_edit` (renamed op: `1.data`) |
| P3 | legacy | `paddle.jit.save` writes a program file; no findings | **PASS** | wrote `inference.pdmodel` + `.pdiparams` + `.pdiparams.info`; `[]` |
| P4 | legacy | the same edit through Paddle's own `framework_pb2`: exactly one PDL001 | **PASS** | `inference.pdmodel block 0: op save_combine, file_path /tmp/p_edit` (renamed op: `feed`) |
| P5 | legacy | a static `Program` with a `save_combine` op (`/tmp/p5`): exactly one PDL001 | **NOT RUN** in v2; **PASS** in v3 | v2: Paddle refused to build it, `Output Y cannot be found in operator save_combine`. v3: `model block 0: op save_combine, file_path /tmp/p5` |
| P6 | legacy | a static `Program` with a `load_combine` op (`/tmp/p6`): exactly one PDL002 | **PASS** | `model block 0: op load_combine, file_path /tmp/p6` |
| P7 | legacy | a static `Program` built with `paddle.static.py_func`: exactly one PDL003 | **PASS** | `model block 0: op py_func, forward_callable_id 0` |

**Why P5 did not run the first time.** The check script appended a
`save_combine` op with no outputs. In Paddle 3.3.1, `Block.append_op` runs the
op's variable-type inference straight away. `save_combine` declares an output
`Y`, so Paddle raised `(NotFound) Output Y cannot be found in operator
save_combine` before any file existed. That was a mistake in the check
script, not something the scanner saw.

**The op names Paddle actually wrote.** The PIR program from P1 names its
ops `1.add`, `1.data`, `1.fetch`, `1.matmul`, `1.relu` and `p` (parameters).
The dialect prefix sits before the last `.`, and the scanner matches on the
part after it, which is why P2's `1.save_combine` was recognised. No change to
the matching is needed.

## The unit-test step

The first job also re-ran `test_paddle_program_scan.py` from the folder it
was filed in. That step exited 1: 21 of 23 tests passed and 2 raised
`TypeError: _jop() got multiple values for argument 'name'`. Both errors came
from a **test helper**, not the scanner: the helper took its op name as a
parameter called `name`, and two PIR tests also passed a `name=` attribute.
The published test file renames the parameter to `op_name`. The scanner
module is byte-for-byte the one this job checked, and the publishing pipeline
ran the published test file and committed only after it passed. The v3 job ran
the published test file: 23 of 23 passed.

## Honest limits

- One file per prediction, built by this job, not a corpus of published
  Paddle models. This is not a false-positive rate on real-world programs.
- P2 and P4 were edited copies of real files, so they test the scanner's
  walk over Paddle's real layout, not a file Paddle would write on its own.
- One Paddle release (3.3.1, CPU).
- P5 was graded on a second job after a fix to the check script. The
  prediction itself was not changed.
- A finding says a program asks for something a reviewer should look at (a
  stored file path, a registered Python callable). It does not show that any
  program loading it is exploitable.
- Static review only: no crafted program was run.
