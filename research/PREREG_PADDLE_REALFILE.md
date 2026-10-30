# Pre-registration: paddle_program_scan on files written by Paddle itself

Written 30 October 2026 (UTC), before the check runs. Made with AI agents
working in the name of MV2 of Munim, Inc. Apache-2.0 code, CC BY 4.0 text.

`paddle_program_scan.py` 0.1.0 was built and tested on hand-encoded programs
only. This check writes programs with the current `paddlepaddle` CPU wheel in
a sealed sandbox (no network while it runs) and scans them. The programs are
only serialized and scanned; none is executed as a model. Script:
`research/realfile_check_paddle.py`. Each case that raises an API error is
reported as "not run", not as held or failed.

PIR mode (`FLAGS_enable_pir_api=1`, Paddle 3 default):

- **P1** `paddle.jit.save` of a small Linear+ReLU layer writes a program file
  (`.json` or `.pdmodel`), and the scanner reports **no findings** on it.
- **P2** In a copy of that file, one existing op is renamed to `save_combine`
  (same dialect prefix) and given a `file_path` attribute `/tmp/p_edit`; the
  scanner reports **exactly one PDL001** naming `/tmp/p_edit`. This tests the
  walker on Paddle's real layout, not on our own guess of it.

Legacy mode (`FLAGS_enable_pir_api=0`):

- **P3** `paddle.jit.save` writes a program file and the scanner reports **no
  findings**.
- **P4** Same edit as P2 on that file (through Paddle's own `framework_pb2`):
  **exactly one PDL001** naming `/tmp/p_edit`.
- **P5** A static `Program` with a `save_combine` op (`file_path=/tmp/p5`),
  serialized by `Program.desc.serialize_to_string()`: **exactly one PDL001**
  naming `/tmp/p5`.
- **P6** Same with `load_combine` (`file_path=/tmp/p6`): **exactly one
  PDL002** naming `/tmp/p6`.
- **P7** A static `Program` built with `paddle.static.py_func`: **exactly one
  PDL003** mentioning `forward_callable_id`.

The unit tests in `test_paddle_program_scan.py` are re-run in the same job.
The graded result will be published as `REALFILE_CHECK_PADDLE_2026-10.md`,
including any prediction that fails and the op names Paddle actually wrote.
