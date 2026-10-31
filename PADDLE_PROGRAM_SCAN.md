# paddle_program_scan

Static scanner for **PaddlePaddle** program files: legacy `.pdmodel`
(`ProgramDesc` protobuf) and Paddle 3 PIR `.json` programs. Part of the
open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan)
toolkit. Made with AI agents working in the name of MV2 of Munim, Inc.
Apache-2.0.

```bash
python paddle_program_scan.py inference.pdmodel
python paddle_program_scan.py inference.json
```

It exits `1` on any high finding (so it can gate CI), `2` on a usage error or
an unreadable file, and `0` when clean or only medium findings remain. It uses
**only the Python standard library**: no paddle, no protobuf package.

## Why

A Paddle inference model is a program plus a weights file
(`.pdiparams`). When the program runs, every op in it runs. A few operators
touch the file system through a path stored in the op's own attributes, so the
path comes from the model file, not from the code that loads it:

| op | attribute | what it does | source |
|---|---|---|---|
| `save`, `save_combine` | `file_path` (string) | writes tensors to that path (`save` overwrites by default) | `paddle/fluid/operators/save_op.cc`, `save_combine_op.cc`; `phi/ops/yaml/inconsistent/static_ops.yaml` |
| `load`, `load_combine` | `file_path` (string) | reads tensors from that path | `load_op.cc`, `load_combine_op.cc`; `static_ops.yaml` |
| `read_file` | `filename` (string) | reads raw bytes from that path into a tensor | `phi/ops/yaml/ops.yaml` |
| `py_func` | `forward_callable_id` (int) | calls a Python function registered in the loading process, picked by index | `py_func_op.cc` |

This is documented behaviour, not a Paddle bug: Paddle's security policy
(github.com/PaddlePaddle/Paddle/security/policy) says computation graphs can
read and write files, treats that as intended, and asks users to audit
untrusted models and run them in a sandbox. This module is a tool for that
audit step.

A program exported for inference does not need any of these. This scanner
lists them, with the path each one names, so a reviewer or a CI gate sees them
before the model is run.

Formats, from Paddle's own source (read 30 October 2026):

- `.pdmodel`: `ProgramDesc{blocks=1, version=4, op_version_map=5}`,
  `BlockDesc{idx=1, parent_idx=2, vars=3, ops=4}`,
  `OpDesc{inputs=1, outputs=2, type=3, attrs=4}`,
  `OpDesc.Attr{name=1, type=2, i=3, s=5, strings=8, var_name=17, vars_name=18, ...}`
  (`paddle/phi/core/framework/framework.proto`).
- PIR `.json`: regions hold `blocks`, blocks hold `ops`; an op names itself
  under `"#"` and lists attributes under `"A"` as `{"N": name, "AT": {...,
  "D": value}}` (`paddle/fluid/pir/serialize_deserialize/include/schema.h`).
  Op names may carry a dialect prefix (`pd_op.` or a compressed id), so the
  scanner compares the part after the last `.`.

Every block (and every nested region in PIR) is checked, so ops inside
control-flow sub-blocks are found too.

## Rules

| rule | severity | CWE | what it means |
|------|----------|-----|---------------|
| PDL001 | high | CWE-73 | An op that writes a file (`save`, `save_combine`), with the `file_path` it names. |
| PDL002 | high | CWE-73 | An op that reads a file (`load`, `load_combine`, `read_file`), with the path it names. |
| PDL003 | medium | CWE-829 | A `py_func` op: it runs a Python callable registered in the loading process. The callable is not stored in the file, only its index. |
| PDL004 | medium | CWE-693 | Not a parseable ProgramDesc or PIR program, nesting deeper than 64 levels, or findings capped. |

Repeats of the same op and path are reported once with a count.

## Prior art and honest limits

promptfoo's ModelAudit has a `paddle_scanner.py`. As we read its source
(30 October 2026), it handles `.pdmodel` and `.pdiparams`, does not parse the
format, and searches the raw bytes for suspicious code strings; it does not
look at operators or their attributes, and does not read PIR `.json`
programs. `paddle_program_scan` does exactly that operator-level check, which
the byte search cannot do, and leaves code-string searching to other tools.

Limits:

- Static review only: nothing is loaded or executed. Whether a given Paddle
  runtime path runs a given op is not tested here; the scanner reports that
  the program contains it.
- Only the ops in the table are checked. `.pdiparams` weight files and
  pickle-based `.pdparams` files are not read by this module (use the
  toolkit's pickle scanner for `.pdparams`).
- The PIR reading relies on the documented JSON keys (`ops`, `#`, `A`, `N`,
  `AT`, `D`); if a Paddle release compresses op names to numeric ids only,
  those ops would not be matched.
- These tests use hand-encoded programs. A check against files written by
  Paddle itself is pre-registered in `research/PREREG_PADDLE_REALFILE.md` and
  has not run yet.

If you spot a mistake, the repo is the place to raise it.
