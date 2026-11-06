# Pre-registration: STACK_GLOBAL operands from the pickle memo (pkl-memo-v1)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 6 November 2026 (UTC), before job `pkl-memo-v1` ran. Scripts:
[research/pkl-memo/](pkl-memo/). The new test module is committed only
together with the fix, so it never runs against unpatched code.

## Why

Our walk-names check (job `walk-names-v1`, graded in
[REALFILE_CHECK_WALK_NAMES_2026-11.md](../REALFILE_CHECK_WALK_NAMES_2026-11.md))
held 13 of 15 rows. The two failures had one cause in our pickle scanner.
`pickle_model_scan` 0.2.1 reported **PKL007 HIGH** ("unresolved
STACK_GLOBAL operands") on both files that paddlepaddle 3.3.1's
`paddle.save` wrote. It did the same on 6 of the 7 published `.pdparams`
files the job downloaded.

The cause is in `scan_pickle_bytes`. At protocols 4 and 5, Python's pickler
writes an import as two memoized strings and `STACK_GLOBAL`. When a module
name comes up again (for example `numpy.ndarray`, then `numpy.dtype`), the
pickler fetches the string from the memo (`BINGET`) instead of writing it
again. 0.2.1 counted any memo fetch as an unresolved operand. So any
honest protocol-4/5 pickle that imports two names from one module got
PKL007 HIGH. That includes `paddle.save`'s default protocol 4 and plain
`pickle.dump` at protocol 5, the Python 3.8+ default. A HIGH that every
honest file of a format triggers teaches users to ignore the rule.

0.2.1 also read "the last two strings seen", not "the last two pushes". So
strings followed by `POP` could put different operands on the stack from the
ones it classified. That makes it too lenient in one case while being too
strict in the common one.

## The fix (patch_pkl.py, applied to live `main` inside the job)

- `pickle_model_scan` 0.3.0 tracks the memo the way the unpickler fills it.
  `PUT`, `BINPUT` and `LONG_BINPUT` store at their index, and `MEMOIZE`
  stores at the current memo size. A slot holds the string only if the
  opcode just before the store pushed a string. A `STACK_GLOBAL` is
  resolved when the two opcodes that pushed its operands are string literals
  or memo fetches of such a slot. Only memo stores, `FRAME` and `PROTO` may
  sit in between. Every other case stays PKL007 HIGH: a slot holding no
  string, an index never stored, or operands that are not the last two
  pushes. A resolved import is classified like any other, so a memoized
  `os` / `system` with `REDUCE` is PKL001 CRITICAL, not only PKL007.
- `test_pickle_model_scan.test_unresolved_stack_global_is_flagged` used a
  memoized string `"x"` fetched twice. That stream now resolves (to an
  unknown import, PKL003). The test is changed to a memo slot holding an
  empty tuple, which must still give PKL007 HIGH.
- model-file-scan 0.12.1 (module and `pyproject.toml`), so pip users get the
  change. `PICKLE_SCAN.md` gets a section. The PKL007 message wording is
  updated if it matches exactly (optional, reported).
- New stdlib test module `test_pickle_model_scan_memo.py` (10 tests). It
  includes real `pickle.dumps` output at protocols 4 and 5, and asserts
  that the memo fetch is really there.
- Each edit must apply exactly once, a second pass must change nothing, and
  no line may be lost except the replaced ones. Otherwise nothing is
  written. Setup waits up to 90 minutes for release v0.52.1
  (`openvino_ir_scan` 0.1.2) to be on `main`, so the suite runs on the tree
  that would be released next (`fetch.combined`).

## Setup

A sealed `python:3.12` container. Setup has network. It downloads live
`main` and installs CPU torch, paddlepaddle and numpy (the newest releases;
versions are recorded). It also downloads published files ending `.pdparams`,
`.pdopt`, `.pkl` or `.pickle` from the 500 most downloaded Hub models tagged
`paddlepaddle` and the 500 tagged `sklearn`. Limits: non-gated models, at
most 2 files per model, 15 per list, 40 attempts per list, 40 MB each. The
run steps have no network. Nothing is ever loaded or unpickled. The
scanners only disassemble bytes, and each version runs in its own process.

Writers (child processes): `pd` (`paddle.save` of a Linear layer's and an
Adam optimizer's `state_dict`), `coll` (Python `pickle.dump` of a Counter, a
ChainMap and an OrderedDict at protocols 4 and 5), `np` (three numpy arrays
at protocols 4 and 5), `torch` (`torch.save` of a small `state_dict` at its
default protocol and at `pickle_protocol=4`).

Planted streams: Fa (memo slot holds a tuple), Fb (memo index never stored),
Fc (four strings, then two `POP`s, then `STACK_GLOBAL`), Fd (`os` and
`system` memoized, fetched back, `STACK_GLOBAL`, `REDUCE`), Fe (the
`test_attribution` stream: protocol-2 `GLOBAL os system`, `REDUCE`).

## Predictions

| # | prediction |
|---|---|
| P1 | the patch applies under the rules above |
| V1 | unpatched: pickle_model_scan 0.2.1, model-file-scan 0.12.0; patched: 0.3.0, 0.12.1, `pyproject.toml` 0.12.1 |
| S1 | the whole unit-test suite passes on the patched tree: 0 failures, 0 errors |
| S2 | the new test module alone exits 0 and runs at least 10 tests |
| G1 | the gap: 0.2.1 gives PKL007 HIGH on `model.pdparams`, `model.pdopt` and both collections pickles |
| N1 | 0.3.0 on every honest written file: no PKL007 and nothing HIGH or CRITICAL |
| N2 | 0.3.0 on both collections pickles: nothing above LOW |
| F1 | 0.3.0 on planted streams: Fa, Fb, Fc PKL007 HIGH; Fd, Fe PKL001 CRITICAL |
| F2 | 0.2.1 on planted streams: Fd PKL007 without PKL001; Fc nothing above LOW (the two weaknesses this fixes) |
| H1 | gate: at least 10 published files downloaded |
| H2 | 0.2.1 gives PKL007 on at least 5 published files |
| H3 | 0.3.0 gives PKL007 on none of them, with no scan error |
| H4 | 0.3.0 keeps every rule 0.2.1 raised on each published file, except PKL007 |

## Grading

- If P1 fails, every other row is **not run**.
- A writer that raises or writes other files than listed is reported and
  its files are left out of G1, N1 and N2. If a scanner process fails, the
  scan rows are not run. Fewer than 10 downloaded files makes H1 fail and
  H2 to H4 not run.
- Reported, not graded: magic bytes; 0.2.1 results on the numpy and torch
  files; model-file-scan CLI exit codes; rules 0.3.0 adds on published files
  (newly resolved imports may be classified, for example PKL003 MEDIUM for a
  module outside the allowlist); published files where 0.3.0 still finds
  HIGH or CRITICAL; published files whose only HIGH under 0.2.1 was PKL007.
- **Release rule:** if P1, V1, S1, S2, G1, N1, F1, H3 and H4 hold, and
  `fetch.combined` is true, release **v0.52.2** with the job's patched files
  exactly as written. If a release ships after the job's fetch, a short
  full-suite job on the combined tree runs first. If any of those rows
  fails, there is no release, and the failure is written up first.

## Prior art

picklescan's `_list_globals` (main, read 2026-11-06) already resolves memo
fetches. It keeps a memo dict (`MEMOIZE` at the next index, `PUT`-style
opcodes at their key). It walks back from each `STACK_GLOBAL`, skipping
memo stores, and takes the two nearest opcodes. A missing memo key or any
opcode that is neither a string nor a memo fetch becomes "unknown", which
it scores as dangerous. So this fix brings our scanner up to the behaviour
picklescan already has; it is not a new idea. One detail differs: we treat a
memo slot that holds a non-string as unresolved, while picklescan converts
the stored value with `str()`. (We also skip `FRAME` and `PROTO`, which
change nothing on the stack.)

## Limits

One release of each writer and small objects. The Hub files are from the
most downloaded models on one day, not a random sample, and capped at 40 MB.
The resolver follows the stack only as far as the two operands of each
`STACK_GLOBAL`. It is not a full pickle virtual machine, and anything it
cannot follow stays PKL007. A clean result says our rules found nothing, not
that a file is safe to load. This check covers our own scanner, tests no
loader, and touches no live system beyond public downloads in setup.
