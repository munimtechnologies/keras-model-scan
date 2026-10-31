# Real-file check: R .rds/.RData scanner, October 2026

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.

`r_serialized_scan.py` was written and unit-tested against hand-encoded
serialization streams. This check asks whether it reads files written by R
itself the same way, and whether it stays quiet on ordinary data and model
objects, which are full of closures, promises and environments. The
expectations were written down before the job ran, in
[research/PREREG_RDS_REALFILE.md](research/PREREG_RDS_REALFILE.md).

The job (`rds-realfile-v1`) ran in a sealed `r-base:latest` container on
31 October 2026 (UTC). Network was used only for `apt-get install python3`
during setup; there was none while files were built and scanned. R wrote every
file with `saveRDS()` or `save()` (`compete/rds-realfile/make_files.R`).
Nothing was read back, called or forced, and the functions that mention
`system()` were never called. A file R failed to build would have counted as
NOT TESTED; none did (all 15 builds report `ok`).

**Result: 15 of 15 pre-registered predictions held.** No false alarm on the
eight ordinary files, and each crafted case was flagged by exactly the
predicted rule with the predicted evidence.

Versions: `R version 4.6.2 (2026-10-29)`, `rpart 4.1.27`,
`r_serialized_scan 0.1.0`.

| # | File (how R wrote it) | Prediction | Result | Evidence |
|---|------------------------|-----------|--------|----------|
| R1 | `plain.rds`: a data frame | no findings | **PASS** | `[]` |
| R2 | `lm.rds`: an `lm()` fit | no findings | **PASS** | `[]` |
| R3 | `glm.rds`: a `glm(..., family = binomial())` fit | no findings | **PASS** | `[]` |
| R4 | `rpart.rds`: an `rpart()` fit | only RDS003, naming `rpart` | **PASS** | RDS003 `rpart.rds[[9]][[1]]: namespace rpart 4.1.27` |
| R5 | `fn_system.rds`: `function(cmd) system(cmd)` | exactly one RDS002, `calls system()` | **PASS** | `fn_system.rds > function: calls system()` |
| R6 | `fn_system_bc.rds`: R5 after `compiler::cmpfun` | exactly one RDS002, `calls system()` | **PASS** | `fn_system_bc.rds > function: calls system()` |
| R7 | `promise.rds`: `delayedAssign("x", Sys.time())` in an environment | exactly one RDS001, `promise calls Sys.time()` | **PASS** | `promise.rds > env[[5]]$x: promise calls Sys.time()` |
| R8 | `active.rds`: `makeActiveBinding("x", ...)` in an environment | exactly one RDS001, `active binding` | **PASS** | `active.rds > env[[5]]$x: active binding` |
| R9 | `pkgfun.rds`: `list(f = rpart::rpart)` | RDS002 with an eval-family call and RDS003 naming `rpart`, no RDS004 | **PASS** | RDS003 `namespace rpart 4.1.27`; RDS002 `calls eval.parent()` |
| R10 | `fn_ascii.rds`: R5 with `ascii = TRUE, compress = FALSE` | exactly one RDS002, `calls system()` | **PASS** | `fn_ascii.rds > function: calls system()` |
| R11 | `plain_xz.rds`: R1, `compress = "xz"` | no findings | **PASS** | `[]` |
| R12 | `plain_bz2.rds`: R1, `compress = "bzip2"` | no findings | **PASS** | `[]` |
| R13 | `workspace.RData`: `save(df, fit)` with an `lm` fit | no findings | **PASS** | `[]` |
| R14 | `plain_v2.rds`: R1, `version = 2` | no findings | **PASS** | `[]` |
| R15 | `altrep.rds`: `saveRDS(1:10)` | no findings | **PASS** | `[]` |

The file headers confirm the formats were the ones intended: gzip
(`1f8b...`) by default, xz (`fd377a58...`) for R11, bzip2 (`425a68...`) for
R12, and an uncompressed ascii stream (`A\n3\n...`) for R10.

What the two calibration rows show:

- **R3** (no false alarm): a `binomial()` family keeps its link as an
  unevaluated promise of a constant, and its functions call `.Call`. The
  scanner reported neither, as designed: RDS001 reports a promise only when
  its code is a call or bytecode.
- **R9** (an expected alarm): saving a whole package function trips RDS002,
  because `rpart()` really does call `eval.parent()`. A saved package
  function carries its code, so a reviewer should see it.

R6 matters because byte-compiled closures keep their source only in the
bytecode constant pool; the call was found there. R7 and R8 matter because
R's reader refuses a promise only at the top level of a file: a promise or
active binding inside an environment is restored as it is.

The scanner's own 27 unit tests also passed in the same container.

## What this means in practice

R4 shows that an ordinary `rpart` model saved with `saveRDS()` gets one
**medium** RDS003 finding: its stored functions refer to the `rpart`
namespace, so reading the file loads that package. That is accurate, and it
is something a reviewer should know, but it is not a red flag on its own.
`model-file-scan` fails on medium findings by default, so a project that
ships fitted models from packages such as `rpart` should gate on
`--fail-on high`, where RDS001 (promises, active bindings) and RDS002 (risky
calls in stored code) still stop the build.

## Honest limits

- One file per prediction, built by this job, not a corpus of published
  `.rds` files. This is not a false-positive rate on real-world data.
- R15 passed, but the job did not separately confirm that R wrote `1:10` as a
  compact ALTREP item rather than a plain integer vector; either form should
  give no findings.
- One R release (4.6.2) and one non-base package (`rpart`).
- A finding says a file carries code or loads a package a reviewer should
  look at. It does not show that any program reading the file is exploitable.
- Static review only: nothing was loaded, evaluated or executed.
