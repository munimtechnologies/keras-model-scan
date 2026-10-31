# Pre-registration: r_serialized_scan on files written by R

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 31 October 2026 (UTC), before the check was run.

## Question

Does `r_serialized_scan.py` 0.1.0 read files written by R itself the way its
hand-built unit tests say it does? Does it stay quiet on ordinary data and
model files, which contain closures, promises and namespace references?

## Setup

- Job `rds-realfile-v1`: a sealed `r-base:latest` container. Network is used
  only for `apt-get install python3` during setup, and there is none while
  files are built and scanned.
- `compete/rds-realfile/make_files.R` writes every file with `saveRDS()` or
  `save()`. Nothing is read back, called or forced. The functions that
  mention `system()` are never called.
- `compete/rds-realfile/realfile_check_rds.py` scans each file with
  `scan_file` and grades it. If R fails to build a file, that row counts as
  **NOT TESTED**, never as a pass. The R version is recorded.

## Predictions

| # | File (how R wrote it) | Prediction |
|---|------------------------|-----------|
| R1 | `plain.rds`: `saveRDS(data.frame(...))` | no findings |
| R2 | `lm.rds`: an `lm()` fit | no findings |
| R3 | `glm.rds`: a `glm(..., family = binomial())` fit | no findings |
| R4 | `rpart.rds`: an `rpart()` fit on `kyphosis` | no RDS001, RDS002 or RDS004; at least one RDS003 naming `rpart` |
| R5 | `fn_system.rds`: `function(cmd) system(cmd)` | exactly one finding, RDS002, `calls system()` |
| R6 | `fn_system_bc.rds`: the same function after `compiler::cmpfun` | exactly one finding, RDS002, `calls system()` (found in bytecode) |
| R7 | `promise.rds`: an environment with `delayedAssign("x", Sys.time())` | exactly one finding, RDS001, `promise calls Sys.time()` |
| R8 | `active.rds`: an environment with `makeActiveBinding("x", ...)` | exactly one finding, RDS001, `active binding` |
| R9 | `pkgfun.rds`: `list(f = rpart::rpart)` | RDS002 with an `eval`-family call and RDS003 naming `rpart`, no RDS004 |
| R10 | `fn_ascii.rds`: R5's function with `ascii = TRUE, compress = FALSE` | exactly one finding, RDS002, `calls system()` |
| R11 | `plain_xz.rds`: R1 with `compress = "xz"` | no findings |
| R12 | `plain_bz2.rds`: R1 with `compress = "bzip2"` | no findings |
| R13 | `workspace.RData`: `save(df, fit)` with an `lm` fit | no findings |
| R14 | `plain_v2.rds`: R1 with `version = 2` | no findings |
| R15 | `altrep.rds`: `saveRDS(1:10)` (a compact ALTREP sequence) | no findings |

R3 is the calibration row. A `binomial()` family keeps its default link as an
unevaluated promise of the constant `"logit"`, and its functions call `.Call`.
Neither should be reported. R9 is a calibration row in the other direction:
a whole package function is expected to trip RDS002, because `rpart()`
builds its model frame with `eval.parent`.

## Decision rule

Each row is PASS or FAIL as written above. Any FAIL is reported as a failure
with the scanner's output. If a FAIL comes from the scanner, the module is
fixed in a dated correction, and the check is re-run under a new job version
with these predictions unchanged.
