# r_serialized_scan: static checks for R .rds and .RData files

Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

`r_serialized_scan.py` reads R's serialization format itself, using only the
Python standard library. It needs no R installation and never loads, calls or
evaluates anything. It is meant for the same CI gate as the other scanners in
this repository: a pull request or model registry upload that adds an `.rds`
or `.RData` file gets checked before anyone runs `readRDS()` or `load()` on it.

```bash
python r_serialized_scan.py model.rds workspace.RData
```

Exit code 1 if any finding is high, 2 on usage or read errors, 0 otherwise.

## What it reports

| Rule | Severity | CWE | Meaning |
|------|----------|-----|---------|
| RDS001 | high | CWE-502 | Code that runs when a value is read: a promise that was never evaluated and whose code is a call or bytecode, or an active binding in a saved environment. |
| RDS002 | high | CWE-94 | Stored code calls a function that runs commands, evaluates or loads code, opens connections or deletes files (`system`, `eval`, `parse`, `source`, `dyn.load`, `library`, `download.file`, `url`, `unlink` and others). Applies in function bodies, bytecode constants, promises and quoted calls, including calls by name through `do.call`, `get`, `match.fun` and `pkg::fn`. |
| RDS003 | medium | CWE-829 | Reading the file reaches outside it. This covers a namespace reference or ALTREP class from a package that is not part of base R (R loads that package), or a persistent reference that needs a restore hook. |
| RDS004 | medium | CWE-693 | The file could not be fully decoded: it is not R serialization, uses an unsupported compression (zstd), is truncated, hits the nesting or size limits, or there are too many findings to list. Findings made before that point are kept. |

Evidence names where in the object the finding is, for example
`model.rds$family$linkinv > function: calls system()` or
`cache.rds > env$x: promise calls Sys.time()`.

## Why these checks

These come from R's own source (`src/main/serialize.c`, `src/main/altrep.c`,
`src/include/Defn.h`, read 31 October 2026):

- **Promises.** The reader decodes a promise cell like any pairlist cell. The
  only check is `checkNotPromise`, which `readRDS()` applies to the object it
  returns. A promise nested anywhere else, such as a binding in a saved
  environment, is restored as written, and its code runs the first time that
  binding is read. A promise whose value slot is already filled
  (evaluated), or whose code is only a constant or a symbol, runs nothing, so
  it is not reported. This matters because ordinary `glm()` objects carry
  such promises: `binomial()` leaves its default `link = "logit"` as an
  unevaluated promise of a constant.
- **Active bindings.** `ReadItem` copies the cell's `gp` bits from the stream
  without masking, so `ACTIVE_BINDING_MASK` (bit 15) survives. The binding's
  function runs each time the variable is read.
- **ALTREP and namespaces.** When an ALTREP class is not registered, R calls
  `R_FindNamespace` on the package named in the file. A namespace reference
  is resolved the same way, which loads that package and runs its load hooks.
  Base R's own classes (`compact_intseq` and others, package `base`) and the
  base-R packages are not reported.
- **Calls.** Functions keep their body as a call tree, or as bytecode whose
  constants hold the same calls. The scanner follows the symbol reference
  table so a call head written once and referenced later is still named.

Formats: XDR (`X`, the default), native binary (`B`) and ascii (`A`, with R's
octal and C escapes), serialization versions 2 and 3, `RDX2`/`RDX3`/`RDA`/`RDB`
workspace headers from `save()`, and gzip, bzip2 or xz compression.

## Prior art and what is new here

- **ModelAudit** (`modelaudit/scanners/r_serialized_scanner.py`, read
  31 October 2026) pulls printable strings out of the decompressed bytes and
  matches regular expressions such as `system(` or URLs. It does not decode
  the item tree, so it cannot tell a promise or a function from text that
  mentions one.
- **zurds** (github.com/pedrobtz/zurds, scanner merged 10 October 2026) is an
  R package with a C walker. It reports kinds of object (closure, bytecode,
  environment, promise, namespace, ALTREP, S4 and others), and its tests
  include a CVE-2024-27322-style promise. Its user-facing functions run in R.
  Its page does not describe naming the functions that stored code calls or
  checking active bindings, and it treats language objects as non-findings.
- **This module** decodes the same structure without R, in the Python CI
  where model-file scanning already runs. It names the risky call (and how it
  is reached: `do.call`, `get`, `::`), checks active bindings, and does not
  flag evaluated or constant promises. Ordinary model files still contain
  promises, closures and namespace references, so a scanner that flags every
  one of them would fail on every `glm` file.

## Honest limits

- The list of risky functions is a list. Code can reach a function by a
  computed name (`get(paste0("sys", "tem"))`), through a package function not
  on the list, or through `.Call` into native code. A clean result means none
  of these checks fired, not that the file is safe to load from an untrusted
  source.
- Saved package functions often call `eval` or `library` legitimately (for
  example, the model-frame code in `rpart`), so a file that stores whole
  package functions will get RDS002. That is a reason to look, not proof of
  harm.
- Nesting deeper than 180 levels (a very long formula, or a call with more than
  about 170 arguments inside bytecode) stops the decode with RDS004.
- The unit tests use hand-built streams. A check against files written by R
  itself is pre-registered in
  [research/PREREG_RDS_REALFILE.md](research/PREREG_RDS_REALFILE.md).
- Static review only: nothing is loaded or executed.
