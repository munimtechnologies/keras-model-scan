# Cross-coverage audit: does keras-model-scan resist the picklescan CVE-2026-56315 bypass?

**Scope:** source review of `pickle_model_scan.py` on `main` (release v0.47.0,
`pickle_model_scan` 0.2.1) against the public advisory for **CVE-2026-56315**. No code
was executed and no system was probed; this is a read of two open files plus a public CVE
record. Work produced by AI agents in the name of MV2, Munim, Inc.; see the note at the end.

## TL;DR

- **CVE-2026-56315** (GHSA-g38g-8gr9-h9xp, PYSEC-2026-4134, **CWE-184 "Incomplete List of
  Disallowed Inputs"**, CVSS v4.0 9.3, fixed in **picklescan 1.0.4**) is an RCE bypass of
  *picklescan*: it failed to block "at least seven" Python standard-library modules that
  expose functions giving direct command execution, so a crafted pickle importing one of
  them passed picklescan's validation **entirely**. Named modules include `uuid`, `imaplib`,
  `_osx_support`, `_aix_support`, and `_pyrepl.pager`.
- **keras-model-scan does not have this silent-pass behaviour.** Its pickle scanner is
  *allowlist-default-flag*: any resolvable global that is neither on the benign allowlist nor
  on the dangerous denylist is reported as **PKL003 (MEDIUM, "Import outside the known-safe
  allowlist")**, and PKL003 fires for **every** such import. All five named bypass modules
  land there — they are surfaced for review, not passed as safe.
- **Honest residual gap (severity, not detection):** PKL003 does not escalate when the
  unknown import is an *actively-invoked* RCE gadget. So a real gadget in an unlisted module,
  reduced during unpickling, is reported **MEDIUM**, not CRITICAL. We surface it; we
  under-rate it. A fix spec that avoids the whack-a-mole trap that caused CVE-2026-56315 is
  below.

## Why this is the right question

CVE-2026-56315's root cause (CWE-184) is structural, not a single missing name: a scanner
that decides "safe unless the import is on my denylist" is only ever as complete as its
denylist, and the Python standard library keeps offering new command-execution surfaces.
picklescan's 1.0.4 fix added the newly-found modules to its denylist — which closes these
specific modules but leaves the same shape of gap for the next unlisted one. The durable
question for any competing scanner is therefore not "did you also add `uuid`?" but **"what
is your default verdict for an import you have never enumerated?"**

## What keras-model-scan actually does (verified)

The pickle scanner classifies each resolvable global into one of four buckets and emits a
finding per bucket:

| classification | basis | finding |
|---|---|---|
| `dangerous` | module/name in fixed `DANGEROUS_MODULES` / `DANGEROUS_BUILTINS` | **PKL001** (escalates to CRITICAL when execution opcodes are present) |
| `rce_gadget` | special-cased gadget names / `GADGET_MODULE_PREFIXES` | **PKL005** (escalates on execution opcodes) |
| `benign` | top package in fixed `BENIGN_TOP` allowlist | no finding |
| `unknown` | **everything else** | **PKL003 (MEDIUM)** — fires for every resolvable unknown import, regardless of opcodes |

The decisive property is the last row: an import the tool has never enumerated is **not**
treated as safe. It defaults to a surfaced MEDIUM finding that asks the reviewer to "confirm
this module belongs in a model file." That inverts the CWE-184 failure mode of CVE-2026-56315.

### The five named bypass modules, cross-checked

None of the CVE-2026-56315 modules appear in `DANGEROUS_MODULES` or in the `BENIGN_TOP`
allowlist, so each is classified `unknown` → **PKL003 MEDIUM**:

| module (from the advisory) | in DANGEROUS_MODULES? | in BENIGN_TOP? | keras-model-scan verdict |
|---|---|---|---|
| `uuid` | no | no | PKL003 MEDIUM (surfaced) |
| `imaplib` | no | no | PKL003 MEDIUM (surfaced) |
| `_osx_support` | no | no | PKL003 MEDIUM (surfaced) |
| `_aix_support` | no | no | PKL003 MEDIUM (surfaced) |
| `_pyrepl.pager` (top pkg `_pyrepl`) | no | no | PKL003 MEDIUM (surfaced) |

So the pickle file that defeats picklescan < 1.0.4 would, scanned by keras-model-scan, raise
a MEDIUM finding on the exact import that carries the payload. It would not receive a clean
bill of health.

## The honest residual: a severity-precision gap, not a miss

PKL003 is emitted the same way whether or not execution opcodes (`REDUCE`, `BUILD`, `INST`,
`OBJ`, `NEWOBJ`, `NEWOBJ_EX`) are present; the `exec_ops` signal only escalates the
`dangerous` and `rce_gadget` buckets. CVE-2026-56315's modules are genuine RCE gadgets, so a
pickle that actually *invokes* one would, ideally, be rated higher than "please review."
Today it is MEDIUM. This is a **severity-rating** limitation, not a detection miss — the
distinction that this toolkit's audits keep insisting on (detection vs. recall vs.
attribution): the import is detected and reported; its danger is under-rated.

### Fix spec (needs a compute slot; stated carefully to avoid a new CWE-184)

1. **CVE-map backfill (clean, low-risk):** add CVE-2026-56315 / GHSA-g38g-8gr9-h9xp
   (CWE-184, picklescan, fixed 1.0.4) to `model_file_cve_map.json`, keyed to the pickle
   unknown-import rule, as the public reference for why out-of-allowlist imports matter.
2. **Behavioural severity escalation (the real fix) — do NOT just grow the denylist.**
   Adding `uuid`/`imaplib`/... to `DANGEROUS_MODULES` would repeat picklescan's mistake: it
   fixes these five and nothing else. The CWE-184-immune move is behavioural: escalate an
   `unknown`-classified global to **HIGH** (e.g. a new `PKL008`) **only when that specific
   global is the callable being reduced/instantiated** — i.e. the unknown name is the operand
   consumed by a `REDUCE`/`NEWOBJ`/`INST`/`OBJ`, not merely that execution opcodes exist
   somewhere in the stream.
   - **Important false-positive caveat:** a naive "unknown import + any exec_ops" rule would
     escalate almost every real pickle, because normal pickles are full of `REDUCE`/`BUILD`.
     The escalation must be *per-global call tracking* (this unknown global is actually
     invoked), which is more work than the current stream-level `exec_ops` counter and is why
     this is spec'd rather than shipped here.
   - **Test:** a pickle that reduces an `uuid`/`imaplib` global → HIGH; the same unlisted
     import merely referenced (not reduced) → MEDIUM (unchanged); a benign allowlisted import
     → no finding (unchanged).

## Prior art / why this is new

The toolkit's recent pickle work covered a different picklescan issue (the STACK_GLOBAL
off-by-one, CVE-2025-71325) and a numpy-allowlist CVE (CVE-2025-71355), and the r188
BENIGN_TOP audit covered *over-trust of allowlisted packages*. This is the first cross-map of
**CVE-2026-56315** (the CWE-184 stdlib-module bypass, disclosed 2026) against this scanner,
establishing the opposite-direction result: the allowlist-default-flag posture means the
under-enumeration that broke picklescan surfaces here as PKL003 rather than passing silently,
while isolating the residual as a severity-rating gap with a false-positive-aware fix.
CVE-2026-56315 is not in `model_file_cve_map.json` and is not referenced in the scanner
source as of v0.47.0.

## Honest limits

- Verified by **source review** of two open files plus the public CVE/GHSA record; **nothing
  was executed**. Set membership (which modules are/are not in `DANGEROUS_MODULES` and
  `BENIGN_TOP`) was read from the source, not confirmed by running the scanner.
- This audit does **not** re-prove that the named modules are exploitable gadgets; it relies
  on the upstream advisory for that and reasons only about how this scanner *classifies and
  rates* them.
- Whether any specific gadget is reachable inside a particular loader is out of scope and
  would need a sealed local proof-of-concept.

---

*This document was produced by AI agents working in the name of MV2, Munim, Inc. It is part
of the Apache-2.0 licensed `keras-model-scan` project; the prose may be reused under CC BY
4.0. It analyses a defensive scanner and public CVE records only — no exploit code, and no
live or third-party system was touched.*
