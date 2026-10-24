<!--
Copyright 2026 Munim, Inc.
SPDX-License-Identifier: Apache-2.0
Text and data in this document are licensed CC BY 4.0.
Made with AI agents working in the name of MV2 of Munim, Inc.
-->

# Infection semantics: the axis that decides whether a model file is reported

*By MV2 of Munim, Inc. Made with AI agents working in his name. Source review only;
no scanner was run against any live or hosted system. Sources read 2026-10-24.*

This is the **third axis** of the keras-model-scan vs
[picklescan](https://github.com/mmaitre314/picklescan) comparison. The first two
compared *which* globals each tool knows:

- **Whole-module (wildcard) axis** — [`PICKLESCAN_COVERAGE_DIFF.md`](PICKLESCAN_COVERAGE_DIFF.md):
  of picklescan's whole-module denylist, keras-model-scan's top-package classifier
  covers 18 of 36.
- **Specific-name axis** — [`PICKLESCAN_SPECIFIC_AXIS.md`](PICKLESCAN_SPECIFIC_AXIS.md):
  picklescan's exact-name entries, including 9 `torch.*` gadget paths that
  keras-model-scan allowlists.

This axis asks a different and, for a user, more consequential question: **when a
global lands outside *both* of a tool's lists, does the tool report the file as a
problem?** That is the pass/fail signal a CI gate or a human actually reads.

## What each tool does with an out-of-list global

**picklescan** (verified in `src/picklescan/scanner.py`, `main`, 2026-10-24):

- Every scan entry point defaults to non-strict: `scan_pickle_bytes`, `scan_bytes`,
  `scan_file_path` and `scan_directory_path` all have `strict=False`.
- The per-global cascade is: `"unknown"` in the module/name → *Dangerous* (the
  STACK_GLOBAL evasion guard); else an exact `_unsafe_globals` match (or a `"*"`
  inherited from a dotted parent) → *Dangerous*; else an exact `_safe_globals`
  name match → *Innocuous*; else → **Suspicious**.
- Only *Dangerous* globals increment `issues_count`, and `infected_files` is set
  from `issues_count`. *Suspicious* globals increment a **separate**
  `suspicious_count` and **do not mark the file infected**:
  `ScanResult(globals, 1, issues_count, 1 if issues_count > 0 else 0, scan_err, suspicious_count)`.

So by default, a global whose module is not on either list is *Suspicious*: it is
listed in the result for a careful reader, but `infected_files` stays `0` — the
standard pass/fail signal does not fire.

**keras-model-scan** (`pickle_model_scan.py` 0.2.1): `_classify` returns `"unknown"`
for exactly that case, and `scan_pickle_bytes` emits it as a **PKL003 / MEDIUM**
finding — *"Import outside the known-safe allowlist"*. It is a surfaced finding, not
a silent pass. The design is **fail-towards-flagging**: anything not demonstrably on
the known-safe allowlist is surfaced for review.

## Why this is the first time it's been written down

picklescan, fickling and modelscan each document their own behaviour, but no project
publishes a side-by-side of two scanners on the *infection/report* axis — the point
at which the tools diverge not on vocabulary but on whether an unlisted code-exec
import causes the file to be reported at all. The two prior axes in this repo compared
list membership; this one compares outcomes. The result is reproducible by reading two
open-source files, with no execution against any system.

## The divergence, reproducibly

[`infection_semantics_diff.py`](infection_semantics_diff.py) encodes a faithful,
source-dated **model** of each tool's classifier and prints a provenance-labelled
matrix; [`test_infection_semantics_diff.py`](test_infection_semantics_diff.py) pins
the invariants. The structural core (asserted for a synthetic never-listed module, so
it does not depend on either list's exact contents):

| case | picklescan (default) | keras-model-scan | file reported? |
|---|---|---|---|
| `os.system` | Dangerous → **infected** | dangerous → PKL001/CRITICAL | both: yes |
| `collections.OrderedDict` | Innocuous | benign | both: no (correct) |
| `numpy.f2py.compile` | Dangerous → infected | rce_gadget → PKL001 | both: yes |
| *unlisted* code-exec module | **Suspicious → not infected** | unknown → **PKL003/MEDIUM** | **picklescan: no · keras: yes** |

The last row is the finding: for any import outside both lists, picklescan's default
run does not set `infected_files`, while keras-model-scan always surfaces it.

## Honest limits

- These are **models of each tool's source**, not the live tools; they are pinned to
  the code read on 2026-10-24 and will drift if either project changes.
- This is **not a vulnerability report**. picklescan's non-strict default and its
  *Suspicious* level are a deliberate, documented design choice that trades recall
  for fewer false positives; picklescan also offers `strict=True`. The contribution
  here is the explicit side-by-side on the pass/fail axis, not a claim that either
  behaviour is a bug.
- The exhaustive enumeration of *which real modules* fall in the last row (candidates
  include `importlib`, `multiprocessing`, `platform`, `signal`, `dill`, and
  module-level `cloudpickle`, all in keras-model-scan's `DANGEROUS_MODULES`) is being
  produced by a compute job that introspects the pip-installed picklescan directly, to
  avoid any transcription error; the verified counts will be added here.

## Reproduce

```
python infection_semantics_diff.py            # prints the JSON matrix
python -m unittest test_infection_semantics_diff -v
```
