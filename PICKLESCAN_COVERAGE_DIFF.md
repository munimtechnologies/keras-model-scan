<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright 2026 Munim, Inc. Made with AI agents working in MV2's name.
-->
# picklescan denylist vs top-package classification: a coverage differential

**Made with AI** (agents working in MV2's name, Munim, Inc.). Honest, reproducible,
source-review only. Regenerate the table with `python picklescan_coverage_diff.py`.

keras-model-scan's pickle scanner classifies a pickled `GLOBAL` / `STACK_GLOBAL`
operand by its **top-level package** (`module.split(".", 1)[0]`), not by matching the
full `module.name` pair against an exact denylist the way [picklescan](https://github.com/mmaitre314/picklescan)
does. Top-package classification has one proven advantage — it is **immune to the
submodule-import bypass class** (CVE-2025-10157): importing `asyncio.unix_events` still
has top package `asyncio`, so exact-match evasion does not work against it.

But resilience is not breadth. A top-package classifier can only flag a package it has
been told about. This note measures the gap with data: of the modules picklescan marks
**entirely** unsafe (its `"*"` wildcard entries — every attribute is a gadget), how many
does keras-model-scan's classifier cover today, and which does it miss?

As far as a prior-art search shows (picklescan, fickling and modelscan ship no such
comparison), this is the **first published module-by-module coverage differential**
between the two classification strategies.

## Result: 18 of 36 covered, 18 gaps (live, keras-model-scan 0.2.1)

| picklescan wildcard-unsafe module | keras-model-scan top-package coverage |
|---|---|
| `_aix_support` | GAP |
| `_osx_support` | GAP |
| `_pickle` | GAP |
| `_pyrepl` | GAP |
| `aiohttp` | GAP |
| `asyncio` | covered |
| `bdb` | covered |
| `cProfile` | GAP |
| `commands` | covered |
| `ctypes` | covered |
| `distutils.file_util` | GAP |
| `httplib` | GAP |
| `nt` | covered |
| `numpy.f2py` | covered (gadget prefix) |
| `numpy.testing._private.utils` | GAP |
| `os` | covered |
| `pdb` | covered |
| `pickle` | covered |
| `pip` | GAP |
| `posix` | covered |
| `profile` | GAP |
| `pty` | covered |
| `pydoc` | GAP |
| `requests.api` | GAP |
| `runpy` | covered |
| `shutil` | covered |
| `socket` | covered |
| `ssl` | GAP |
| `subprocess` | covered |
| `sys` | covered |
| `test` | GAP |
| `timeit` | covered |
| `urllib.request` | GAP |
| `uuid` | GAP |
| `venv` | GAP |
| `webbrowser` | covered |

**Gaps (18):** `_aix_support`, `_osx_support`, `_pickle`, `_pyrepl`, `aiohttp`,
`cProfile`, `distutils.file_util`, `httplib`, `numpy.testing._private.utils`, `pip`,
`profile`, `pydoc`, `requests.api`, `ssl`, `test`, `urllib.request`, `uuid`, `venv`.

Three of those gaps already have detectors **queued** and verified in a sealed sandbox:
`cProfile` and `profile` (release v0.48.0) and `pip` (CVE-2025-1716). With those applied
the count becomes **21 of 36 covered, 15 gaps** — see the `include_pending` table the
generator prints.

## This is not one-directional — each tool covers things the other misses

The differential above counts picklescan's wildcard modules only. Looking the other way,
keras-model-scan's top-package rule is **more complete** than picklescan's exact-match
denylist on several families:

- **`idlelib`** — picklescan enumerates specific IDLE entry points
  (`idlelib.run.Executive.runcode`, `idlelib.pyshell...`, etc.); keras flags the whole
  `idlelib` package, so it also covers helpers picklescan has not enumerated.
- **`cloudpickle` / `dill`** — keras treats the whole packages as dangerous; picklescan
  lists only `cloudpickle.cloudpickle`'s specific reconstruction helpers.
- **builtins** — keras's `DANGEROUS_BUILTINS` flags 14 names (`eval`, `exec`, `compile`,
  `open`, `__import__`, `input`, `breakpoint`, `getattr`, `setattr`, `globals`, `vars`,
  `memoryview`, `exit`, `quit`); picklescan's `builtins` entry lists 7.
- **`numpy.f2py`** — one gadget prefix subsumes two separately-assigned CVEs
  (CVE-2025-71339, CVE-2025-71372) that picklescan patched as two denylist additions.
- **submodule bypass** — keras is structurally immune to CVE-2025-10157; picklescan had
  to patch it.

## The honest takeaway

Top-package classification is **strictly more resilient** to evasion (submodule bypass)
and **strictly broader per covered package**, but its breadth across the whole gadget
space is bounded by its package list — today that list covers half of picklescan's
fully-unsafe modules. The gap list is therefore a concrete, source-backed roadmap: each
entry is a package picklescan already treats as entirely unsafe, so adding it to
`DANGEROUS_MODULES` is a defensible, non-speculative coverage win. High-value next adds
(reachable, non-legacy): `pip` (queued), `ssl`, `aiohttp`, `requests.api`,
`urllib.request`, `distutils.file_util`, `pydoc`, `_pickle`.

Prior art checked: picklescan's own `_unsafe_globals` (the denylist being compared),
fickling's analysis passes, and modelscan's scanner — none ship a module-level coverage
differential between an exact-match denylist and a top-package classifier.
