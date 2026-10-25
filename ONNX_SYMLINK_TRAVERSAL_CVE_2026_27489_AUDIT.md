# ONNX external-data symlink traversal (CVE-2026-27489): fix audit and a static-detection gap

*By MV2 of Munim, Inc. Made with AI agents working in MV2's name. Apache-2.0.*
*Source review only — no code was executed against any system, and no live or hosted
service was probed. Every claim is from reading open-source files at pinned tags.*

## Summary

CVE-2026-27489 (GHSA-3r9x-f23j-gc73, PYSEC-2026-2239; fixed in **onnx 1.21.0**) is a
symlink path-traversal in ONNX external-data loading: a model whose external-data
`location` is `symlink_subdir/real_file.data`, where `symlink_subdir` is a symbolic
link on the loading host pointing outside the model directory, let the loader read an
arbitrary file. This audit answers two questions the project had not yet resolved:

1. **Is the 1.21.0 fix complete, or is it another entry in the ONNX path-check bypass
   lineage** (CVE-2022-25882 -> CVE-2024-27318 -> CVE-2026-27489), each of which
   bypassed its predecessor's check? **Finding: the 1.21.0 fix is robust** against the
   nested/absolute/Windows-drive/`..` variants. It is a real fix, not a partial one.
   This is an honest negative for vulnerability hunting.
2. **Does MV2's `onnx_external_data_scan.py` detect this class?** **Finding: no — and by
   construction it cannot detect the symlink itself,** because the malicious element
   lives on the victim's filesystem, not in the model file. But a *necessary
   precondition* of the whole class — a `location` that traverses into a subdirectory —
   is statically visible in the model and is currently unflagged. That is a concrete,
   bounded scanner gap, addressed here by a proposed informational rule **OED006**.

## 1. The fix, read at the v1.21.0 tag

CVE-2026-27489's root cause (per NVD/GHSA): the pre-fix load path validated external
data with `is_symlink()`, which only inspects the **final** path component. For
`symlink_subdir/real_file.data`, the final component `real_file.data` is an ordinary
file, so `is_symlink()` passed while `symlink_subdir` silently redirected the resolved
path out of the model directory.

The fix (commit `4755f8053928dce18a61db8fec71b69c74f786cb`) moves the authoritative
load-time validation into the C++ checker. In `onnx/external_data_helper.py` at
`v1.21.0`, `load_external_data_for_tensor` now resolves the path through the C++
routine and opens it with `O_NOFOLLOW` as defense-in-depth:

- Path resolution is delegated to `c_checker._resolve_external_data_location(base_dir,
  info.location, tensor.name)`.
- The open uses `os.O_RDONLY | os.O_NOFOLLOW` (where available), then `os.fdopen`.

The Python-side `_validate_external_data_path` (realpath containment + final-component
symlink + hardlink-count) is used on the **save** path. On the **load** path the
containment work is done by the C++ `resolve_external_data_location` in
`onnx/checker.cc`, which I read in full at `v1.21.0`. Its defenses, in order:

- **Absolute-path reject.** `file_path.is_absolute()` fails the check. On Windows the
  path is built from a wide string, so a drive-letter path (`C:\...`) is absolute and is
  rejected by the same branch. (Covers the absolute / Windows-drive axis.)
- **`..` reject.** After `lexically_normal().make_preferred()`, the native string is
  searched for `..` and rejected if present. (Covers the parent-traversal axis.)
- **Final-component symlink reject.** `std::filesystem::is_symlink(data_path)` — the
  same limited check as before, now only one layer of several.
- **Canonical containment (the real fix for intermediate symlinks).** It computes
  `weakly_canonical(base_dir)` and `weakly_canonical(data_path)`, appends a path
  separator to the canonical base, and requires `canonical_data.find(canonical_base) ==
  0`. `weakly_canonical` resolves symlinks across **every existing path component**, so
  an intermediate `symlink_subdir` is resolved to its real target before the containment
  test — exactly the case `is_symlink()` missed. The trailing-separator step also
  defeats the classic sibling-prefix bypass (`/base` vs `/base-evil`).
- **Regular-file + hardlink-count checks** further constrain the target.

### Why this is not another lineage bypass

The earlier bypasses (CVE-2024-27318 over CVE-2022-25882) worked because each check
reasoned about the *lexical* path string or a *single* component while the filesystem
resolved something else. `weakly_canonical` closes that gap categorically: it asks the
filesystem to resolve the whole path (all symlinks, all `.`/`..` that survive) and then
compares real prefixes. I could not construct a nested-symlink, absolute, Windows-drive,
or `..` location that passes this on the load path. **The fix holds.**

### Two honest residuals (documented, low value, not reportable)

- **TOCTOU.** The C++ check resolves and validates, then Python `os.open`s the returned
  path. `O_NOFOLLOW` guards only the final component at open time, so a local attacker
  able to *write into the model directory concurrently during load* could swap an
  intermediate directory for a symlink between check and open. This needs local
  concurrent write access to the trusted model directory — a weak, non-default threat
  model, and a generic property of check-then-open, not specific to this fix.
- **`#`-prefixed in-memory locations** skip the canonical/regular-file/hardlink checks
  (by design, for container in-memory tensors). They do not skip the final-component
  symlink check, and `#`-locations are intercepted before any file `open`, so this is not
  a traversal path. Noted for completeness.

Both are intentionally **not** huntr material: CVE-2026-27489 is published and fixed,
and neither residual is a default-settings arbitrary read.

## 2. The static-detection gap in `onnx_external_data_scan.py`

MV2's `onnx_external_data_scan.py` (v0.1.0) reads only the `external_data` `location`
strings from the protobuf and never opens a referenced file. Its five rules:

| Rule | Severity | Fires when the `location`... |
|------|----------|------------------------------|
| OED001 | HIGH | has a `..` component (split on `/` or `\`) |
| OED002 | HIGH | is absolute (`/`, `\`, or a drive letter) |
| OED003 | HIGH | matches a URL scheme (`scheme://`) |
| OED004 | HIGH | contains a NUL or control byte (`ord < 0x20`) |
| OED005 | MEDIUM | contains a backslash separator |

**The CVE-2026-27489 attack location is `symlink_subdir/real_file.data`.** Trace it
against every rule:

- OED001: no `..` component -> does not fire.
- OED002: relative, no drive letter -> does not fire.
- OED003: no `scheme://` -> does not fire.
- OED004: printable ASCII only -> does not fire.
- OED005: forward slash, no backslash -> does not fire.

So the scanner returns a **clean** result on a model crafted for the exact published
CVE. (The module's own docstring already warns a clean scan "guarantees nothing"; this
pins down one concrete thing a clean scan does not cover.)

### Why this is a *bounded* gap, not a false sense of a missed vuln

The malicious ingredient — `symlink_subdir` being a symlink that escapes the model
directory — exists on the **loading host's filesystem**, not in the shipped model.
A static scanner that sees only the model file **cannot** know whether `symlink_subdir`
will resolve to a symlink on some future victim's disk. So detecting the symlink *as a
symlink* statically is impossible in principle, and claiming otherwise would be
dishonest. What the scanner *can* see is the **precondition**: the whole class requires
the `location` to reference at least one **intermediate directory component**
(`subdir/file`). A conventional external-data file sits next to the model with a
single-component location (`weights.bin`, `model.data`); a subdirectory-traversing
location is unusual and is the only in-file footprint the class leaves.

### Proposed rule OED006 (informational / low)

Add a rule that flags a `location` which, after the existing OED001/OED002/OED005
checks, still contains a path separator (i.e. references a subdirectory):

- **ID/severity:** OED006, **LOW** (informational — attack *surface*, not a vuln in the
  file itself).
- **CWE / CVE context:** CWE-61 (symlink following); cite CVE-2026-27489.
- **Condition (precise, so a future run can implement without ambiguity):** after
  OED001 (`..`) and OED002 (absolute) have been evaluated and have *not* fired, if
  `len([p for p in re.split(r"[\\/]", value) if p]) > 1` then emit OED006. (Backslash
  variants will also trip OED005; OED006 is what catches the clean forward-slash case.)
- **Message:** "external-data location references a subdirectory
  (`{location}`); if loaded on onnx < 1.21.0, or by a loader that skips the onnx
  checker, an intermediate directory that is a symlink on the loading host can escape
  the model directory (CVE-2026-27489 class). Not detectable statically; verify the
  loader is onnx >= 1.21.0."
- **False-positive note:** legitimate multi-file exports (e.g. a `weights/` layout) will
  trip OED006, which is why it is LOW/informational, not HIGH.

Also add **CVE-2026-27489** to the ONNX section of the CVE map and to
`ONNX_EXTERNAL_DATA_SCAN.md`, with the plain statement that its symlink axis is a
host-filesystem property outside static model-file scanning and that the correct primary
defense is onnx >= 1.21.0.

## Why this is new

Prior project work (`ONNX_EXTERNAL_DATA_SCAN.md`, the external-data corpus and KEY
scan) mapped the lexical traversal axes (`..`, absolute, URL, control byte, backslash)
and cited CVE-2022-25882 and CVE-2026-55832. No prior work in this repo — and, from a
prior-art search, no public write-up — audits the **CVE-2026-27489 symlink fix against
the ONNX bypass lineage** and states, with the source reasoning, that a static
model-file scanner **cannot** detect the symlink axis while the **subdirectory
precondition can** be. That boundary is the contribution: it tells a scanner user
exactly what OED001-005 do and do not cover for this CVE, and it gives a precise,
false-positive-aware rule (OED006) to cover the one statically-visible part.

## Reproduction (reading only)

- Fix commit: `github.com/onnx/onnx/commit/4755f8053928dce18a61db8fec71b69c74f786cb`
- Post-fix load path: `onnx/external_data_helper.py` and
  `resolve_external_data_location` in `onnx/checker.cc` at tag `v1.21.0`.
- Scanner under audit: `onnx_external_data_scan.py` (v0.1.0) and
  `ONNX_EXTERNAL_DATA_SCAN.md` in this repo.
- Advisory: GHSA-3r9x-f23j-gc73; NVD CVE-2026-27489; PYSEC-2026-2239. Fixed onnx 1.21.0.

## Honest status

$0 earned. This is a completeness + gap-analysis result: the upstream fix is confirmed
robust (a negative for hunting), and the scanner gap is bounded and specified but **not
yet implemented** — implementing OED006 touches the live scanner module and its test,
which needs a sealed compute job; it is queued behind the project's current congested
compute queue and will land in a later run.
