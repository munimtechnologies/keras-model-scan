# The `.keras` archive-extraction path across Keras releases: a version-by-version source review

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Part of munimtechnologies/keras-model-scan. Made with AI agents working in the
     name of MV2, Munim, Inc. (mv2@munimtech.com). Source review only; no execution,
     no live target, no network probing. All claims are from reading open-source files. -->

**TL;DR.** A `.keras` model file is a ZIP archive, and loading it extracts that
archive to a temp directory inside `DiskIOStore`. This note traces that extraction
path across every Keras 3 release line and asks one question per version: *can a
crafted `.keras` file abuse extraction to write outside the temp directory, or
otherwise misbehave at load time?* The honest answer for the **model-load** path is
**no arbitrary write on any released version** — but the reasoning is subtler than
"Keras validates members," and one low-severity robustness bug is still reachable on
the version GitHub currently serves as "latest." A separate, more serious
arbitrary-write issue (CVE-2026-11816) is real, but it lives in the **`get_file`
tar** path, which model loading never takes.

This corrects and sharpens earlier notes in this repo
(`KERAS_ASSET_LOAD_PATH_IO_SURFACE.md`), which reviewed only the `master` branch and
attributed the safety of the zip path to Keras's own member filter. On the releases
users actually run, the real backstop is CPython, not Keras.

## Why the "latest release" everyone reads is misleading

`GET https://api.github.com/repos/keras-team/keras/releases/latest` returns
**`v3.12.4`** (published `2026-07-29T22:19:46Z`). But that is *not* the newest Keras.
Listing `/releases?per_page=15` shows (newest version number first):

```
v3.15.1  2026-07-29T18:25:38Z   <- highest version number
v3.12.4  2026-07-29T22:19:46Z   <- GitHub "latest" (published ~4h after v3.15.1)
v3.15.0  2026-06-24
v3.14.1  2026-05-07
v3.14.0  2026-04-03
v3.13.2  2026-01-30
v3.12.3  2026-06-26
...
```

GitHub's `/releases/latest` returns the release with the most recent `published_at`,
not the highest semantic version. `v3.12.4` is a back-port patch to the 3.12 line that
happened to be *published last*, so it shadows `v3.15.1`. **Any automated check that
treats `/releases/latest` as "the current version" will silently miss the entire
3.13 / 3.14 / 3.15 series — including several security fixes.** Tools (including model
scanners and dependency checkers) should enumerate `/releases` and sort by semantic
version, or read `/tags`.

## The extraction call, version by version

All facts below are from reading `keras/src/saving/saving_lib.py` and
`keras/src/utils/file_utils.py` at each tag on `raw.githubusercontent.com`.

**`DiskIOStore` is where a loaded `.keras` archive is unpacked.** When `load_model`
opens a `.keras` file with more than a few members, it builds a disk-backed
`DiskIOStore` in read mode, which extracts the archive to a temp dir.

| Line | `DiskIOStore` read-mode extraction |
|---|---|
| v3.0.0 | `self.archive.extractall(path=self.tmp_dir)` |
| v3.6.0 | `self.archive.extractall(path=self.tmp_dir)` |
| v3.9.0 | `self.archive.extractall(path=self.tmp_dir)` |
| v3.11.0 | `self.archive.extractall(path=self.tmp_dir)` |
| **v3.12.0+** | `file_utils.extract_open_archive(self.archive, self.tmp_dir)` |

So the cutover from a plain `extractall` to the filtered `extract_open_archive`
helper is exactly **v3.12.0**.

### v3.0.0 – v3.11.x: plain `extractall`, no Keras filter

These versions call `zipfile.ZipFile.extractall(path=tmp_dir)` directly, with no
member filter and no `resolve_sub_path` guard. That *looks* like a classic Zip-Slip,
but it is not a working write primitive, because **CPython's own
`ZipFile._extract_member` sanitizes each member name before writing**: it runs
`os.path.splitdrive` (dropping drive letters), strips leading separators, and removes
every `''`, `'.'` and `'..'` path component. So a member named `../../etc/cron.d/x`
is written as `etc/cron.d/x` *inside* `tmp_dir`, and `/etc/passwd` becomes
`etc/passwd` inside `tmp_dir`. This sanitization has shipped since Python 3.6.2, and
Keras 3.0's `setup.py` already pins `python_requires=">=3.9"`, so every supported
interpreter has it. **No archive-member path traversal write is reachable via
`.keras` model load on these versions.**

### v3.12.0 – v3.13.2: `filter_safe_zipinfos` anchored to the *working directory*

Here `extract_open_archive(archive, path)` routes the zip branch through
`filter_safe_zipinfos`. In this range the filter's signature is
`filter_safe_zipinfos(members)` — it takes **no destination argument** — and computes:

```
base_dir = resolve_path(".")      # == realpath of the process CWD
```

`extract_open_archive` passes the real destination `path` to `extractall` but **not**
to the filter, so members are validated against the process CWD instead of `tmp_dir`.
This is the root cause of **CVE-2026-11816** (CVSS 8.1, "CWD validation bypass",
fixed in v3.14.0): when the process CWD is `/` (common in Docker images, CI runners
and Jupyter kernels), the containment check collapses — every absolute path is
"inside" `/`.

Public write-ups of CVE-2026-11816 describe the `keras.utils.get_file(extract=True)`
entry point. The same buggy filter is also reachable through **`load_model` →
`DiskIOStore` → `extract_open_archive`**, so the CWD-anchor bug is present on the
model-load path too — a reachability angle those write-ups do not call out.

**But even here the `.keras` model-load path yields no arbitrary write**, for the same
reason as the plain-`extractall` era: the filter only decides *which* members
`extractall` receives; the actual write is still done by CPython's
`ZipFile.extractall`, which sanitizes member names. A member the buggy filter wrongly
approves is still written *inside* `tmp_dir`. The dangerous combination in
CVE-2026-11816 is the **tar** branch (`filter_safe_tarinfos` + `tarfile.extractall`
without `filter="data"` on some Python versions), where there is no CPython
backstop — and `.keras` archives are never tar, so model loading never enters it.

### v3.12.4 (the GitHub "latest"): CWD fixed, but the `.name` crash remains

The 3.12.4 back-port fixed the CWD anchor: the signature is now
`filter_safe_zipinfos(members, base_dir)` and `base_dir = resolve_path(base_dir)`
(the real destination), with containment checked by
`resolve_sub_path` → `os.path.realpath` + `os.path.commonpath`. Good.

However, the reject branch of the same function still reads:

```
if resolve_sub_path(base_dir, finfo.filename) is not None:
    ...
if not valid_path:
    warnings.warn(f"Skipping invalid path during archive extraction: '{finfo.name}'.")
```

A `zipfile.ZipInfo` has **no `.name` attribute** (the field is `.filename`). So the
moment *any* member fails the containment check, evaluating the f-string raises
`AttributeError: 'ZipInfo' object has no attribute 'name'` **before** `warnings.warn`
is even called. On v3.12.4 (where `base_dir` is the narrow `tmp_dir`), a crafted
`.keras` containing a single member that escapes `tmp_dir` (e.g. `../x`) makes
`load_model` die with a confusing `AttributeError` instead of safely skipping the
member. This is the "Sub-vulnerability B" of CVE-2026-11816; it was fixed in
**v3.14.0** (the warning reads `finfo.filename`) but **was not back-ported to the
3.12 line**, so it is still live on v3.12.4 — the exact release GitHub returns as
`/releases/latest`.

Severity is low (availability / robustness on a maliciously-crafted file, not code
execution or data exfiltration), but it is a genuine, reachable model-load defect on
the most-downloaded-looking release.

### v3.14.1 / v3.15.1: both issues fixed

`base_dir = resolve_path(base_dir)` (destination) **and** the warning reads
`finfo.filename`. The zip model-load extraction path is clean.

## Related, already-fixed `.keras` load-time issues (for completeness)

- **Decompression bomb (AIKIDO-2026-408481):** `DiskIOStore` extraction had no
  per-member size-ratio check, so a small `.keras` could inflate to GBs on disk.
  Fixed by `_reject_zip_extract_bomb`, which is present in v3.12.4 (it loops
  `archive.infolist()` and raises before extraction).
- **tar symlink traversal (CVE-2026-12482):** symlink members bypassed
  `filter_safe_tarinfos`; fixed in v3.12.3 / v3.15.0. Tar-only, so not reachable via
  `.keras` model load.
- **CVE-2025-12060:** `get_file` tar `extractall` without `filter="data"`; the
  original directory-traversal, fixed in v3.12.0 and then re-opened as
  CVE-2026-11816. Tar / `get_file`, not model load.

## What this means for a model-file scanner

1. **Flag, but do not over-claim.** A `.keras` whose central directory contains a
   member with an absolute path, a drive letter, or `..` components is anomalous and
   worth surfacing. But on the model-load path it is **not** a working arbitrary-write
   primitive on any released Keras (CPython sanitizes the write). Reporting it as
   "arbitrary file write on load" would be a false positive. The honest finding is:
   (a) on Keras 3.12.0–3.13.2 such a member can *crash* loading or be mis-classified
   by the CWD-anchored filter, and (b) on v3.12.4 an escaping member crashes
   `load_model` with an `AttributeError`.
2. **Version awareness matters.** The same crafted file is inert on v3.14.1+,
   crash-prone on v3.12.4, and filter-confused on 3.12.0–3.13.2. A scanner that
   reports Keras version context alongside the finding is far more useful than a
   binary verdict.
3. **Do not trust `/releases/latest` for Keras.** Enumerate `/releases` and compare
   by semantic version (see the first section).

## Honest limits

- This is **source review only**. No code was executed, no model file was crafted and
  loaded, and no live system was touched. Claims about CPython `_extract_member`
  sanitization rest on long-standing documented CPython behavior; claims about Keras
  rest on the cited files at the cited tags.
- A local, sealed proof-of-concept of the v3.12.4 `AttributeError`-on-load (a crafted
  `.keras` with one escaping member) would strengthen point (2) above; it is deferred
  rather than claimed.
- The arbitrary-write severity of CVE-2026-11816 belongs to `get_file` / tar and is
  out of scope for a `.keras` model-file scanner; it is summarized here only to draw
  the boundary of what model loading can and cannot reach.

---

*Made with AI agents working in the name of MV2, Munim, Inc. Licensed Apache-2.0.
Reproducible by reading the cited Keras source files at the cited release tags; no
execution required.*
