# CVE map linter (`cve_map_lint.py`)

A dependency-free, standard-library structural linter for the cross-format
advisory maps shipped in this repo (`model_file_cve_map.json` and
`gguf_cve_map.json`). It checks the **shape** of an advisory map and
**re-asserts no CVE, GHSA or CWE identifiers or facts** of its own.

Made with AI by MV2 of Munim, Inc. Code is Apache-2.0; this document is CC BY 4.0.

## Why this exists

The advisory maps are the single source of truth for which public advisory each
detector covers. Their factual content (the CVE/GHSA ids, the CWE classes, the
CVSS scores) is verified at source and pinned by `test_model_file_cve_map.py`.
What was *not* reusable before this tool is the **schema** around those facts: a
fork, or a future edit that adds an entry, had no standalone way to check that
the structure is still well formed, and `gguf_cve_map.json` had no independent
shape check at all.

`cve_map_lint.py` fills exactly that gap, and nothing more. By design it never
encodes an advisory id or a score, so it cannot be the place a wrong fact is
introduced — it only reports structural problems, leaving the verified facts to
the map files and the pinned fact test.

## Usage

```
python cve_map_lint.py model_file_cve_map.json gguf_cve_map.json
python cve_map_lint.py --quiet model_file_cve_map.json   # ERROR findings only
```

The exit code is non-zero if any `ERROR`-severity finding is produced, so it can
guard a map file in CI or a pre-commit hook. It can also be imported:

```python
import cve_map_lint
findings = cve_map_lint.load_and_lint("model_file_cve_map.json")
errors = [f for f in findings if f.severity == cve_map_lint.ERROR]
```

Each `Finding` has `code`, `severity` (`ERROR` / `WARN` / `INFO`), `location`
and `message`.

## What it checks

Top level: the required keys are present; `license` is the expected
`CC BY 4.0` for a data file (warning if not); `made_with` discloses AI (warning
if not); `coverage_legend` and `formats` are objects; each format record carries
`code_execution_surface` (boolean), `detector_module` and `note`.

Each entry: all required fields are present; `id` is a string (an id outside the
recognised CVE / GHSA / CWE families is only an **info** note, never an error, so
a valid map is never rejected over an id shape); `format` is one declared in the
`formats` block; `cwe` is a non-empty list of `CWE-<n>` tokens; `cvss` is a
number in `0.0`–`10.0` or `null`; `mechanism` and `verified` are non-empty;
the `detector` object has exactly `module`, `rule`, `coverage`, its `coverage`
is one of the legend keys, `full`/`partial` coverage carries a module and rule,
and `out-of-scope` coverage has a `null` rule. Duplicate entry ids are an error.

## Finding codes

| Code | Severity | Meaning |
|------|----------|---------|
| CML000 | ERROR | file not found or invalid JSON |
| CML001 | ERROR | root is not a JSON object |
| CML002 | ERROR | missing required top-level key |
| CML003 | WARN | `license` is not `CC BY 4.0` |
| CML004 | WARN | `made_with` does not disclose AI |
| CML005 | ERROR | `coverage_legend` is not an object |
| CML006 | ERROR | `formats` is not an object |
| CML007 | WARN | `formats` block is empty |
| CML008 | ERROR | a format record is not an object |
| CML009 | ERROR | a format record is missing a required key |
| CML010 | ERROR | `code_execution_surface` is not a boolean |
| CML011 | ERROR | `entries` is not a list |
| CML012 | WARN | `entries` list is empty |
| CML013 | ERROR | an entry is not an object |
| CML014 | ERROR | an entry is missing a required field |
| CML015 | ERROR | duplicate entry id |
| CML016 | INFO | entry id is not a recognised CVE/GHSA/CWE form |
| CML017 | ERROR | entry `id` is not a string |
| CML018 | ERROR | entry `format` is not declared in `formats` |
| CML019 | ERROR | `cwe` is not a non-empty list |
| CML020 | ERROR | a `cwe` token does not match `CWE-<n>` |
| CML021 | ERROR | `aliases` is not a list |
| CML022 | ERROR | `cvss` is not a number or null |
| CML023 | ERROR | `cvss` is outside `0.0`–`10.0` |
| CML024 | ERROR | `mechanism`/`verified` is empty |
| CML025 | ERROR | `detector` is not an object |
| CML026 | ERROR | `detector` keys are not exactly module/rule/coverage |
| CML027 | ERROR | `detector.coverage` is not in `coverage_legend` |
| CML028 | ERROR | `full`/`partial` coverage lacks a module or rule |
| CML029 | ERROR | `out-of-scope` coverage does not have a null rule |

## Honest limits

- This is a **structural** check only. It does not verify that a CVE id is real,
  that a CVSS score is correct, or that a detector actually detects what it
  claims — those are the job of the map's own sources and of
  `test_model_file_cve_map.py`.
- The schema it enforces mirrors the one documented in `MODEL_FILE_CVE_MAP.md`.
  It is covered by `test_cve_map_lint.py`, which builds every fixture inline; a
  clean lint of a real map file still guarantees only that the file's shape is
  valid, not that its contents are complete.
