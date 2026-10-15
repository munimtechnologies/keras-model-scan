# Model-archive decompression-bomb scanner (`archive_bomb_scan.py`)

Part of **model-file-scan**. Static, no-execution detection of decompression-bomb /
resource-exhaustion risk (CWE-409) in ZIP-based ML model archives.

> Made with AI by MV2 of Munim, Inc. Everything here is already public; nothing
> below is a zero-day. The scanner describes detection, not exploitation, and a
> clean scan does **not** prove a file is safe.

## Why this exists

Several common model containers are ZIP archives that a loader **expands** before
inference even begins:

| Format            | What the loader does with the zip                        |
| ----------------- | -------------------------------------------------------- |
| `.keras` (v3)     | extracts `config.json` + weight shards to a temp dir     |
| `.pt` / `.pth`    | reads a zip of a pickle plus tensor storages             |
| `.npz`            | reads a zip of `.npy` arrays                             |
| MLeap / stanza    | extracts a zip of model resources                        |

The **path-traversal** dimension of these archives — a member that escapes the
extraction directory — is already covered elsewhere in this suite (rule `KMS005`
for `.keras`, `PKL030` for pickle/`.pt`). This module covers the **orthogonal**
dimension: an archive whose *declared* sizes, member count, or nesting would
exhaust disk or memory when a loader expands it. That is a classic "zip bomb" /
data-amplification denial of service. A loader that calls `extractall()` or
materializes storages trusts the central-directory sizes and will happily try to
write gigabytes from a few-kilobyte file.

## How it works

The scanner opens the archive with the standard-library `zipfile` and reads
**only the central directory** (`ZipInfo.file_size`, `ZipInfo.compress_size`, and
the member list). It never extracts, decompresses, or reads entry data, never
imports `keras`/`torch`/`numpy`, and never executes anything.

| Code     | Severity | Meaning                                                                 |
| -------- | -------- | ----------------------------------------------------------------------- |
| `ABZ001` | HIGH     | A member's declared uncompressed/compressed ratio is far above what genuine (high-entropy) weights produce, and the member is large enough to matter. |
| `ABZ002` | HIGH     | The sum of declared uncompressed sizes exceeds a configured budget.     |
| `ABZ003` | MEDIUM   | The archive declares an unusually large number of members.              |
| `ABZ004` | MEDIUM   | A member is itself an archive (nested-expansion precursor).             |
| `ABZ000` | ERROR    | The file looked like an archive but could not be read.                  |

### Usage

```bash
python archive_bomb_scan.py path/to/model.keras
python archive_bomb_scan.py ./model-dir --fail-on HIGH --json
```

Thresholds (`--per-entry-ratio`, `--min-entry-bytes`, `--total-uncompressed`,
`--max-entries`, `--no-nested`) are tunable. The defaults are deliberately
conservative for production (1 MiB minimum flagged member, 1 GiB total budget,
100 000 members); lower them for stricter pipelines.

## Corpus

`archive_bomb_corpus.py` writes five **tiny, payload-free** archives (each well
under 100 KiB on disk, none expanding to a dangerous size) that reproduce the
*structure* of each class plus a clean control. They let you regression-test this
scanner — or any model-zip reader — without ever handling a real bomb. The test
module scans them with low thresholds so the harmless demonstrators trip the same
code paths a production-scale bomb would trip against the realistic defaults.

| File                      | Trips            |
| ------------------------- | ---------------- |
| `abomb_high_ratio.zip`    | `ABZ001`         |
| `abomb_large_total.zip`   | `ABZ001`,`ABZ002`|
| `abomb_many_entries.zip`  | `ABZ003`         |
| `abomb_nested.zip`        | `ABZ004`         |
| `clean_model.zip`         | (none)           |

## Prior art and honest limitations

- Generic zip-bomb detection is well established (antivirus, archive libraries).
  The **SecAI-Hub** `modelscan` fork added archive-bomb checks for model zips.
  ProtectAI **ModelScan** and promptfoo **ModelAudit**'s base scanners flag code
  and path traversal but do **not** flag decompression bombs. This module is a
  standalone, dependency-free detector for the model-file niche, paired with a
  reproducible, safe corpus.
- It trusts the central-directory sizes, which an attacker controls. A member can
  **under-declare** its expansion, or an **overlapping-entry** bomb can reuse the
  same compressed data for many members; detecting those precisely needs
  local-header parsing and is out of scope here. The declared ratio is still a
  strong first-pass signal because a real loader acts on exactly these numbers.
- Nested-archive detection (`ABZ004`) is name-based; it flags a precursor, not a
  confirmed recursive bomb.
- This is a **class** detector (CWE-409); it is not tied to a single CVE.

## References

- CWE-409: Improper Handling of Highly Compressed Data (Data Amplification).
- JFrog, *Zip-based model attempting ZipSlip path traversal* (background on
  zip-based model containers).
- SecAI-Hub `modelscan` (archive-bomb hardening in a `modelscan` fork).
