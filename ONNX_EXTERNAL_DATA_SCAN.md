<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# ONNX external_data path-traversal scanner (`onnx-external-data-scan`)

A static, no-execution scanner for the one thing an attacker controls in an
otherwise code-free ONNX model: the **`external_data` `location`** field.
It closes the ONNX "gap" rows in this repo's cross-format
[`MODEL_FILE_CVE_MAP.md`](MODEL_FILE_CVE_MAP.md).

> This tool, its tests and this document were made with AI, by MV2 of Munim, Inc.
> Code is Apache-2.0; the text is CC BY 4.0. Every CVE named here is already
> public — nothing here is a zero-day, and a clean scan guarantees nothing.

## The weakness

An `.onnx` file is a protobuf `ModelProto`. A tensor whose `data_location` is
`EXTERNAL` keeps its weights in a separate file, named by an `external_data`
entry with key `"location"`. The ONNX spec requires that location to be a
**relative path inside the model directory**. A naive loader instead joins the
untrusted value onto the model directory and opens it, so:

- an **absolute path** (`/etc/passwd`, `C:\Windows\win.ini`) is opened as-is;
- a **`..` segment** (`../../../etc/passwd`) escapes the model directory;
- a **URL scheme** (`https://`, `file://`) makes the loader fetch a remote or
  arbitrary resource;
- a **NUL / control byte** can truncate or bypass a weak path check;
- a **backslash** separator can slip past a naive `..` check and act as a
  path separator on Windows.

The result is arbitrary local file read (and, for a loader that writes back,
write) **at load time**, with no pickle and no code in the package.

### Public cases this maps to

| Advisory | Project | CWE | Root cause |
|---|---|---|---|
| CVE-2022-25882 / GHSA-ffxj-547x-5j7c (fixed in onnx 1.13.0) | `onnx` (Python) | CWE-22 | `external_data` location could point outside the model dir, e.g. `../../../etc/passwd` |
| CVE-2026-55832 / GHSA-h668-6x6g-f8r5 (fixed in tract 0.21.17 / 0.22.3 / 0.23.2) | `tract-onnx` (Rust) | CWE-22 | location joined to the model dir without rejecting absolute / `..` paths (plus an offset/length out-of-range DoS) |

Both were fixed by forcing `location` to be a relative path that stays inside
the model directory — exactly what this scanner checks before a loader runs.

## What it does

- Parses the protobuf **wire format itself** (Python standard library only, no
  `onnx` dependency) and reads **only** the `external_data` location strings.
- Never opens a referenced data file and never loads or runs the model.
- Walks initializers, sparse initializers, and tensors nested inside node
  attributes and subgraphs (recursively, with depth and size caps).

## Rules

| Rule | Severity | CWE | Flags |
|---|---|---|---|
| OED001 | HIGH | CWE-22 | `..` parent-directory segment in the location |
| OED002 | HIGH | CWE-22 | absolute path (POSIX `/…`, Windows drive `C:\…`, leading `\`) |
| OED003 | HIGH | CWE-918 | URL scheme (`http://`, `file://`, …) |
| OED004 | HIGH | CWE-22 | NUL or control byte in the location |
| OED005 | MEDIUM | CWE-22 | backslash path separator (ONNX locations must be POSIX-relative) |

## Usage

```bash
# scan a file or a directory of .onnx files
python onnx_external_data_scan.py ./model-dir

# CI gate: non-zero exit if anything HIGH or worse is found
python onnx_external_data_scan.py ./model-dir --fail-on HIGH

# machine-readable
python onnx_external_data_scan.py ./model.onnx --json
```

## Honest limits

- It flags **suspicious path shapes**, not confirmed exploitation; a patched
  loader (onnx ≥ 1.13.0, tract ≥ 0.21.17 / 0.22.3 / 0.23.2) rejects these
  itself, so a finding on such a loader is defence-in-depth, not a live bug.
- The `offset`/`length` out-of-range DoS angle of CVE-2026-55832 is **not**
  checked statically, because the size of the (relative) data file is unknown
  without opening it — out of scope for a no-execution file linter.
- A clean scan means only that none of the above shapes appear; it is not a
  guarantee the model is safe.
