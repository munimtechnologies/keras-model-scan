# ONNX external_data traversal corpus (`onnx-external-data-corpus`)

A small, reproducible corpus of **crafted header-only `.onnx` files** for
regression-testing how an ONNX loader (or scanner) handles the `external_data`
`location` field. It pairs with this project's static detector
[`onnx_external_data_scan.py`](./ONNX_EXTERNAL_DATA_SCAN.md).

*Made with AI by MV2 of Munim, Inc. Code: Apache-2.0. Dataset/metadata: CC BY 4.0.*

## Why

An `.onnx` file is a protobuf `ModelProto`. It has no code of its own, but a tensor
with `data_location = EXTERNAL` names the file holding its weights in a repeated
`external_data` map whose `location` entry is — per the ONNX spec — a **relative**
path that must resolve *inside* the model directory. A loader that joins that
untrusted value onto the model directory without sanitising it can be steered to
read (or, in some loaders, write) an arbitrary local file **at load time**, before
any inference runs. This is CWE-22 path traversal.

Public, already-fixed cases:

| Project | Advisory | Fixed in | Class |
|---|---|---|---|
| onnx (`< 1.13.0`) | CVE-2022-25882 / GHSA-ffxj-547x-5j7c | 1.13.0 | CWE-22 |
| tract-onnx | CVE-2026-55832 / GHSA-h668-6x6g-f8r5 | 0.21.17 / 0.22.3 / 0.23.2 | CWE-22 |

Both were fixed by forcing `location` to a relative, in-directory path. A new DIY
loader that forgets this check reintroduces the bug — so a fixed corpus is a cheap
regression gate.

## What it generates

`python onnx_external_data_corpus.py --out-dir ./corpus` writes nine files plus a
`manifest.json`. Each file is a minimal valid `ModelProto` with one external tensor;
only the `location` string differs. **No tensor payload, no exploit code** — just a
protobuf header. A safe loader must reject every malicious file and accept the clean
control.

| File | `location` | Rule | Technique |
|---|---|---|---|
| `traversal_posix.onnx` | `../../../../../../etc/passwd` | OED001 | parent-directory escape |
| `absolute_posix.onnx` | `/etc/shadow` | OED002 | absolute POSIX path |
| `url_http.onnx` | `http://169.254.169.254/latest/meta-data/iam/` | OED003 | remote URL scheme (SSRF) |
| `url_file.onnx` | `file:///etc/passwd` | OED003 | `file://` URL scheme |
| `nul_byte.onnx` | `weights.bin\0.png` | OED004 | embedded NUL truncation |
| `control_byte.onnx` | `weights\x07.bin` | OED004 | control byte in path |
| `backslash.onnx` | `subdir\weights.bin` | OED005 | backslash separator |
| `windows_drive.onnx` | `C:\Windows\System32\config\sam` | OED005 | Windows drive-absolute |
| `clean_control.onnx` | `weights.bin` | — | spec-conformant control |

Severities in `manifest.json` are this corpus's own CWE-22 classification, not a
promise about any particular scanner's output.

## Using it

As a Python library:

```python
import onnx_external_data_corpus as corp
corp.write_corpus("./corpus")          # files + manifest.json
models = corp.build_corpus()           # {filename: onnx_bytes}
one = corp.build_model("../../etc/passwd")
```

As a regression test against this project's scanner:

```sh
python onnx_external_data_corpus.py --out-dir ./corpus
python onnx_external_data_scan.py ./corpus --fail-on LOW   # should flag all but clean_control.onnx
```

## Honesty / limits

- Every CVE named is already **public and fixed**; nothing here is a zero-day.
- The files are **header-only** and contain no exploit payload — they describe a
  dangerous *input*, not an attack.
- The corpus exercises the `location` string only. The offset/length
  out-of-bounds (DoS) angle of CVE-2026-55832 needs the real external file's size
  and is out of a header-only corpus's scope.
- A loader passing this corpus is not proven safe in general; it is only shown to
  reject these specific techniques.
- Standard library only — no `onnx`, no protobuf runtime. The protobuf wire format
  is emitted and re-parsed by hand, so the corpus and its test have no dependencies.
