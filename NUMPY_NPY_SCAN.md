# numpy_npy_scan — NumPy `.npy` / `.npz` object-array deserialization scanner

Part of [`munimtechnologies/keras-model-scan`](https://github.com/munimtechnologies/keras-model-scan)
(Apache-2.0). Static, read-only, standard-library only. It never imports
`numpy`, never unpickles, and never executes anything — it parses the NumPy
array-file header and disassembles any trailing pickle stream with
`pickletools` opcode analysis only.

> Made with AI agents working in the name of MV2 of Munim, Inc. The work is
> disclosed as AI-generated wherever a platform or project asks.

## Why NumPy array files are a model-file attack surface

The `.npy` binary format stores ordinary numeric arrays as raw contiguous
bytes. But an **object array** — one whose dtype carries Python objects
(`dtype.hasobject is True`, e.g. a `descr` of `'|O'`) — is serialized by
writing a **Python pickle** of the array into the file's data section. Loading
such a file therefore requires `numpy.load(..., allow_pickle=True)`, and doing
that on an untrusted file unpickles attacker-controlled bytes. As NumPy's own
docs put it, this is equivalent to running `eval()` on the file.

`.npz` is simply a ZIP archive of `.npy` members, so an object-array member
inside a `.npz` carries the same pickle risk.

This is tracked as **CVE-2019-6446** (CWE-502, CVSS 9.8): NumPy before 1.16.3
used pickle **by default** when loading, so a crafted `.npy` / `.npz` could
execute arbitrary code. NumPy 1.16.3 flipped `allow_pickle` to default
`False`, but the exposure remains for any caller that re-enables pickle or runs
an old NumPy. A model distributed as an object-array `.npy` / `.npz` can *only*
be loaded by re-enabling pickle — so these files are worth flagging before
anyone loads them. `.npy` / `.npz` are a common companion format in ML
pipelines (checkpoints, embeddings, label caches), and sit alongside the pickle,
Keras, GGUF, ONNX, safetensors and skops formats the rest of this toolkit
already covers.

## Rules

| Rule | Severity | CVE / CWE | What it flags |
|------|----------|-----------|---------------|
| **NPY001** | high | CVE-2019-6446 / CWE-502 | An object-dtype array in a `.npy` file, or in a `.npy` member of a `.npz`. Its data section is an untrusted pickle; loading it requires `allow_pickle=True`. Object dtypes **nested inside a structured dtype** (e.g. `[('a', '<f8'), ('b', '|O')]`) are detected too — a case a naïve `descr == '|O'` check misses. |
| **NPY002** | high | CVE-2019-6446 / CWE-502 | The pickle data section of an object array contains code-execution opcodes (`GLOBAL`/`STACK_GLOBAL`/`REDUCE`/`BUILD`/`INST`/`OBJ`/`NEWOBJ`/`NEWOBJ_EX`). The referenced globals are reported, decoded from opcodes only — the pickle is never executed. |

## Usage

```bash
# scan one or more files
python numpy_npy_scan.py model.npy embeddings.npz

# exit code: 1 if any high-severity finding, 2 on usage/IO error, 0 if clean
```

```python
import numpy_npy_scan as nps

findings = nps.scan_file("suspicious.npz")
for f in findings:
    print(f["rule"], f["severity"], f["cve"], f["message"])

# or scan bytes you already have in memory
findings = nps.scan_bytes(open("a.npy", "rb").read(), name="a.npy")
```

Each finding is a dict with keys `rule`, `severity`, `cve`, `cwe`, `message`,
`evidence` — the same shape the other scanners in this repo use.

## Honest limits

- This is a **static** detector. NPY001 fires on the *presence* of an object
  array; such a file is only dangerous if the loader passes `allow_pickle=True`
  (or runs NumPy < 1.16.3). That is exactly the condition this scanner is meant
  to warn about before it happens.
- NPY002's opcode decode reports what a pickle *would* import; it does not
  prove exploitability and never executes the stream. A truncated or unusual
  pickle may yield partial global names.
- It parses `.npy` format versions 1.0, 2.0 and 3.0 headers and `.npz` ZIP
  containers. Non-NumPy inputs return no findings.

## Prior art and what is new here

Pickle scanners (`picklescan`, `fickling`) analyse raw pickle streams, and
`modelscan`-style tools cover several ML formats. What this standalone module
adds to a vendor-neutral toolkit is a dedicated `.npy` / `.npz` detector that
(a) parses the NumPy array-file header statically to decide whether a pickle is
even present, (b) recurses into **structured** dtypes so an object field hidden
among numeric fields is still caught, and (c) reports the pickle's
code-execution opcodes without executing it — all with the standard library
only and no `numpy` dependency.
