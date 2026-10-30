# archive_payload_scan.py — executables and scripts hidden in model archives

`archive_payload_scan.py` is a static, dependency-free detector for native
executables, shared libraries and scripts carried inside model archives:
PyTorch and TorchScript zips, Keras v3 `.keras`, NumPy `.npz`, NeMo `.nemo`
tars, and `.zip` / `.tar.gz` / `.tar.xz` bundles. It is part of the open-source
[keras-model-scan](https://github.com/munimtechnologies/keras-model-scan) toolkit.
Made with AI agents working in the name of MV2 of Munim, Inc. Apache-2.0.

## Why archives need this check

Weights never need native code. Yet a model archive can carry a shared library,
an executable or a script next to the weights, often under a harmless name such
as `model.bin`. Custom-op loaders that take a library path, remote-code style
loading, or a user who unpacks the bundle and runs what is inside can then
execute it. Opcode-level pickle scanners and config walkers never look at these
members, because they are not pickles or configs.

This toolkit's `SCANNER_COVERAGE_MATRIX.md` marked "Embedded executable in
model archive" as not covered here (ModelScan: not documented; ModelAudit:
documented). This module closes that row.

## What it does

- Lists every member of a zip, or of a tar (plain, gzip, bzip2 or xz), and
  reads only the first `HEAD_BYTES` (4096) bytes of each. It never extracts to
  disk, never runs anything, and never imports a model library.
- Judges members by their bytes, not their names: ELF (class and byte-order
  bytes checked), PE (the `PE\0\0` signature at `e_lfanew` is verified, so a
  tensor that happens to start with `MZ` is not flagged), Mach-O, and fat
  Mach-O (told apart from Java class files, which share the `CAFEBABE` magic).
- Reports `#!/` scripts (the whole first line must be printable ASCII, so a
  tensor starting with `#!` is not flagged), Java class files, and script or
  Python file extensions. TorchScript's own `code/**/*.py` (an archive that has
  `constants.pkl`) is exempt; a `.py` anywhere else is reported.
- Opens nested archives (a zip checkpoint inside a `.nemo` tar, a `.tgz` inside
  a zip) up to `MAX_DEPTH` (3) levels and `MAX_NESTED_BYTES` (128 MiB), and
  checks what a bare gzip/bzip2/xz stream unpacks to.
- `scan_file` streams from disk, so a multi-GB archive is not loaded whole.

## Rules

| rule | severity | class | condition |
|------|----------|-------|-----------|
| **ARC001** | high | CWE-829 | A member, or the file itself, is a native executable or shared library (ELF, PE, Mach-O). The evidence says when the file name hides it. |
| **ARC002** | medium | CWE-829 | A member is a script or code: `#!/` shebang, Python source or bytecode, shell, batch, PowerShell, VBScript, HTA, Java class or jar, or a name like `libop.so` with no native header. |
| **ARC003** | medium | CWE-693 | A member that could not be inspected: encrypted, a 7z or RAR container, unreadable, nested deeper than `MAX_DEPTH`, or a nested archive over `MAX_NESTED_BYTES`. |

## Usage

```bash
python archive_payload_scan.py model.nemo checkpoint.pt bundle.tar.gz
```

Exit `1` on any high finding, `0` otherwise, `2` on usage error or unreadable
input. `scan_bytes(data, name=...)` and `scan_file(path)` return a list of
finding dicts with keys `rule, severity, cve, cwe, message, evidence`.

## Honest limits

- This is static review. A finding shows that a program or script is in the
  archive, not that any loader runs it.
- Only zip and tar containers are opened. 7z and RAR members are reported
  (ARC003), not opened; a compressed stream that unpacks to another archive is
  reported, not opened.
- A nested archive over 128 MiB is reported, not opened. Large `.nemo` files
  hold their weights as a nested checkpoint, so expect an ARC003 (medium) there;
  medium findings do not change the exit code.
- Script detection is by shebang, magic and extension. A script with no
  shebang and a neutral name (for example Python source saved as `notes.txt`)
  is not seen.
- Member path traversal and tar symlinks are left to `nemo_container_scan.py`;
  pickle members to the pickle scanners in this repo.
- Tests build small zip and tar fixtures in memory with header bytes only; no
  real executables are used.
