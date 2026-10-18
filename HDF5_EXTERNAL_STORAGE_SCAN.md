# hdf5_external_storage_scan

Static, no-execution detector for HDF5 weight files (`.h5`, `.hdf5`,
`.weights.h5`, and the `model.weights.h5` inside a `.keras` archive) that make
the loader read **other files on the host**. Standard library only: no h5py, no
Keras, nothing is loaded. Apache-2.0.

## The vulnerability

**CVE-2026-1669** ([GHSA-3m4q-jmj6-r34q](https://github.com/advisories/GHSA-3m4q-jmj6-r34q),
CWE-73, CVSS 7.1 GitHub / 7.5 NVD). Keras 3.0.0 through 3.13.1 honour two HDF5
features when reading weights:

- **external storage**: a dataset's raw bytes live in named files outside the
  HDF5 file, and
- **external links**: a group member resolves to an object in another HDF5 file.

A crafted `.weights.h5`, or a `.keras` archive that embeds one, makes
`load_weights()` / `load_model()` read an arbitrary readable file into the
model's tensors. Those bytes can then be recovered through inference or a
re-save. `safe_mode` does not help, because it guards object deserialization,
not weight I/O. **Fixed in Keras 3.12.1 and 3.13.2.**

Keras's own savers use neither feature, so either one in a weights file is
anomalous. This is a different sink from the legacy HDF5 Lambda code-execution
issue (CVE-2025-9905), which `hdf5_keras_lambda_scan` covers.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| HES001 | high | External Data Files message (object-header message type `0x0007`): a dataset reads its raw data from the named external file(s). The finding lists every name, offset and size, and flags absolute paths and `..` traversal. |
| HES002 | high | Link message (type `0x0006`) with link type 64 (external link): the finding names the link, the target file and the object path. |
| HES010 | info | Not HDF5 (no superblock at 0, 512, 1024, ...) or not a readable zip, so nothing was checked. |
| HES011 | info | An HDF5 member of a `.keras`/zip archive was over the read limit (default 1 GiB) or unreadable, and was skipped. |

All high findings carry `cve: CVE-2026-1669` and `cwe: CWE-73`.

## Usage

```bash
python hdf5_external_storage_scan.py model.weights.h5 model.keras
```

Exit code 0 means no high findings, 1 means at least one high finding, and 2
means a usage or I/O error. From Python, `scan_file(path)` and
`scan_bytes(data, name=...)` return a list of finding dicts (`rule`,
`severity`, `cve`, `cwe`, `message`, `evidence`), the same shape as the other
scanners in this repo.

## How it works

The scanner reads the superblock first (versions 0-3) to get the sizes of
offsets and lengths and the base address. It then finds each record by its
**body**, decoded the way libhdf5's own decoders do (`H5Oefl.c`,
`H5HLcache.c`, `H5Olink.c`, `H5Ocache.c` in HDFGroup/hdf5):

- **HES001.** Matches a type-7 message header in version 1 form (u16 type, u16
  size, flags, 3 reserved) or version 2 form (u8 type, u16 size, flags, and an
  optional u16 creation order). The body must be version 1, and the 3 reserved
  bytes may be anything, as libhdf5 skips them unchecked. It also needs
  `0 < used <= allocated` slots and a message size large enough for the slots.
  Most importantly, the **heap address must point at a version-0 local heap
  (`HEAP`)**, which libhdf5 requires. Each slot's file name is read from that
  heap, and an empty name is rejected, as libhdf5 does. Requiring a real heap
  structure at the stated address keeps random weight bytes from matching.
- **HES002.** Matches a version-1 link body whose flags store a link type
  (bit `0x08`; flags above `0x1f` are invalid) followed by type 64. It decodes
  the optional creation order and character set and the 1/2/4/8-byte name
  length, then the 2-byte user-data length. The user data must be
  `<version 0 byte><file>\0<object>\0`, with printable names. Anchoring on the
  body finds the link both in an object header (compact storage) and in an
  unfiltered dense-storage heap block.

## Validation status

- `test_hdf5_external_storage_scan.py` builds byte-level fixtures (stdlib only).
  They cover version 1 and version 2 message headers, non-zero reserved bytes, a
  512-byte user block, several slots with traversal, and the negatives: no heap,
  a wrong heap address, used greater than allocated, an empty name, and a
  symbol-table message pointing at a heap. External links are tested with
  creation order, character set and 2- and 8-byte name lengths, alongside hard
  and soft links and an unprintable target. The suite also checks `.keras`
  member scanning, the size limit and the CLI exit codes. The publish gate runs
  this suite.
- `RealH5pyFilesTest` in the same file repeats the checks on files written by
  **h5py/libhdf5 itself**: clean weights, `create_dataset(..., external=...)`
  and `h5py.ExternalLink`, each with `libver="earliest"` and `"latest"`, plus
  a `.keras` wrapper. It runs only where h5py is installed, so the stdlib-only
  publish gate skips it. Run it locally with `pip install h5py numpy` and then
  `python -m unittest test_hdf5_external_storage_scan`. Results on real files
  will be recorded here once that run is done. Until then, treat real-file
  coverage as unconfirmed.

## Prior art

Promptfoo's ModelAudit (`keras_h5_scanner.py`) already flags CVE-2026-1669. It
opens the file with h5py and reports external storage, external links and
virtual-dataset sources, so it covers more than this scanner (virtual datasets
included). This scanner is not a first. It is a stdlib-only alternative that
never passes the untrusted file to h5py/libhdf5, and it fills this repo's
coverage gap for the CVE.

## Honest limits

- **Virtual datasets** (layout class 3, with source file names in the global
  heap) are another way for HDF5 to read other files, and this scanner does not
  decode them. Public huntr report titles describe a virtual-dataset bypass of
  the CVE-2026-1669 fix. No separate CVE is assigned, and this repo has not
  verified the bypass.
- A record stored inside a filtered (compressed) heap block is invisible to a
  byte scan.
- Names and paths must be printable UTF-8. Link names over 1 MiB are not
  examined.
- A clean result is triage, not proof that a file is safe. Upgrading Keras to
  3.12.1 or 3.13.2 or later is the fix.

## References

- GHSA-3m4q-jmj6-r34q / CVE-2026-1669: https://github.com/advisories/GHSA-3m4q-jmj6-r34q
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-1669
- HDF5 File Format Specification: https://support.hdfgroup.org/documentation/hdf5/latest/_f_m_t3.html

Made with AI by MV2 of Munim, Inc. Apache-2.0.
