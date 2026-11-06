<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Munim, Inc. -->

# Pre-registration: big NeMo checkpoints in `nemo_container_scan` (job `nemo-big-v1`)

Written and published on 2026-11-06, **before** job `nemo-big-v1` runs.
Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0.

## What we found by reading source (not yet run)

1. **Big checkpoints are skipped with no finding.** `nemo_container_scan`
   0.1.0 reads each tar member with `fh.read(MAX_MEMBER_BYTES + 1)` and, if the
   member is larger than `MAX_MEMBER_BYTES` (256 MiB), goes on to the next
   member with no finding. NeMo's `SaveRestoreConnector.save_to` writes the
   weights with `torch.save(state_dict, "model_weights.ckpt")` and tars the
   folder uncompressed (`tarfile.open(filename, "w:")`, `tar.add(source_dir,
   arcname=".")`; NeMo main, read 2026-11-06). So for a model whose checkpoint
   is bigger than 256 MiB, the pickle that `restore_from` loads is never
   checked and the result is clean, while a smaller honest model gets
   NEMO010.
2. **The whole file is read into memory.** `scan_file` does `fh.read()` with
   no limit before scanning, so a 2.4 GB model needs about 2.4 GB of RAM plus
   one 256 MiB read.
3. **Too many members ends quietly.** After `MAX_MEMBERS` (10,000) members the
   loop stops with no finding.

## The fix under test (0.2.0)

- A member that starts with a zip header (a torch-save checkpoint) is opened
  in place as a seekable file. Only the zip directory and its `*.pkl` entries
  are read, whatever the checkpoint's size.
- `scan_file` streams the tar from disk; `scan_bytes` is unchanged for callers.
- **NEMO030** (medium): a pickle still too big to check (a bare pickle member
  of protocol 2-5, or a `*.pkl` zip entry, larger than `MAX_MEMBER_BYTES`).
- **NEMO031** (medium): more members than `MAX_MEMBERS`.
- The old test module's exact pin `assertEqual(scan.__version__, "0.1.0")`
  becomes a floor (>= 0.2.0). No other test pins this module's version
  (checked: `test_attribution.py`, `test_nemo_container_scan.py`).
- New test module `test_nemo_container_scan_big.py` (standard library only; not
  published until the release).

## Files

| Case | What it is |
|---|---|
| w_small | NeMo layout ("w:", arcname "."), `torch.save` of an OrderedDict with a 4,000,000-byte uint8 zero tensor |
| w_big | the same with a 280,000,000-byte tensor (checkpoint > 256 MiB) |
| w_big_gz | w_big tarred "w:gz" (older NeMo releases) |
| w_legacy_big | w_big saved with `_use_new_zipfile_serialization=False` (reported only) |
| titanet_large | `nvidia/speakerverification_en_titanet_large` .nemo, revision 0dc382f4, 101,621,760 bytes, CC BY 4.0 |
| parakeet-110m | `nvidia/parakeet-tdt_ctc-110m` .nemo, revision 431a349f, 459,243,520 bytes, CC BY 4.0 |

The published files are downloaded inside the sealed job and read only as
bytes by `tarfile`, `zipfile` and the scanners. Nothing is unpickled, loaded
or extracted. All tensors in the written files are zeros.

## Predictions (graded rows)

| Row | Prediction |
|---|---|
| P1 | the patch applies cleanly (scanner, old test's version pin, doc; each edit once, a second pass changes nothing, no line lost outside the replaced functions, the code compiles) |
| S1 | the whole keras-model-scan suite passes with the patched files |
| W1 | torch writes each checkpoint as a zip (`PK\x03\x04`); each tar holds `./model_config.yaml` and `./model_weights.ckpt`; w_big's checkpoint is larger than 256 MiB |
| R1 | both published files download at the pinned size; each has a member ending in `model_weights.ckpt` that starts with `PK\x03\x04`; titanet's is at most 256 MiB, parakeet-110m's is larger |
| N1 | w_small: 0.1.0 {NEMO010}, 0.2.0 {NEMO010} |
| N2 | w_big: 0.1.0 no findings, 0.2.0 {NEMO010} |
| N3 | w_big_gz: 0.1.0 no findings, 0.2.0 {NEMO010} |
| N4 | titanet_large: 0.1.0 {NEMO010}, 0.2.0 {NEMO010} |
| N5 | parakeet-110m: 0.1.0 no findings, 0.2.0 {NEMO010} |
| M1 | 0.2.0 scans parakeet-110m with under 200 MB peak RSS |
| T1 | 0.2.0 scans parakeet-110m in under 60 s (not release-gating) |
| Hb | among `.nemo` files in the 100 most-downloaded Hub repos tagged `nemo` (file-size metadata only), at least 20 files, and at least half larger than 256 MiB (not release-gating) |

Reported, not graded: w_legacy_big (predicted 0.1.0 no findings, 0.2.0
{NEMO030}); 0.1.0's peak RSS on parakeet-110m; the share of `.nemo` files
above 50 MiB.

**Release rule:** if P1, S1, W1, R1, N1-N5 and M1 hold, the patched files, the
new test module and a graded report are published and released
(nemo_container_scan 0.2.0). If another release ships first, the suite is
re-run on the new main before publishing. Any failed row is published as it
came out.

## Prior art

promptfoo's ModelAudit `nemo_scanner` (main, read 2026-11-06) streams the tar
from the path and hands each checkpoint member up to
`NEMO_MAX_CHECKPOINT_SCAN_BYTES` (50 MB) to its nested scanners; a bigger
checkpoint is marked inconclusive (`nemo_checkpoint_scan_skipped_size_limit`)
and not scanned. It fails closed; our 0.1.0 failed open. Reading only a
checkpoint's zip directory and pickle entries is not new either:
[0xelitesystem/model-pickle-scanner](https://github.com/0xelitesystem/model-pickle-scanner)
does it in the browser for `.pt`/`.bin`/`.ckpt` files (found by web search on
2026-11-06). 0.2.0 applies the same idea to the checkpoint inside a `.nemo`
tar. This is a small engineering step that brings our gate up to date, not a
new kind of check.

## Honest limits

- This is a coverage gap in our own CI gate, found by reading source. NeMo
  itself is not claimed to have a bug here, and no loader is tested on
  planted input.
- Only two published models are downloaded. The Hub census uses file size
  as a stand-in for checkpoint size.
- NEMO010 on an honest model is expected: `.nemo` weights are pickles.
