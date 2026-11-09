# Pre-registration: legacy-format checkpoints inside `.nemo` files (job `nemo-legacy-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Written 9 November 2026 (UTC), before the job runs. The job's code is in
[research/nemo-legacy/](nemo-legacy/). The new test module
(`test_nemo_container_scan_streams.py`, 16 tests) is published only if and
when the fix ships.

## The gap (found by reading our own code)

A `.nemo` file is a tar holding `model_config.yaml` and `model_weights.ckpt`,
which NeMo's `restore_from` reads with `torch.load`. `torch.save` writes that
checkpoint either as a zip with `data.pkl` (the default since PyTorch 1.6) or,
with `_use_new_zipfile_serialization=False` (the default before 1.6), in the
legacy format: **five pickles back to back** (torch's magic number
0x1950A86A20F9469CFC6C, protocol version 1001, a `sys_info` dict, the object,
the storage keys) followed by raw tensor bytes. `torch.load` reads all five
(`_legacy_load` in `torch/serialization.py`).

`nemo_container_scan` 0.2.0 (in release v0.54.0) handles a bare-pickle member
with one `pickletools.genops` pass, which ends at the first STOP. For a legacy
checkpoint that is the 15-byte magic-number pickle, which has no imports, so
the member yields **no finding at all**. That is not even NEMO010, which the
zip-format checkpoint of the same model gets. (Checkpoints over 256 MiB already
get NEMO030, "too big to check", since 0.2.0.) The module's own docstring
says the legacy format is covered. It is not.

This is a coverage gap in our own scanner on honest files. NeMo and PyTorch
are not claimed to have a bug.

## The fix: `nemo_container_scan` 0.3.0

- A bare-pickle member is walked the way the loader reads it. That means
  exactly five pickles when the first holds torch's magic number, with no walk
  into the raw tensor bytes that follow. Otherwise the walk continues while the
  next bytes open a protocol 2-5 pickle (cap 4,096), and each pickle gets its
  own memo.
- A torch zip's `data.pkl` is still read as one pickle, as `torch.load` reads
  it.
- The evidence says "legacy torch.save, N of 5 pickles" (plus "truncated" if
  the file ends early). A legacy checkpoint is reported as NEMO010 even when
  it names nothing.
- STACK_GLOBAL keeps the module/name pair 0.2.0 recorded. When it differs, it
  also records the pair whose module string was fetched back from the memo
  (protocol 4+ reuses a module name). Nothing 0.2.0 reported is dropped.
- `model-file-scan` gets a patch version bump at release; its routing is
  unchanged.

## Files (written in the sealed container with the real writer)

Writer: CPU `torch` (latest), tars made with `tarfile` the way NeMo's
`save_to` makes them (`"w:"`, `tar.add(folder, arcname=".")`).

| case | checkpoint | tar |
|---|---|---|
| L1 | legacy, `state_dict` of a small MLP, protocol 2 | plain |
| L2 | legacy, same, `pickle_protocol=4` | plain |
| L3 | legacy, `{epoch, state_dict, optimizer}` (SGD momentum) | plain |
| L4 | legacy, `state_dict` | gzip (older NeMo) |
| Z1 | default zip, `state_dict` (control) | plain |
| Z2 | zip, `pickle_protocol=4` (control) | plain |
| C1 | none, config only (control) | plain |

Ground truth comes from `torch.load(weights_only=False)` on our own checkpoints
only, through a recording pickle module that logs every `find_class` call and
each pickle read. Torch handles `*Storage` names itself, so they are not
logged.

## Rows

Release rule: **P1 V1 S1 S2 W1 G1 B1 F1 F2 F3 F4 E1 must all hold**.

| # | prediction |
|---|---|
| P1 | The patch applies once (docstring, version, walker, bare branch). A second pass is a no-op, no line is lost, and the result compiles. |
| V1 | base nemo 0.2.0, tree 0.3.0; model-file-scan 0.12.1 in both |
| S1 | The full suite on the patched tree passes and runs exactly the base suite's count + 16 tests. |
| S2 | The new module alone: exit 0, 16 tests. |
| W1 | All 7 files are written. L1-L4 checkpoints start with torch's legacy header; Z1 and Z2 start `PK\x03\x04`. |
| G1 | `torch.load` reads the L1-L4, Z1 and Z2 checkpoints without error and logs `collections OrderedDict` and `torch._utils _rebuild_tensor_v2`. On L1-L4 it reads exactly 5 pickles. |
| B1 | 0.2.0 reports **nothing** on L1-L4 (the gap). |
| F1 | 0.3.0 reports exactly one finding on each of L1-L4: NEMO010, with "legacy torch.save, 5 of 5 pickles" in its evidence. |
| F2 | On L1-L4, Z1 and Z2, every import the loader logs is among the imports 0.3.0 lists for the checkpoint member. |
| F3 | Z1 and C1 findings are identical in 0.2.0 and 0.3.0 (C1: none). Z2 has the same rules. |
| F4 | `model-file-scan --json` (tree) exits 1 on L1-L4, Z1 and Z2 (NEMO010 is medium; the CLI fails on medium by default) and 0 on C1. Base exits are reported. |
| E1 | `model-file-scan --json` on the folder of 7 files exits 1 and lists 7 files. |

Not gating (a Hub census, headers only, never loaded). The 100 most
downloaded public repos tagged `nemo` are covered, at most 2 `.nemo` files
each and 120 files in all. The first 1,024 bytes are read with an HTTP Range
request. For a plain tar, each member's header and the first 64 bytes of its
content are read (at most 80 members per file, 2,500 requests in all).
Compressed tars are counted, not walked.

| # | prediction |
|---|---|
| H1 | At least 60 plain `.nemo` files are walked to a weights member (`*.ckpt`/`*.pt`/`*.pth`/`*.bin`). |
| H2 | At most 1% of those weights members are legacy-format (we expect 0: NeMo's `.nemo` format postdates PyTorch 1.6). |
| H3 | If any legacy `.nemo` of 100 MB or less exists, it is downloaded and read as bytes: 0.2.0 reports nothing and 0.3.0 reports NEMO010. Otherwise "not run". |

Reported, not graded: tar containers (plain/gzip/bz2/xz), member kinds,
the names of pickle and zip members, and how many files hit the member cap.

## If H2 holds

That means the fix matters little for public NeMo models. It closes a silent
case for private or older checkpoints and makes the gate match its own
docstring. We will say so plainly and not oversell it.

## Limits

- The legacy files are our own, written by current `torch` with the legacy
  flag. They are not files written by PyTorch before 1.6.
- No loader is ever given planted input. Hub files are only read as bytes.
- Prior art: we found no published census of the checkpoint format inside
  public `.nemo` files other than our own size census (v0.53.0). How other
  scanners handle this case was not surveyed.
