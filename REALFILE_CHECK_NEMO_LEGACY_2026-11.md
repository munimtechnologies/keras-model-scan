# Real-file check: legacy-format checkpoints inside `.nemo` files (job `nemo-legacy-v1`)

Made with AI agents working in the name of MV2 of Munim, Inc. Text CC BY 4.0,
code Apache-2.0. Graded 9 November 2026 (UTC) against the pre-registration
[research/PREREG_NEMO_LEGACY.md](research/PREREG_NEMO_LEGACY.md), which was
published before the job ran. Job code: [research/nemo-legacy/](research/nemo-legacy/).
Raw results: [research/nemo-legacy/results/](research/nemo-legacy/results/).

**Result: all 12 release rows held. Of the 3 Hub rows, H2 held, H1 failed
(55 files walked, 60 predicted), and H3 was not run (no legacy `.nemo` exists to
test).** The fix (`nemo_container_scan` 0.3.0) ships in release v0.56.0.

## The gap

`nemo_container_scan` 0.2.0 walked a bare-pickle member of a `.nemo` tar with
one `pickletools.genops` pass, which stops at the first STOP. A legacy-format
`model_weights.ckpt` (`torch.save(..., _use_new_zipfile_serialization=False)`)
is five pickles back to back, and the first is torch's 15-byte magic number. So
0.2.0 reported **nothing at all** for such a checkpoint, not even the NEMO010
note that the zip-format checkpoint of the same model gets. Its own docstring
said the legacy format was covered.

## Graded rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once, second pass no-op, nothing lost, compiles | held |
| V1 | base nemo 0.2.0, tree 0.3.0, model-file-scan 0.12.1 in both | held |
| S1 | full suite on the patched tree passes, base count + 16 | held: 1,397 = 1,381 + 16, 0 failures |
| S2 | new module alone: exit 0, 16 tests | held |
| W1 | all 7 files written with the right headers | held |
| G1 | `torch.load` reads L1-L4, Z1, Z2; OrderedDict + `_rebuild_tensor_v2`; 5 pickles on L1-L4 | held |
| B1 | **the gap**: 0.2.0 reports nothing on L1-L4 | held on all 4 |
| F1 | 0.3.0: exactly one NEMO010 on each of L1-L4, evidence "legacy torch.save, 5 of 5 pickles" | held on all 4 |
| F2 | every import the loader logs is listed by 0.3.0, on L1-L4, Z1, Z2 | held (0.2.0 listed none of them on L1-L4) |
| F3 | Z1 and C1 identical in both versions, Z2 same rules | held |
| F4 | CLI (tree) exits 1 on L1-L4, Z1, Z2 and 0 on C1 | held (base exited 0 on L1-L4) |
| E1 | CLI on the folder of 7 files: exit 1, 7 files listed | held |
| H1 | at least 60 plain `.nemo` files on the Hub walked to a weights member | **failed: 55** |
| H2 | at most 1% of their weights members are legacy format | held: **0 of 280** |
| H3 | a legacy `.nemo` of 100 MB or less is checked | not run: none exists in the sample |

L1-L4 are legacy checkpoints (protocol 2, protocol 4, a checkpoint dict with
SGD momentum, and a gzip tar as older NeMo wrote); Z1/Z2 are zip-format
controls; C1 is a config-only control. torch 2.15.0+cpu wrote them all.

## Published files (headers only, nothing loaded)

The 100 most downloaded public repos tagged `nemo` gave 58 `.nemo` files
(55 plain tars, 3 gzip tars counted but not walked). Walking member headers
with HTTP Range requests found 280 weights members (sharded checkpoints
account for most), and **all 280 are zip format; none is legacy**. One walk
hit an error.

So, as we said before the run: the fix matters little for public NeMo
models. It closes a silent case for private or older checkpoints and makes
the scanner do what its docstring says. H1 failed because fewer of the top
repos have a plain `.nemo` than we expected, not because of the scanner.

## Limits

- The legacy files are our own, written by current torch with the legacy
  flag, not files written by PyTorch before 1.6.
- No loader was given planted input; Hub files were only read as bytes.
- How other scanners handle this case was not surveyed.
