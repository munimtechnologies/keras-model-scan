# Real-file check: ONNX local functions and big inline models in the external-data scanners (graded; release waits for the gate)

Made with AI agents working in the name of MV2 of Munim, Inc. CC BY 4.0.
Graded 7 November 2026 (UTC). Pre-registration:
[research/PREREG_OED_FUNCTIONS.md](research/PREREG_OED_FUNCTIONS.md) and its
[Amendment 1](research/PREREG_OED_FUNCTIONS_AMENDMENT_1.md), both committed
before job `oed-functions-v2` ran (2026-11-07 00:04 to 00:07 UTC). Raw
results: [research/oed-functions/results/oed_summary.json](research/oed-functions/results/oed_summary.json).

## Result

**13 of 13 graded predictions held. None were skipped. The harness reported
no scan errors** (the first run, v1, never reached the scanners because of a
harness bug; see the amendment).

The release rule holds. But the pre-registration also says: if another
release ships first, the suite is re-run on the new main before publishing.
`nemo_container_scan` 0.2.0 ships first, in v0.53.0. So the two patched
scanners are published now only as a **candidate** in
[research/candidates/oed-functions/](research/candidates/oed-functions/),
exactly as the job wrote them, and become the live modules after the release
gate passes: job `gate-oed-v1`, pre-registered in
[research/PREREG_RELEASE_GATE_OED.md](research/PREREG_RELEASE_GATE_OED.md).

## What the fix closes

1. **Local functions.** Up to 0.1.0, `onnx_external_data_scan` and
   `onnx_external_data_key_scan` walked only `ModelProto.graph`. onnx's own
   loader also loads external data for tensors inside the model's local
   functions (`ModelProto.functions`), and `onnx.save_model(...,
   save_as_external_data=True, convert_attribute=True)` writes them that
   way. Row W1 confirmed it with onnx 1.23.2: the function's Constant was
   stored at `weights.bin`, offset 4096. So a location the loader follows was
   never checked. 0.2.0 walks function nodes, function `attribute_proto`,
   and both `training_info` graphs.
2. **Big inline models.** 0.1.0 read at most 256 MiB and stopped quietly, so
   any tensor entry after that point in a bigger single-file model was never
   seen. 0.2.0 reads up to protobuf's 2 GiB message limit (in 16 MiB chunks)
   and reports OED006 (medium) instead of passing quietly when a file is
   bigger than that.

How common are such files? Among `.onnx` files in the 100 most-downloaded
Hugging Face repos tagged `onnx` (file-size metadata only): 555 files, of
which **174 (31%) are between 256 MiB and 2 GiB** (162 distinct blobs, 62
repos; for example openai-community/gpt2's `onnx/decoder_model.onnx`,
653,665,842 bytes). None are over 2 GiB. For files in that band, 0.1.0 checked
only the first 256 MiB.

## Versions

Live `main` after v0.52.1 (model-file-scan 0.12.0; both scanners 0.1.0) and
the patched 0.2.0 of both. onnx 1.23.2, numpy 2.5.4. Container
`python:3.12`; the run steps had no network. Planted files were made by
editing one `external_data` entry of a proto and writing the bytes; onnx
never loaded a planted file.

## Rows

| # | prediction | result |
|---|---|---|
| P1 | patch applies once to both scanners and both docs; second pass no-op; compiles | held |
| S1 | full unit-test suite on the patched tree | held: 1,341 run, 0 failures, 0 errors, 3 skipped |
| W1 | onnx stores the function Constant externally (`weights.bin`), as well as the graph initializer | held (function tensor at offset 4096, length 4096) |
| L1 | `onnx.load` fills the function tensor back from `weights.bin` | held (4,096 bytes, equal to those written) |
| H1 | 0.2.0 silent on all four honest files (incl. a 272 MB inline model); key scanner 0.2.0 silent on three | held |
| E1 | function Constant at `../outside.bin`: 0.1.0 nothing, 0.2.0 {OED001} | held |
| E2 | function default attribute at `/abs/w.bin`: 0.1.0 nothing, 0.2.0 {OED002} | held |
| E3 | training_info initializer at `..\t.bin`: 0.1.0 nothing, 0.2.0 {OED001, OED005} | held |
| E4 | `../after.bin` after byte 268,435,456 of a 272 MB model: 0.1.0 nothing, 0.2.0 {OED001} | held (entry at byte 272,000,079) |
| K1 | extra `owner` key on a function tensor: key 0.1.0 nothing, 0.2.0 OEK001 for `owner` | held |
| C1 | control, graph initializer at `../g.bin`: {OED001} from both | held |
| T1 | 0.2.0 scans the 272 MB file in under 60 s and 1,024 MB | held: 0.37 s, 309.5 MB (0.1.0: 0.19 s, 274.4 MB) |
| Hb | at least 10 files between 256 MiB and 2 GiB in the onnx-tagged top 100 (not gating) | held: 174 |

Hb is graded as written, but we had seen v1's count of a different
population (33 files, because the Hub API ignores `library=`) before v2 ran.

## Limits

- These are coverage gaps in our own CI gates, found by reading source.
  Current onnx releases check external-data paths themselves, so a finding
  is defence in depth for a pipeline, not evidence of a live onnx bug. No
  loader was given a planted file.
- 0.2.0 holds the file in memory (309.5 MB peak for a 272 MB model);
  `onnx_external_data_key_scan` reads the whole file with no cap.
- One onnx release (1.23.2) wrote the files. The Hub census uses file sizes
  only.
- Prior art: promptfoo's ModelAudit already walks function nodes,
  `attribute_proto` and both training_info graphs (read 2026-11-06). This
  catches our gate up; it is not a new kind of check.
