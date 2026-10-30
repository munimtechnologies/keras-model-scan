# Real-file check, October 2026: msgpack_weights_scan.py and archive_payload_scan.py

Graded 2026-10-30. Made with AI agents working in the name of MV2 of Munim,
Inc. Text CC BY 4.0; script Apache-2.0
([`research/realfile_check_2026_10.py`](research/realfile_check_2026_10.py)).

## What was checked

The two scanners' tests use bytes built by hand from the published formats.
This check asks a different question: do they read files written by the
**real libraries** correctly, with no false alarms on normal files?

The expectations were written down before the job ran (pre-registration
below, unchanged). The job ran once in a sealed local container
(`python:3.12`, 2 CPUs, 2 GB; network only for `pip install`, none while the
checks ran) on 2026-10-30, 07:10 to 07:16 UTC. Libraries installed: torch
2.15.0+cpu, numpy 2.5.4, msgpack 1.2.4, msgpack-numpy 0.4.8, flax 0.12.12
with jax 0.12.0.1, keras 3.15.1. `archive_payload_scan.py` was taken from this
repository's `main`. The module's own 33 unit tests passed in the same
container first.

## Result: 13 of 13 predictions held (17 of 17 checks)

| # | prediction | result | evidence |
|---|---|---|---|
| 1 | msgpack-numpy plain float32 array + float64 scalar: no findings | PASS | `[]` |
| 2 | object array of builtins: exactly MPK002 | PASS | imports `_codecs.encode`, `numpy._core.multiarray._reconstruct`, `numpy.dtype`, `numpy.ndarray` |
| 3 | object array holding `fractions.Fraction`: exactly MPK001, evidence names it | PASS | evidence lists `fractions.Fraction` |
| 4 | `msgpack_numpy.decode` really unpickles that element | PASS | element type is `Fraction` |
| 5 | Flax state dict (float32, bfloat16, int8, int64 scalar, float64, complex): no findings, and it round-trips | PASS | `[]`; kernel shape `(4, 3)` restored |
| 6 | Flax ext-1 payload, shape (2, 3) float32 with a 20-byte buffer: exactly MPK003, and `msgpack_restore` raises | PASS | "needs 24 bytes but the buffer holds 20"; restore raised |
| 7 | `torch.save` of a `Linear` state dict: no findings | PASS | `[]` |
| 8 | TorchScript export (has `code/**/*.py`): no findings | PASS | `[]` |
| 9 | `np.savez`: no findings | PASS | `[]` |
| 10 | Keras v3 `.keras` (jax backend): no findings | PASS | `[]` |
| 11 | `.tar.gz` holding files 7 to 10 (nested zips): no findings | PASS | `[]` |
| 12 | zip holding the image's real `/bin/ls` stored as `model.bin`: exactly ARC001, "the file name does not say so" | PASS | `with_binary.zip!weights/model.bin: ELF; the file name does not say so` |
| 13 | zip holding `run.sh` starting `#!/bin/sh`: exactly ARC002 | PASS | `shebang script '#!/bin/sh'` |

## Notes

- Prediction 5 says `to_bytes`; the script called
  `flax.serialization.msgpack_serialize` on the state dict directly. For a
  plain dict the two write the same bytes (`to_bytes` is
  `msgpack_serialize(to_state_dict(x))`).
- Prediction 4 confirms what the msgpack-numpy MPK001 rule is about: an
  object-dtype array in msgpack-numpy's format goes through `pickle.loads`.
  That behaviour is already public (an open pull request in msgpack-numpy and
  a public huntr report); it isn't presented here as a new finding.
- The job's "versions" line shows `msgpack-numpy ?` because the module has no
  `__version__`; pip's log shows 0.4.8.
- An automated job graded each check against the pre-registered value. No
  person re-ran it by hand.

## Pre-registration (written 2026-10-30, before the job ran)

> Job `mpk-arc-realfile-v1` (local sandbox, no network during run steps) writes
> files with the real libraries and scans them. Expectations, each graded
> PASS/FAIL:
>
> msgpack-numpy (msgpack + msgpack-numpy + numpy)
> 1. Plain float32 array + float64 scalar packed with `msgpack_numpy.encode` ->
>    no findings.
> 2. Object array of builtins (`[1, "a", None]`) -> exactly `MPK002` (only
>    numpy's reconstruction globals; numpy 2.x writes
>    `numpy._core.multiarray._reconstruct`).
> 3. Object array holding `fractions.Fraction(1, 3)` (harmless stdlib class) ->
>    exactly `MPK001`, evidence names `fractions.Fraction`.
> 4. Behaviour claim: `msgpack.unpackb(..., object_hook=msgpack_numpy.decode)`
>    on file 3 returns an array whose element is a `Fraction`, i.e. the data
>    really was unpickled.
>
> Flax (flax + jax CPU)
> 5. `flax.serialization.to_bytes` of a dict with float32 kernel/bias, a
>    bfloat16 array, an int8 array, an int64 numpy scalar, a float64 scalar and
>    a Python complex -> no findings, and `msgpack_restore` round-trips it.
> 6. A hand-made Flax ext-1 payload of shape (2, 3) float32 with a 20-byte
>    buffer -> exactly `MPK003`, and `flax.serialization.msgpack_restore`
>    raises on it.
>
> Archives (torch CPU, numpy, keras with the jax backend)
> 7. `torch.save(nn.Linear(4, 3).state_dict())` -> no findings.
> 8. `torch.jit.script(nn.Linear(4, 3)).save(...)` (TorchScript, has
>    `code/**/*.py`) -> no findings.
> 9. `np.savez` with two arrays -> no findings.
> 10. Keras v3 `.keras` of a one-Dense-layer model -> no findings.
> 11. A `.tar.gz` holding files 7, 8, 9 and 10 (nested zips) -> no findings.
> 12. A zip holding the image's real `/bin/ls` stored as `model.bin` plus
>     file 9 -> exactly one `ARC001`, evidence contains "the file name does not
>     say so".
> 13. A zip holding `run.sh` that starts `#!/bin/sh` -> exactly one `ARC002`.
>
> Any FAIL is reported as found and fixed in the scanner (or the expectation),
> not hidden.

## Limits

One small file per case and one version of each library. This shows the
scanners read these writers' real output and stay quiet on normal files. It
doesn't measure false-positive rates on published models.
