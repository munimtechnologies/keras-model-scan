# Pre-registration: model-file-scan routes TensorFlow SavedModels (job tfsm-route-v1)

Filed 12 November 2026, before the job runs. Made with AI agents working in
the name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## The gap

This repository has shipped `tf_savedmodel_ops_scan` (rules TFSM001,
TFSM002, TFSM003 and TFSM005: graph ops that write files, read or list files,
or call back into host Python) as a standalone module with its own tests.
But the unified `model-file-scan` command, which the GitHub Action and the
agent skill run, never calls it. Up to model-file-scan 0.14.0 (release
v0.60.0):

- a folder scan skips `saved_model.pb` without a word (`.pb` is not in the
  walk list), so scanning a SavedModel directory reports "no model files
  found" or only its other files;
- a `saved_model.pb` named on the command line goes to the pickle scanner,
  which reports only `PKL099` (INFO, "Unrecognised file format");
- `pyproject.toml` does not list the module, so `pip install` leaves it out.

## Which files TensorFlow reads (from TensorFlow's source)

- `tensorflow/cc/saved_model/constants.h` names `saved_model.pb`,
  `saved_model.pbtxt` and a chunked `saved_model.cpb`, plus
  `fingerprint.pb` and `debug/saved_model_debug_info.pb`.
- `tensorflow/cc/saved_model/reader.cc` and `parse_saved_model` in
  `tensorflow/python/saved_model/loader_impl.py` read `saved_model.pb`
  first and `saved_model.pbtxt` only when there is no `.pb`. The open-source
  readers build the `.cpb` path but never read it (its merger is a
  placeholder outside open-source builds), so `.cpb` is out of scope here.

## The change under test

model-file-scan 0.15.0 (version number relative to v0.60.0; see the release
rule):

- `.pb` and `.pbtxt` route to `tf_savedmodel_ops_scan` (new kind `tfsm`).
- Folder walks keep every `.pb` (SavedModels, frozen GraphDefs,
  `keras_metadata.pb`, `fingerprint.pb`) and, of the `.pbtxt` files, only
  `saved_model.pbtxt`. Other `.pbtxt` files are label maps and configs.
- The pickle scanner also runs when a `.pb` / `.pbtxt` does not start like a
  TensorFlow protobuf: binary field 1 or 2 (`0x08`, `0x0a`, `0x12`), or text
  naming SavedModel/GraphDef fields. So a pickle, ZIP or compressed stream
  that only carries a `.pb` name keeps its pickle checks, as `.skops` does.
- `pyproject.toml` lists `tf_savedmodel_ops_scan`.
- 21 new unit tests (`test_model_file_scan_tfsm.py`, standard library only,
  hand-encoded protobufs built with the existing test helpers): routing,
  route_kinds, walk contents and dispatch through `scan_path` and `main`.
  Nothing is ever loaded or executed.

The scanner module itself (`tf_savedmodel_ops_scan` 0.1.0) is unchanged.

## The job (sealed container, CPU only)

Setup (network): download v0.60.0 twice (`tree` is patched, `base` is not);
install CPU-only TensorFlow; list the 1,000 most-downloaded models tagged
`keras`, `tf-keras` and `tf` on the Hugging Face Hub. Then download up to 60
`saved_model.pb` files (one per open model, most downloaded first, at most
64 MB each and 1.5 GB in all) plus `keras_metadata.pb` and `fingerprint.pb`
from the same folder. Variables and assets are never downloaded.

Run (no network): TensorFlow writes five honest SavedModels with its public
API (`plain` tf.Module matmul; `table` StaticHashTable from a vocabulary
asset; `read_asset` tf.io.read_file of an asset; `textline`
tf.data.TextLineDataset over an asset; `keras` a small Keras model
exported as a SavedModel). No saved function is ever called. Ground truth is
TensorFlow's own `SavedModel` protobuf class (`ParseFromString` only; no
model is loaded). Then: patch `tree`, run both full suites, grade.

## Rows (each is reported as held, failed or untestable)

- **S1 (no regressions):** every patch edit matches once; the patched suite
  has no failing test that the base suite does not also have, none of the
  SavedModel tests fail, and it runs at least 21 more tests than the base.
- **F1 (decoder = TensorFlow, writer files):** at least 4 of the 5 fixtures
  are written (else untestable). On each one, the multiset of op names that
  the scanner's decoder reads (graph nodes plus every function's nodes)
  **equals** the multiset that TensorFlow's protobuf class reads.
- **F2 (routing on writer files):** patched `model-file-scan --json <dir>`
  on each fixture directory scans its `saved_model.pb`, exits 0 or 1, and
  reports exactly: `plain` none; `table` exactly {TFSM003}; `read_asset`
  includes TFSM002 and not TFSM001; `textline` includes TFSM002 or TFSM003
  and neither TFSM001 nor TFSM005; `keras` none.
- **B1 (the gap, recorded):** v0.60.0 `model-file-scan` on the same
  directories does not scan any `saved_model.pb`. Expected to hold. It
  describes the gap and does not gate the release.
- **H1 (decoder = TensorFlow, published files):** TensorFlow parses at
  least 30 fetched Hub `saved_model.pb` files, and on **every** one the
  decoder's op multiset equals TensorFlow's.
- **H2 (routing on published files):** for at least 30 fetched Hub files,
  patched `model-file-scan` on the downloaded folder scans `saved_model.pb`
  and exits 0 or 1 (never 2, "errored").
- **H3 (false-positive ceiling):** at most 10% of the fetched Hub
  `saved_model.pb` files get a HIGH TFSM finding.
- **H4 (sidecar files stay quiet):** every fetched `keras_metadata.pb` and
  `fingerprint.pb` gets zero findings and no error. Untestable if fewer than
  10 were fetched.

Measured and reported, not graded: how many listed models ship
`saved_model.pb`, `saved_model.pbtxt`, `saved_model.cpb` or any `.pb`; the
most common other `.pb` names; per rule, how many Hub files it fires on;
how many Hub models contain each watched op; and the share of Hub files
that would fail the default `--fail-on medium` gate.

## Release rule

Release only if S1, F1, F2, H1, H2 and H3 all held and H4 did not fail.
Every row is published whatever the outcome. The release number depends on
order. If the separately pre-registered `.ptd` scanner (job ptd-scan-v1)
ships first as v0.61.0 (model-file-scan 0.15.0), these same routing edits are
applied on top of it as model-file-scan 0.16.0 / v0.62.0, and the release
commit re-runs both routing test files before it is committed. If H1 fails,
each mismatching file is read against TensorFlow's `graph.proto` /
`function.proto` and the decoder gets its own pre-registered fix. If H3
fails, the flagged ops are listed and the severity policy is reconsidered
in a new pre-registration before any release.

## Honest limits

- The scanner reports graph ops only. It does not judge weights, Keras
  Lambda layers inside `keras_metadata.pb` (sibling modules cover Keras
  configs), or custom ops registered by the loading process.
- `saved_model.cpb` (chunked) is not parsed. Open-source TensorFlow does not
  read it either.
- The Hub sample is the top of three tag lists by downloads, and files over
  64 MB are skipped and counted, so it is not a random sample of every
  SavedModel.
- The TensorFlow version is whatever `pip install tensorflow-cpu` gives on
  the day; it is recorded.
