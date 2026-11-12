# Pre-registration: model-file-scan checks GGUF chat templates (job gct-route-v1)

Filed 12 November 2026, before the job runs. Made with AI agents working in
the name of MV2 of Munim, Inc. Apache-2.0 (code), CC BY 4.0 (this text).

## The gap

A `.gguf` file stores the model's Jinja chat template as a metadata string
(`tokenizer.chat_template`, plus named `tokenizer.chat_template.<name>`
variants). Servers that rendered it without a sandbox were open to template
injection: CVE-2024-34359 (llama-cpp-python) and CVE-2026-5760 (SGLang).
This repository has shipped `gguf_chat_template_scan` (0.20.0; rules
CT001-CT006 and GCT000) for that string as a standalone module. But up to
model-file-scan 0.14.0 (release v0.60.0), the unified `model-file-scan`
command never calls it. That is the command the GitHub Action and the agent
skill run:

- a `.gguf` goes only to `gguf_scan`, whose header and tensor-info checks
  never read the template string;
- `pyproject.toml` does not list the module, so `pip install` leaves it out;
- the module's own `scan_file()` reads the whole file into memory, which
  does not work on multi-GB model files.

## The change under test

model-file-scan 0.15.0 (version relative to v0.60.0; see the release rule):

- The existing `gguf` kind becomes an adapter that runs `gguf_scan` as
  before and then checks every `tokenizer.chat_template*` string with
  `gguf_chat_template_scan`'s own metadata reader and pattern check. No
  route, walk or kind changes.
- Only the head of the file is read: 16 MB, then 64 MB (`gguf_scan`'s own
  cap) if the metadata table runs past the first read. A table that runs
  past 64 MB, or that cannot be parsed, gives one `GCT000` (LOW, "chat
  template not checked"). The template is never rendered.
- Template findings keep the module's code as the rule (`CT001`...) and its
  severity, and are tagged CWE-1336.
- `pyproject.toml` lists `gguf_chat_template_scan`.
- 17 new unit tests (`test_model_file_scan_gct.py`, standard library only,
  GGUF bytes built by hand). The path that carries a finding is tested with
  fake scanner modules, so no test file holds a payload.

`gguf_chat_template_scan` 0.20.0 and `gguf_scan` are unchanged.

## The job (sealed container, CPU only)

Setup (network): download v0.60.0 twice (`tree` is patched, `base` is not);
install `gguf` (llama.cpp's Python package); list the 1,000 most-downloaded
models tagged `gguf` on the Hugging Face Hub. For up to 300 open models,
most downloaded first, pick one `.gguf` (not an `mmproj` projector, not a
later split shard; `Q4_K_M` when present, else the first by name). Download
only its first 16 MB with an HTTP Range request, or the first 64 MB when the
metadata runs past 16 MB. Files of 100 MB or less are downloaded whole (at
most 25). Tensor data past the head is never downloaded.

Run (no network): llama.cpp's `GGUFWriter` writes five honest fixtures, each
with one small tensor: `plain` (no template), `chatml`, `named` (a default
plus a `tool_use` template, written as llama.cpp's converter does),
`bigendian`, and `bigmeta` (a 1.3-million-entry token list before the
template, so the template sits past the first 16 MB). Then patch `tree`, run
both full test suites, and grade. Patched and base model-file-scan run
in-process with a counter around the template reader, so each row can show
that the check actually ran. Ground truth is llama.cpp's `GGUFReader`
(metadata and tensor-info only; tensor data is not built).

## Rows (each is reported as held, failed or untestable)

- **S1 (no regressions):** every patch edit matches once; the patched suite
  has no failing test that the base suite does not also have; none of the
  17 new tests fails or is skipped; and the patched suite runs at least 17
  more tests than the base.
- **F1 (reader = llama.cpp, writer files):** at least 4 of the 5 fixtures
  are written (else untestable). On each one, the list of (key, template)
  pairs the route extracts **equals** the list `GGUFReader` reads, in order.
  On `bigmeta` (which must be larger than 16 MB), the route reads twice.
- **F2 (routing on writer files):** patched `model-file-scan --json` on each
  fixture folder exits 0 or 1, the template reader runs, and there is no
  CT or GCT finding.
- **B1 (the gap, recorded):** v0.60.0 never calls the template reader on the
  fixture folders. Expected to hold. It describes the gap and does not gate
  the release.
- **H1 (reader = llama.cpp, published files):** `GGUFReader` parses at
  least 100 fetched Hub files, and on **every** one the extracted (key,
  template) list equals `GGUFReader`'s.
- **H2 (routing on published files):** on at least 100 fetched Hub files,
  patched `model-file-scan` runs the template reader and exits 0 or 1
  (never 2, "errored"). For files cut at 16 or 64 MB, `gguf_scan`'s own
  findings are expected, are not graded here, and are listed.
- **H3 (HIGH ceiling, honest templates):** of the distinct template strings
  found (at least 50, else untestable), at most 2% get a HIGH finding
  (CT001, CT002 or CT003).
- **H4 (default-gate ceiling):** of the same distinct strings, at most 5%
  get any MEDIUM or HIGH finding. That is what would make
  `model-file-scan`'s default `--fail-on medium` gate fail on a popular,
  honest model.

Measured and reported, not graded: how many listed models are open, ship
`mmproj` or split files; files with a template, with a named template or with
an array-valued template; per rule, how many distinct templates and files it
fires on and which words it matched; the most-shared flagged templates, with
the models that carry them, for manual review; exit-code counts for patched
and base; and versions.

## Prediction, stated before the run

The pattern check matches words, not code. Popular templates include long
system prompts in plain English, so we expect H3 and/or H4 may **fail**:
words such as "request", "config" or "commands" in prose would trigger
CT005 or CT003. MV2's earlier DEV write-up of the module said ordinary
templates give no findings, but gave no corpus numbers. This job measures
it on real files either way, and the write-up gets a correction if the
measurement disagrees.

## Release rule

Release only if S1, F1, F2, H1, H2, H3 and H4 all held. Every row is
published whatever the outcome. If H3 or H4 fails, nothing is routed. The
flagged words are listed, and any change to the pattern check gets its own
pre-registration before a release. The release number depends on order: the
`.ptd` scanner (job ptd-scan-v1) and SavedModel routing (job tfsm-route-v1)
are also pre-registered against v0.60.0. If either ships first, these edits
are applied on top of it as the next model-file-scan minor version, and the
release commit re-runs every routing test file before it is committed.

## Honest limits

- The pattern check flags known-suspicious words. It is not a proof of
  safety, and a clean result guarantees nothing. The real defence is to
  render templates in a sandboxed Jinja environment.
- `tokenizer.chat_templates`, an array of template *names*, starts with the
  same prefix, so the module also checks those names. They are short and
  are counted as distinct strings.
- The Hub sample is the top 1,000 `gguf` models by downloads, one file each,
  so it is not a random sample of every GGUF. Shared templates are counted
  once in H3/H4 and per file in the measurements.
- The gguf package version is whatever `pip install gguf` gives on the day;
  it is recorded.
