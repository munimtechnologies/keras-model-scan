# Chat-template SSTI scanner (`chat_template_scan.py`)

A static, no-execution scanner that reads a model's **Jinja2 chat template** and
flags the server-side-template-injection (SSTI) "gadget" tokens that an ordinary
chat template has no reason to contain. Standard library only — no Jinja2, no
model framework, nothing is ever rendered.

*Made with AI by MV2 of Munim, Inc. Licensed under Apache-2.0.*

## Why this matters

A chat template is the rule that turns a list of chat messages into the single
prompt string a model sees. It ships inside the model's own files, in three
carriers:

- the `chat_template` field of **`tokenizer_config.json`** (a string, or a list
  of `{"name": ..., "template": ...}` objects for named templates);
- a **`chat_template.jinja` / `*.jinja` / `*.j2` sidecar** file; and
- the **`tokenizer.chat_template` metadata key inside a `.gguf`** file.

Whoever publishes a model controls that template. Several loaders have rendered
it with an **unsandboxed** Jinja environment
(`jinja2.Environment(...).from_string(chat_template)`), so a crafted template can
reach Python internals and run code the moment the model is loaded — a classic
SSTI → RCE chain. Because the payload is *valid Jinja logic*, not binary
malware, it can slip past serialization- and malware-focused scanners.

### Public cases (all already fixed; nothing here is a zero-day)

| Advisory | Project | Carrier | Fix |
|---|---|---|---|
| CVE-2024-34359 / GHSA-56xg-wfcc-g829 | abetlen/llama-cpp-python | `.gguf` `tokenizer.chat_template` | switched to `ImmutableSandboxedEnvironment` (0.2.72) |
| huntr SSTI report | berriai/litellm | HF `chat_template` via `hf_chat_template` | sandboxed environment |
| PR #1475 | guidance-ai/guidance | model-file chat template | `ImmutableSandboxedEnvironment` |

Classes: **CWE-94** (code injection), **CWE-1336** (server-side template
injection). A representative payload (inert here, never rendered):
`{{ cycler.__init__.__globals__.os.popen('id').read() }}`.

## What it flags

| Code | Severity | What it means |
|---|---|---|
| `CT001` | HIGH | Python dunder attribute access (`__class__`, `__globals__`, `__subclasses__`, `__mro__`, `__init__`, `__builtins__`) |
| `CT002` | HIGH | Jinja builtin SSTI global used as a pivot (`cycler`, `lipsum`, `joiner`) |
| `CT003` | HIGH | OS / process / dynamic-import call (`os.system(`, `popen(`, `subprocess`, `eval(`, `exec(`, `importlib`, `__import__(`) |
| `CT004` | MEDIUM | Dynamic attribute-access bypass (`\|attr`, `getattr(`) |
| `CT005` | MEDIUM | Web-framework SSTI global (`request.`, `url_for(`, `get_flashed_messages`, `self._`) |
| `CT006` | MEDIUM | Template `import` / `from` / `include` / `extends` tag |

**Deliberately not flagged** to avoid false positives on real templates:
`namespace(...)` (legitimately used by current Llama/Qwen/Mistral templates), the
bare word `system` (the system *role*), and ordinary `{% if %}`/`{% for %}`
control flow.

## Usage

```bash
# scan a downloaded model directory, fail CI on any HIGH finding
python chat_template_scan.py ./model-dir --fail-on HIGH

# scan one file, emit JSON
python chat_template_scan.py ./model/tokenizer_config.json --json
```

Exit code is non-zero when any finding meets `--fail-on` (default `HIGH`).

## Honest limits

- This is a **lint, not a sandbox**. A clean scan does **not** prove a template
  is safe — novel gadgets, encodings, or whitespace tricks can evade a static
  token match.
- The real fix is on the *loader* side: render any untrusted chat template only
  inside `jinja2.sandbox.ImmutableSandboxedEnvironment` (what Hugging Face
  `transformers` already does).
- GGUF-embedded templates: extract the `tokenizer.chat_template` metadata string
  with the repository's existing GGUF reader, then pass it to
  `scan_template_string(text, "gguf-metadata", path)`.
- Every advisory named above is public and already patched; this tool describes
  *detection*, not exploitation.

## Prior art (named honestly)

A chat-template SSTI *detector* is not new. promptfoo's **ModelAudit** ships a
Jinja2 template scanner (covers `.gguf`/`.json`/`.jinja`, including
CVE-2024-34359), and **r0b0tlab/model-audit** inspects `tokenizer.chat_template`.
Both pull in their own dependencies. The contribution here is narrower and
specific: a **standard-library-only, no-execution** detector that reads the
template statically across the three carriers above and maps each finding class
to the public advisory — the same dependency-free, reproducible shape as the
other scanners in this repository.

## Reproducibility

`test_chat_template_scan.py` is self-contained (standard library only, no Jinja2
installed). It checks a realistic benign template stays clean, that `namespace`
and the `system` role are not false-flagged, and that each documented payload
class is detected across the string, `tokenizer_config.json`, directory-walk and
CLI paths.
