# GGUF chat-template SSTI scanner (`gguf_chat_template_scan.py`)

*Made with AI by MV2 of Munim, Inc. Licensed under Apache-2.0.*

A static, **no-execution** scanner that reads a GGUF model file's embedded
chat template (`tokenizer.chat_template` metadata) and flags server-side
template-injection (SSTI) patterns in it. It is the GGUF-carrier companion to
`chat_template_scan.py` (v0.18.0), which only reads `tokenizer_config.json`
strings and `.jinja` sidecars and therefore never sees a template carried
*inside* a `.gguf` binary.

## The vector

A `.gguf` file is a binary container with no code of its own. But llama.cpp and
its converters store the model's Jinja2 chat template as a **string** in the
GGUF metadata key `tokenizer.chat_template` (multi-template models use
`tokenizer.chat_template.<name>` keys). Several inference servers render that
template with an **unsandboxed** `jinja2.Environment`, so a crafted template is
SSTI and, in the worst case, remote code execution at inference time.

Public, fixed advisories for exactly this vector:

| Advisory | Product | Fixed in | Class | Impact |
|---|---|---|---|---|
| [CVE-2024-34359](https://osv.dev/vulnerability/CVE-2024-34359) / [GHSA-56xg-wfcc-g829](https://github.com/advisories/GHSA-56xg-wfcc-g829) | llama-cpp-python | 0.2.72 | CWE-76 / CWE-1336 | SSTI → RCE via model-metadata chat template |
| [CVE-2026-5760](https://nvd.nist.gov/vuln/detail/CVE-2026-5760) | SGLang `/v1/rerank` | 0.5.11 | CWE-94 | RCE (CVSS 9.8) via unsandboxed render of a GGUF chat template |

## What it does

`scan_path` walks a directory for `.gguf` files (or scans one file). For each,
it reads **only** the GGUF header and metadata key/value table — never tensor
data — extracts every `tokenizer.chat_template*` string, and applies the SSTI
heuristic as **text** (the template is never rendered). Findings reuse the
chat-template family's codes:

| Code | Severity | Flags |
|---|---|---|
| CT001 | HIGH | Python dunder attribute access (`__class__`, `__globals__`, `__subclasses__`, …) |
| CT002 | HIGH | Jinja SSTI builtin global (`lipsum`, `cycler`, `joiner`) |
| CT003 | HIGH | OS / process / dynamic-import call (`os.`, `subprocess`, `popen`, `system(`, `eval(`, `exec(`) |
| CT004 | MEDIUM | Dynamic attribute-access bypass (`\|attr(`, `getattr(`) |
| CT005 | MEDIUM | Web-framework SSTI global (`request`, `config`, `session`, …) |
| CT006 | MEDIUM | Template `import`/`include`/`extends` tag |
| GCT000 | LOW | GGUF header/metadata unreadable or truncated (not scanned) |

HIGH findings carry the `CVE-2024-34359;CVE-2026-5760` vector reference.

## Usage

```
python gguf_chat_template_scan.py ./model-dir --fail-on HIGH
python gguf_chat_template_scan.py model.gguf --json
```

Exit code is non-zero when a finding at or above `--fail-on` is present, so it
drops into CI as one line.

## Is this novel?

**No new vulnerability class and no new method.** The static approach — parse
the GGUF metadata, extract the chat template, inspect for `__class__` / `os` /
`subprocess` / `eval` / `exec` — is the one publicly described by
[JFrog Security Research (GGUF-SSTI)](https://research.jfrog.com/model-threats/gguf-ssti/),
and the advisories above are all public. The contribution here is a **free,
dependency-free, standard-library, no-execution implementation** that plugs the
GGUF carrier gap in an existing open scanner suite and runs in CI. Existing
model scanners (ModelScan, ModelAudit) check pickle opcodes, ONNX custom ops and
deserialization, but a malicious GGUF chat template is *valid* Jinja2 that runs
at inference time, so it passes those checks — which is why a dedicated
chat-template reader is worth shipping.

## Honest limits

- **Detection, not exploitation.** It describes suspicious tokens; it does not
  prove exploitability. A clean scan guarantees nothing.
- **Heuristic.** Obfuscated payloads (e.g. string-built attribute names) can
  evade the token patterns; low false-positive tuning means some real payloads
  are MEDIUM, not HIGH.
- **The real fix** is to render chat templates only in an
  `ImmutableSandboxedEnvironment`, or to pin a known-good template per model.
- Everything named here is already public; nothing in this tool is a zero-day.

## Safety of this repository's fixtures

The accompanying tests use inert, never-rendered marker strings. The one
OS-call fixture uses the harmless, read-only placeholder `id` and omits any
`__globals__`/`__subclasses__` escalation chain, and a test asserts no
destructive or exploit-completing token appears.
