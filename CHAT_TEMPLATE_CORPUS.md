<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Made with AI by MV2 of Munim, Inc. -->

# Benign chat-template SSTI regression corpus

`chat_template_corpus.py` generates a small, self-contained, **payload-free**
set of model chat-template fixtures for regression-testing a static server-side
template-injection (SSTI) scanner such as [`chat_template_scan.py`](chat_template_scan.py)
(shipped in v0.18.0). It is standard-library only and writes a `manifest.json`
that labels every fixture.

> This tool and this document were **made with AI** by MV2 of Munim, Inc.

## Why this exists

A *chat template* is a Jinja2 rule, shipped inside a model, that turns chat
messages into a prompt string. Several projects rendered that template with an
**unsandboxed** `jinja2.Environment`, so a poisoned template could reach
arbitrary code when the model was loaded. Public, already-fixed cases:

| Advisory | Project | Carrier | Fix |
|---|---|---|---|
| CVE-2024-34359 / GHSA-56xg-wfcc-g829 | abetlen/llama-cpp-python (< 0.2.72) | GGUF `tokenizer.chat_template` | `ImmutableSandboxedEnvironment` |
| huntr report | berriai/litellm | `hf_chat_template` | sandboxed env |
| guidance-ai/guidance PR #1475 | guidance | Jinja `from_string` | sandboxed env |

Weaknesses: **CWE-94** (code injection), **CWE-1336** (template injection). In
every case the real fix is a sandboxed Jinja environment, not a scanner — a
scanner is a lint that helps catch a poisoned template before it is loaded.

## What the corpus contains

Nine fixtures, spread across the three carriers a chat template travels in
(`tokenizer_config.json` `chat_template` as a string, the same as a
named-template list, and a `.jinja` sidecar), mapping to the
`chat_template_scan.py` finding codes:

| Fixture | Code | Severity | Carrier | Token |
|---|---|---|---|---|
| `clean_tokenizer_config.json` | — | CLEAN | json string | (none) |
| `clean_chat_template.jinja` | — | CLEAN | sidecar | (none) |
| `dunder_class_tokenizer_config.json` | CT001 | HIGH | json string | `''.__class__` |
| `ssti_global_tokenizer_config.json` | CT002 | HIGH | json list | `cycler(...)` |
| `oscall_chat_template.jinja` | CT003 | HIGH | sidecar | `os.popen('id')` |
| `attr_filter_tokenizer_config.json` | CT004 | MEDIUM | json string | `\|attr(...)` |
| `web_global_tokenizer_config.json` | CT005 | MEDIUM | json list | `url_for(...)` |
| `include_tag_chat_template.jinja` | CT006 | MEDIUM | sidecar | `{% include %}` |
| `malformed_tokenizer_config.json` | CT000 | LOW | json string | (truncated) |

The clean control uses a realistic Llama-style template with a `namespace(...)`
call, confirming the scanner does **not** flag that legitimate pattern.

## Safety — these are not exploits

Every risky fixture carries only an **inert detector token**. This module and
its tests **never render** a template and never import `jinja2`; the fixtures are
static JSON/text. The one OS-call fixture uses the universally harmless,
read-only placeholder command `id` and **deliberately omits** the
`__subclasses__`/`__mro__` object-walk that a real exploit would need. The test
suite asserts that no fixture contains any destructive or exploit-completing
token (`__subclasses__`, `__mro__`, `__builtins__`, `eval(`, `rm -rf`, `base64`,
`curl`, `wget`, `powershell`, …).

## Usage

```bash
python chat_template_corpus.py --out-dir ./corpus_chat_template
# -> 9 fixtures + manifest.json
```

Validate it against the scanner from v0.18.0 (optional):

```bash
python chat_template_scan.py ./corpus_chat_template --fail-on HIGH
```

## Prior art and what is new here

The *detector* is not new: promptfoo's **ModelAudit** ships a Jinja2
chat-template scanner and **r0b0tlab/model-audit** inspects
`tokenizer.chat_template`. What a 2026-10-15 prior-art check did **not** find was
a **standalone, dependency-free, payload-free, labelled** benign-and-risky corpus
for this exact vector — ModelAudit's fixtures are tied to its own scanner and
dependency tree. That is this corpus's narrow contribution: a reproducible
regression dataset with a `manifest.json`, usable to test *any* chat-template
SSTI linter (this repo's or another's) without installing one.

## Honest limits

- A clean scan guarantees nothing; the detector is a lint, not a sandbox.
- Every identifier named here is already public and already fixed upstream;
  nothing here is a zero-day.
- The corpus exercises detection patterns, not exploitation. GGUF
  `tokenizer.chat_template` is listed as a carrier but the paired scanner parses
  only `tokenizer_config.json` and `.jinja` sidecars today.

## Licence

Code is **Apache-2.0**; the fixture data and manifest are **CC BY 4.0**.
