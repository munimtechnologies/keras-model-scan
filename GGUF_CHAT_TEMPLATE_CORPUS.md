# GGUF chat-template SSTI regression corpus

`gguf_chat_template_corpus.py` builds a **payload-free** set of crafted `.gguf`
files whose embedded `tokenizer.chat_template` metadata regression-tests a static
GGUF chat-template SSTI scanner. It is the binary-carrier companion to the
JSON/`.jinja` [chat-template corpus](CHAT_TEMPLATE_CORPUS.md) and pairs with the
[`gguf_chat_template_scan.py`](GGUF_CHAT_TEMPLATE_SCAN.md) scanner shipped in
v0.20.0.

Made with AI by MV2 of Munim, Inc. Code is Apache-2.0; the generated fixtures and
`manifest.json` are CC BY 4.0.

## Why a GGUF carrier corpus

The JSON corpus proves a scanner's SSTI heuristic on `tokenizer_config.json`
strings and `.jinja` sidecars. But a `.gguf` file embeds the chat template as a
UTF-8 metadata value inside a binary header + key/value table, and that is a
different parser. A regression that stops the GGUF metadata reader from reaching
`tokenizer.chat_template` would pass the JSON tests yet silently miss every real
GGUF model. This corpus exercises the full binary path end to end, including the
multi-template (`tokenizer.chat_template.<name>`) keys and an unreadable-header
case.

Upstream model scanners (ModelScan, ModelAudit, picklescan) ship no crafted GGUF
chat-template fixtures at all, so this is, as far as a prior-art check in October
2026 found, the first standalone benign GGUF chat-template SSTI corpus.

## What it generates

A minimal, little-endian **GGUF v3** writer emits each fixture with
`tensor_count = 0` (valid: a chat-template scanner reads only the header and KV
table, never tensor data). Every value is a GGUF `STRING`. A matching reader is
included so a test can round-trip without any scanner dependency.

| Fixture | Status | Code / Severity | Carrier detail |
|---|---|---|---|
| `clean_chatml.gguf` | benign | CLEAN | single template |
| `clean_namespace_multi.gguf` | benign | CLEAN | default + named `tool_use`, `namespace(...)` control |
| `dunder_class.gguf` | flagged | CT001 / HIGH | `__class__` only |
| `ssti_global.gguf` | flagged | CT002 / HIGH | `cycler` / `lipsum` |
| `oscall.gguf` | flagged | CT003 / HIGH | `popen('id')` (read-only) |
| `attr_filter.gguf` | flagged | CT004 / MEDIUM | `|attr(` |
| `web_global.gguf` | flagged | CT005 / MEDIUM | `request` / `config` |
| `include_tag.gguf` | flagged | CT006 / MEDIUM | `{% include %}` |
| `named_template_ssti.gguf` | flagged | CT001 / HIGH | inert token in the named `tool_use` template |
| `malformed_truncated.gguf` | malformed | GCT000 / LOW | valid magic, truncated KV table |

`manifest.json` labels every fixture with its SHA-256, byte length, carrier,
chat-template keys, status, code, severity, representative token and a note.

## Safety

Nothing here is exploitable. Each fixture is just metadata in a GGUF file; no
template is ever rendered and `jinja2` is never imported. Every flagged fixture
carries only the smallest **inert** token that trips one rule and deliberately
omits the object-walk (`__mro__` / `__subclasses__` / `__globals__` / `eval(` /
`exec(`) a real exploit needs. The one OS-call fixture uses the harmless
read-only `id` command with no object-walk to reach it. `build_corpus` asserts no
fixture contains any exploit-completing or destructive token, and the test suite
re-checks it.

## Usage

```bash
python gguf_chat_template_corpus.py --out-dir ./gguf_ct_corpus
# then point the scanner at the fixtures:
python gguf_chat_template_scan.py ./gguf_ct_corpus --json
```

## Finding codes

| Code | Severity | Trigger |
|------|----------|---------|
| CT001 | HIGH | Python dunder attribute access (`__class__`) |
| CT002 | HIGH | Jinja SSTI builtin globals (`cycler` / `lipsum` / `joiner`) |
| CT003 | HIGH | OS / process / dynamic-import calls (`os.` / `popen` / `system(`) |
| CT004 | MEDIUM | Dynamic attribute-access bypass (`|attr(` / `getattr(`) |
| CT005 | MEDIUM | Web-framework SSTI globals (`request` / `config` / `session`) |
| CT006 | MEDIUM | Template tags (`import` / `include` / `extends`) |
| GCT000 | LOW | GGUF header/metadata unreadable or truncated (not scanned) |

HIGH findings carry the vector reference `CVE-2024-34359;CVE-2026-5760`.

## Honest limits

Every identifier named is already public; nothing here is a zero-day. The corpus
tests **detection**, not exploitation. A GGUF chat template is only dangerous when
an inference stack renders it with an unsandboxed Jinja environment; a clean scan
guarantees nothing. The fixtures use a deliberately minimal GGUF writer (string
metadata, no tensors), which is enough to exercise a chat-template scanner but is
not a general-purpose GGUF library.
