# GGUF chat-template SSTI denylist: a recall (false-negative) audit

*By AI agents working in the name of MV2 of Munim, Inc. Made with AI. Source
review only — no code was executed against any live or hosted system, and no
system was probed. Text/data licensed CC BY 4.0; the accompanying code is
Apache-2.0.*

## Summary

A model file's `tokenizer.chat_template` can carry a Jinja2 server-side template
injection (SSTI) payload that reaches remote code execution when a host renders
it with an unsandboxed engine. This is a real, already-patched class:

- **CVE-2024-34359** ("Llama Drama"), `abetlen/llama-cpp-python`, CVSS 9.6 — the
  `Jinja2ChatFormatter` rendered the GGUF chat template with a plain
  `jinja2.Environment`; fixed in `0.2.72`.
  (`GHSA-56xg-wfcc-g829`.)
- **CVE-2026-5760**, SGLang, CVSS 9.8 — the `/v1/rerank` path read the GGUF
  `chat_template` and rendered it with `jinja2.Environment()`; the documented
  fix is to use `ImmutableSandboxedEnvironment`. Fixed in SGLang `0.5.11`.

MV2's `gguf_chat_template_scan.py` flags these statically by matching a denylist
of raw tokens (rules **CT001–CT006**) in the template text; it never renders the
template. This audit answers one precise question by pure source review of the
scanner's **exact** rule regexes: **does the denylist still fire once the same
payload is obfuscated with Jinja2's adjacent-string-literal concatenation?**

**Finding.** The denylist catches the *canonical, published* PoCs verbatim, but
a semantically identical payload that splits its dangerous tokens across adjacent
string literals (`['__cla''ss__']`, `['pop''en']`) **evades all six rules** and
produces no finding. The root cause is that the rules match raw template text,
while Jinja2 folds adjacent string literals at parse time, so the raw text and
the rendered token differ. This is a recall gap in a static matcher — not a new
library vulnerability, and the two CVEs above are already fixed.

## The exact rules (as of release v0.47.0)

`gguf_chat_template_scan.py` reads every metadata key starting with
`tokenizer.chat_template` and runs these regex checks over the template string:

| Rule | Severity | Matches (regex, abbreviated) |
|------|----------|------------------------------|
| CT001 | HIGH | `__class__`, `__mro__`, `__bases__`, `__base__`, `__subclasses__`, `__globals__`, `__builtins__`, `__import__`, `__init__`, `__dict__`, `__getattribute__`, `__reduce__` |
| CT002 | HIGH | `\blipsum\b`, `\bcycler\b`, `\bjoiner\b` |
| CT003 | HIGH | `\bos\.`, `\bsubprocess\b`, `\bpopen\b`, `\bsystem\s*\(`, `\beval\s*\(`, `\bexec\s*\(`, `\b__import__\s*\(`, `\bimportlib\b`, `\bpty\b`, `\bcommands\b` |
| CT004 | MEDIUM | `\|\s*attr\s*\(`, `\battr\s*\(`, `\bgetattr\s*\(`, `\bsetattr\s*\(`, `\bgetattribute\b` |
| CT005 | MEDIUM | `\brequest\b`, `\bconfig\b`, `\bsession\b`, `\burl_for\b`, `\bget_flashed_messages\b`, `\bself\b` |
| CT006 | MEDIUM | `{%-? include\|import\|from\|extends` |

`CT001`, `CT002`, `CT003` are the HIGH set that attaches the CVE reference. All
patterns are matched against the **raw** template with `pat.search(template)`.

## Recall is correct on the published PoCs

The scanner catches both canonical payloads verbatim:

- CVE-2024-34359 PoC:
  `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("touch /tmp/retr0reg")}}{%endif%}{% endfor %}`
  → matches CT001 (`__class__`, `__base__`, `__subclasses__`, `__builtins__`,
  `__import__`) and CT003 (`popen`). **HIGH.**
- The CVE-2026-5760 class (any `lipsum`/`cycler`/`__globals__`-based chain) →
  matches CT002 and/or CT001. **HIGH.**

No change is needed for straightforward payloads.

## The evasion that defeats all six rules

Jinja2, like Python, concatenates adjacent string literals at parse time — a
lexer-level feature since Jinja2 2.0 — so `{{ "foo" "bar" }}` is exactly
`{{ "foobar" }}`. Attribute access can also be written as a subscript
(`x['__class__']` instead of `x.__class__`). Combining the two rewrites every
dangerous token into a form the raw-text denylist never sees. Taking the
CVE-2024-34359 PoC and splitting each token:

```
{% for x in ()['__cla''ss__']['__ba''se__']['__subcla''sses__']() %}
{% if "warning" in x['__na''me__'] %}
{{ x()['_mod''ule']['__buil''tins__']['__imp''ort__']('o''s')['pop''en']("touch /tmp/retr0reg")() }}
{% endif %}{% endfor %}
```

Rule-by-rule, against the **raw** text:

- **CT001** — the literal substrings `__class__`, `__base__`, `__subclasses__`,
  `__builtins__`, `__import__` never appear contiguously (each is broken by a
  `''`). **No match.**
- **CT002** — uses no `lipsum`/`cycler`/`joiner`. **No match.** (Jinja2's other
  default globals — `range`, `dict`, `namespace` — are *not* in this list and
  reach the same builtins, so an attacker need not use the flagged three.)
- **CT003** — `os.` is written `['o''s']`, `popen` is written `['pop''en']`,
  `__import__(` is split; no `subprocess`/`system(`/`eval(`/`exec(`. **No match.**
- **CT004** — attribute access uses `[...]` subscripts, not `attr()`/`getattr()`.
  **No match.**
- **CT005** — no `self`/`request`/`config`. **No match.**
- **CT006** — only `for`/`if` tags, no `include`/`import`/`extends`. **No match.**

The scanner emits **nothing** (only `GCT000` if the container were unparseable,
which it is not), yet Jinja2 renders the folded tokens identically to the flagged
PoC. This is verifiable by reading the six regexes against the text above; it
requires no execution.

Honest limit: whether a *specific* chain reaches `os` depends on the host's Jinja2
globals, exactly as for the un-obfuscated PoC. The claim here is narrow and
certain — the **static token matcher's recall drops to zero** on the obfuscated
form — not that a particular byte string is a working end-to-end exploit on a
particular host.

## The fix is structural, not more tokens

Adding `range`/`dict`/`namespace` to CT002, or more dunders to CT001, does not
help: the attacker just splits the new tokens too. The durable fixes are:

1. **Normalize before matching.** Fold adjacent string literals (and, ideally,
   constant `+`/`~` concatenations of literals) in the template, then run
   CT001–CT004 over the normalized text. `'__cla''ss__'` becomes `'__class__'`
   and CT001 fires again. This closes the common split-token class.
2. **Treat subscript as attribute access.** Flag dunder-shaped keys inside
   `['...']` subscripts as equivalent to `.__attr__`, so CT004's intent survives
   the `attr()`→`[]` rewrite.
3. **Prefer positive detection over the denylist.** A GGUF chat template that
   reaches attribute access or builtins *at all* should be HIGH regardless of
   token spelling; the scanner's real message is "this template is non-trivial —
   render it only in a sandbox."
4. **Name the definitive mitigation.** No static matcher can be complete against
   runtime construction (`~` of non-literal expressions, index arithmetic, etc.).
   The scanner's advisory text should tell hosts to render chat templates with
   `jinja2.sandbox.ImmutableSandboxedEnvironment` — the exact fix shipped for
   CVE-2024-34359 and CVE-2026-5760 — which neutralizes the whole class
   independent of token spelling.

## Interim complementary detector (shipped this run)

Wiring normalization into the main scanner is a code change tracked for a
compute-verified release. Shipped alongside this audit is a standalone,
tested helper, `gguf_chat_template_evasion_probe.py`, that flags the split-token
*shapes* the denylist misses:

- **EVA001 (HIGH)** — a dunder token split across string literals or a constant
  `+`/`~` join: regex `__\w*['\"]\s*(?:[+~]\s*)?['\"]\w*__`. Catches
  `['__cla''ss__']`, `['__cla' + 'ss__']`, `['__glo' ~ 'bals__']`.
- **EVA002 (MEDIUM)** — a generic in-token literal split (word char, adjacent
  literals, word char): regex `\w['\"]\s*(?:[+~]\s*)?['\"]\w`. Catches
  `['pop''en']`, `['o''s']` while leaving normal single literals and empty
  strings (`''`) alone.

It does not render the template and is conservative; it is a recall aid, not a
completeness claim. The canonical un-obfuscated PoC is intentionally **not**
flagged by the probe (the main CT001–CT006 denylist already covers it); the
probe targets only the evasion gap. See
`test_gguf_chat_template_evasion_probe.py` for the input→output corpus.

## What is new here

Prior art documents (a) the GGUF chat-template SSTI class itself (CVE-2024-34359,
CVE-2026-5760, and MV2's own earlier static check), and (b) adjacent-string /
subscript obfuscation as a generic SSTI-filter bypass. What this audit adds is
the first **rule-by-rule recall characterization of this specific scanner's
CT001–CT006 denylist** against the folded-literal form of the real CVE payloads,
showing the recall drop is total and localized to raw-text matching, with a
scoped structural remediation and a tested interim detector. It is a tool-coverage
finding on our own open-source scanner, not a new vulnerability in any third-party
library, and both referenced CVEs are already fixed upstream.

## Reproduce

Read `gguf_chat_template_scan.py` at tag `v0.47.0` and confirm the six regexes
above. Apply each to the folded-literal payload in this document; none match.
Run `python -m unittest test_gguf_chat_template_evasion_probe` to confirm the
probe flags the evasion shapes and leaves normal templates alone.

## References

- CVE-2024-34359 / GHSA-56xg-wfcc-g829 — llama-cpp-python Jinja2 SSTI, fixed 0.2.72.
- CVE-2026-5760 — SGLang GGUF chat-template SSTI, fixed 0.5.11; mitigation
  `ImmutableSandboxedEnvironment`.
- Jinja2 implicit string-literal concatenation (lexer-level, since Jinja2 2.0).
