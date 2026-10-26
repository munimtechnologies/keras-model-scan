# Copyright 2026 Munim, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file was written by AI agents working in the name of MV2 of Munim, Inc.
"""Standalone complementary detector for a recall gap in token-denylist SSTI
scanners for GGUF chat templates (CVE-2024-34359 / CVE-2026-5760 class).

Why this exists
---------------
``gguf_chat_template_scan.py`` flags a Jinja2 server-side template injection
(SSTI) payload in a model's ``tokenizer.chat_template`` by matching a denylist
of raw tokens (``__class__``, ``lipsum``, ``popen``, ``os.`` ...).  Jinja2, like
Python, concatenates *adjacent string literals* at parse time, so
``{{ "foo" "bar" }}`` is exactly ``{{ "foobar" }}``.  An attacker can therefore
split a dangerous token across adjacent literals -- ``['__cla''ss__']`` or
``['pop''en']`` -- and the raw-text denylist never sees the reconstructed token,
even though Jinja2 renders it identically.  See
``GGUF_CHAT_TEMPLATE_SSTI_DENYLIST_RECALL_AUDIT.md`` for the full census.

This module does NOT render the template.  It is a static text probe that flags
the split-token *shapes* a token denylist misses, so a scanner can use it as a
complementary recall check until adjacent-literal folding is wired into the main
scanner.  It is deliberately conservative: a HIGH finding targets a split
dunder, a MEDIUM finding a generic in-token literal split.
"""

import re

# A dunder attribute token (``__class__``, ``__globals__``, ``__builtins__`` ...)
# split across a string-literal boundary or a constant ``+`` / ``~`` join, which
# Jinja2 folds back together.  The two ``\w*`` groups allow the split to land at
# any interior position of the token.
SPLIT_DUNDER = re.compile(r"__\w*['\"]\s*(?:[+~]\s*)?['\"]\w*__")

# A generic in-token literal split: a word character, then two string-literal
# delimiters that are adjacent (or joined by whitespace / a constant ``+`` / ``~``
# operator), then another word character.  This matches ``pop''en`` and
# ``o''s`` while leaving normal single literals and empty strings ("''") alone.
SPLIT_LITERAL = re.compile(r"\w['\"]\s*(?:[+~]\s*)?['\"]\w")


def probe(template):
    """Return a list of (code, severity, message) for evasion shapes found.

    An empty list means no split-token obfuscation was detected -- it does NOT
    mean the template is safe; the main denylist scanner still applies.
    """
    findings = []
    if not isinstance(template, str):
        return findings
    if SPLIT_DUNDER.search(template):
        findings.append((
            "EVA001", "HIGH",
            "Dunder attribute token split across string literals; Jinja2 folds "
            "adjacent literals so a raw-text denylist is evaded",
        ))
    elif SPLIT_LITERAL.search(template):
        findings.append((
            "EVA002", "MEDIUM",
            "Adjacent string-literal concatenation inside a token; possible "
            "denylist-evasion obfuscation -- review the chat template",
        ))
    return findings


def is_suspicious(template):
    """True if any split-token evasion shape is present."""
    return bool(probe(template))
