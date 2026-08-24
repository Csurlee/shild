"""Pure per-term matcher for SpamGuard -- no supybot import.

Each configured term (word/phrase/pattern/ident/realname word/realname
phrase) is compiled to its OWN regex and tested individually, rather
than combined into one big alternation -- this is what lets a match be
traced straight back to the exact stored Term (and therefore its
permanent id, see terms.py) that fired, for the kick-reason "[id: N]"
tag and `spamguardsearch`. Term lists are expected to stay short
(patterns especially -- see terms.py's own docstring), so the per-term
loop is not a real performance concern.

Word/phrase/ident/realname terms match as a case-insensitive substring
(re.escape'd) -- catches "Czura" anywhere in a message, same as
Armour/idefix's own blacklist convention. Pattern terms are raw regexes,
for a spam template that rotates one token each run; an invalid one
compiles to None and the caller (plugin.py) is expected to skip it with
a logged warning rather than let one bad regex break every other term.
"""
from __future__ import annotations

import re
from typing import Optional

Pattern = "re.Pattern[str]"


def compile_term(text: str, *, is_pattern: bool = False) -> Optional[Pattern]:
    """Compiles one term's own regex. `is_pattern=True` treats `text` as
    a raw regex (the "pattern" category); anything else compiles as a
    case-insensitive literal-substring match. Returns None for an empty
    string, or when `is_pattern` and the regex fails to compile."""
    if not text:
        return None
    if is_pattern:
        try:
            return re.compile(text, re.IGNORECASE)
        except re.error:
            return None
    return re.compile(re.escape(text), re.IGNORECASE)


# A quantified group directly wrapped in another quantifier -- e.g.
# "(a+)+", "(a+b*)+" -- the single most common shape behind catastrophic
# regex backtracking. Found via code review, 2026-08-24: every "pattern"
# term compiled by compile_term() above was only ever validated for
# "does it compile", then run synchronously via first_match()'s
# regex.search() on Limnoria's single, unthreaded main loop
# (plugin.py's `threaded = False`) for every PRIVMSG/QUIT/PART-reason --
# a catastrophic-backtracking pattern matched against a long enough
# attacker-controlled message would hang the ENTIRE bot process, both
# networks, every plugin, not just SpamGuard.
#
# Deliberately a best-effort heuristic, not a proof of safety -- it
# catches the common single-level-nesting shape above, not every
# possible ReDoS construction (multi-level nesting, alternation-based
# blowups). Honest about that limit rather than pretending otherwise,
# same convention as this project's other documented-unverified best-
# effort mechanisms (e.g. docs/UNDERNETX.md's unverified reply markers).
# No threading/timeout redesign here -- out of proportion for what this
# heuristic already closes, and IRC's own 512-byte line cap already
# bounds worst-case input length.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")


def looks_catastrophically_backtracking(pattern_text: str) -> bool:
    """True if `pattern_text` looks like it could cause catastrophic
    regex backtracking -- see _NESTED_QUANTIFIER_RE's own comment above
    for exactly what this does and does not catch. Used by plugin.py's
    `spamguard pattern add` to refuse adding such a pattern, alongside
    the existing "does it compile" check."""
    return bool(_NESTED_QUANTIFIER_RE.search(pattern_text))


def first_match(compiled, text: str):
    """`compiled` is a list of (term, regex) pairs -- plugin.py passes
    its stored Term objects as the first element of each pair. Returns
    the first term whose regex hits `text`, or None if none do. Order
    follows the input list, which plugin.py builds sorted by id, so the
    lowest-id match wins when more than one term could fire on the same
    text."""
    for term, regex in compiled:
        if regex.search(text):
            return term
    return None
