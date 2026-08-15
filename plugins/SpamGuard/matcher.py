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
