"""Persisted, ID-keyed term store for SpamGuard's block-list entries
(content words/phrases/patterns, idents, nicks, realname words/phrases).

Every entry gets a permanent integer id the moment it's added -- NEVER
reused, even after removal, so an id printed in a kick reason or written
to a JSONL log keeps meaning the same term forever, not get silently
reassigned to something else later. Mirrors Armour/idefix's own
`[id: N]` blacklist-entry convention (see plugin.py's module docstring
for the real incident that convention comes from), which is now also
what a SpamGuard kick reason looks like.

Pure: no supybot import, no I/O beyond reading/writing its own JSON
file, so this is independently pytest-testable without the plugin test
harness. Not safe for concurrent writers -- fine here, since Limnoria's
plugin callbacks all run on one thread, same assumption every other
JSON state file in this repo (budget.json, github_watch_state.json)
already makes.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# "phrase"/"realname_phrase" are separate categories from "word"/
# "realname_word" (rather than one category with a "has a space" flag)
# so a category name alone is always enough to know how a term should be
# compiled and where it belongs in `spamguardlist`'s output.
#
# "black" (2026-08-14) is different in kind from every category above --
# see plugin.py's module docstring on the "black" section for the full
# design: one term matches against BOTH a candidate's nick AND host (an
# identity block, not a content/field match), is checked first at JOIN,
# and -- uniquely among all categories here -- ALSO immediately sweeps
# every already-present channel member for a match the moment it's
# added, not just future events.
CATEGORIES = ("word", "phrase", "pattern", "ident", "nick", "realname_word", "realname_phrase",
              "black")


@dataclass
class Term:
    id: int
    category: str
    text: str
    added_by: str
    added_at: float

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Term":
        return Term(
            id=int(d["id"]),
            category=d["category"],
            text=d["text"],
            added_by=d.get("added_by", ""),
            added_at=d.get("added_at", 0.0),
        )


class TermStore:
    """Loads/saves the full term list from one JSON file, resolved
    relative to the bot's own working directory (runtime/) the same way
    every other JSONL/JSON path in this deployment is -- see
    config.py's termsPath docstring.
    """

    def __init__(self, path):
        self.path = Path(path)
        self._terms: dict[int, Term] = {}
        self._next_id = 1
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            # Fails closed to an empty store, same convention as
            # Shild's secrets.py -- a corrupt file must never crash
            # plugin load, just silently start from empty (and get
            # overwritten cleanly on the next add()).
            return
        for entry in raw.get("terms", []):
            try:
                t = Term.from_dict(entry)
            except (KeyError, TypeError, ValueError):
                continue
            self._terms[t.id] = t
        self._next_id = raw.get("next_id", max(self._terms, default=0) + 1)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "next_id": self._next_id,
            "terms": [t.to_dict() for t in self.all()],
        }
        self.path.write_text(json.dumps(data, indent=2))

    def add(self, category: str, text: str, added_by: str = "") -> Term:
        term_id = self._next_id
        self._next_id += 1
        t = Term(id=term_id, category=category, text=text,
                  added_by=added_by, added_at=time.time())
        self._terms[term_id] = t
        self._save()
        return t

    def remove(self, term_id: int) -> Optional[Term]:
        t = self._terms.pop(term_id, None)
        if t is not None:
            self._save()
        return t

    def remove_by_text(self, category: str, text: str) -> Optional[Term]:
        existing = self.find_by_text(category, text)
        if existing is None:
            return None
        return self.remove(existing.id)

    def get(self, term_id: int) -> Optional[Term]:
        return self._terms.get(term_id)

    def find_by_text(self, category: str, text: str) -> Optional[Term]:
        for t in self._terms.values():
            if t.category == category and t.text == text:
                return t
        return None

    def by_category(self, category: str) -> list[Term]:
        return sorted((t for t in self._terms.values() if t.category == category),
                      key=lambda t: t.id)

    def all(self) -> list[Term]:
        return sorted(self._terms.values(), key=lambda t: t.id)

    def search(self, query: str) -> list[Term]:
        """An exact numeric id always wins outright (returns just that
        one term, even if its text also happens to look like a
        substring query someone typed) -- otherwise a case-insensitive
        substring match against term text, across every category."""
        query = query.strip()
        if query.isdigit():
            t = self.get(int(query))
            if t is not None:
                return [t]
        q = query.lower()
        return [t for t in self.all() if q in t.text.lower()]
