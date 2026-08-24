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
harness.

**Concurrency (2026-08-24, WebPanel write-support work)**: this store is
NOW written from two threads -- SpamGuard's own IRC commands (main IRC
thread) and plugins/WebPanel/http.py's new POST routes (the dedicated
HTTP server thread; see supybot's httpserver.py, `Thread(target=server.
serve_forever, ...)`). The previous "fine here, single-threaded" claim
is false as of this change. `TermStore.__init__` now takes a
`threading.Lock()`, same fix already applied to
plugins/Shild/decision_cache.py and plugins/Shild/ban_ids.py for the
identical reason -- see those two files for the exact pattern mirrored
here. Every PUBLIC method acquires the lock exactly once and delegates
to a `_*_locked` private that assumes it's already held; this two-tier
split exists specifically because `add()`/`remove()` call `_save()`
which calls `all()` internally -- a naive "just wrap every public method
body in `with self._lock`" port would self-deadlock on the very first
`add()`. `_save()` is now atomic (temp-file-then-replace, matching
ban_ids.py's exact pattern -- ban_ids.py's own docstring already claimed
this file worked this way; it didn't, until now) and does NOT swallow
`OSError` the way ban_ids.py does, since a failed *term* write must
reach the caller (an admin needs to know their block-list edit didn't
actually persist), unlike a ban id counter where a lost increment is
harmless.
"""
from __future__ import annotations

import json
import threading
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
        # See module docstring's "Concurrency" section -- a plain Lock,
        # not RLock, on purpose: every nested call below goes through an
        # explicit `_*_locked` helper rather than re-acquiring, so a
        # nested re-acquire (which RLock would silently allow) is never
        # needed and never happens. Created before _load() purely for
        # attribute-ordering clarity; load() itself runs at construction
        # time, before any other thread could plausibly hold a reference
        # to this instance.
        self._lock = threading.Lock()
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
        # 2026-08-24 fix (found via code review): the stored next_id was
        # trusted verbatim whenever present, only falling back to
        # max(ids)+1 when the field was MISSING entirely -- a file
        # restored from a stale backup or hand-edited could have a
        # next_id lower than an id already in `terms`, and the next
        # add() would silently reuse it, breaking this module's own "an
        # id always means the same term forever" guarantee. Now always
        # takes the max of both, so a stale-but-present next_id can
        # never regress below what's actually in use.
        try:
            stored_next_id = int(raw.get("next_id", 1))
        except (TypeError, ValueError):
            stored_next_id = 1
        self._next_id = max(stored_next_id, max(self._terms, default=0) + 1)

    def _save_locked(self) -> None:
        """Assumes self._lock is already held. Atomic temp-file-then-
        replace (2026-08-24 fix) -- previously a bare write_text(), so a
        crash or a concurrent reader mid-write could see a truncated
        file, which _load()'s fail-closed-on-JSONDecodeError path turns
        into a silently EMPTIED block list. Unlike ban_ids.py's _save(),
        does NOT swallow OSError: a failed term write must surface to
        the caller (an admin needs to know their edit didn't persist),
        not be silently absorbed the way a lost ban-id increment can be.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "next_id": self._next_id,
            "terms": [t.to_dict() for t in self._all_locked()],
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(self.path)

    def _all_locked(self) -> list[Term]:
        return sorted(self._terms.values(), key=lambda t: t.id)

    def _get_locked(self, term_id: int) -> Optional[Term]:
        return self._terms.get(term_id)

    def _find_by_text_locked(self, category: str, text: str) -> Optional[Term]:
        for t in self._terms.values():
            if t.category == category and t.text == text:
                return t
        return None

    def add(self, category: str, text: str, added_by: str = "") -> Term:
        with self._lock:
            term_id = self._next_id
            self._next_id += 1
            t = Term(id=term_id, category=category, text=text,
                      added_by=added_by, added_at=time.time())
            self._terms[term_id] = t
            self._save_locked()
            return t

    def remove(self, term_id: int) -> Optional[Term]:
        with self._lock:
            t = self._terms.pop(term_id, None)
            if t is not None:
                self._save_locked()
            return t

    def remove_by_text(self, category: str, text: str) -> Optional[Term]:
        # 2026-08-24: one atomic find-then-remove under a single lock
        # acquisition, not two separate locked calls -- the old
        # find_by_text() + remove(existing.id) pair was a genuine
        # check-then-act race between two concurrent callers (a real
        # risk once WebPanel can write this store from a second thread):
        # both could find the same term, both proceed to remove it, and
        # the second remove() would silently no-op on an id that's
        # already gone while believing it removed something.
        with self._lock:
            existing = self._find_by_text_locked(category, text)
            if existing is None:
                return None
            t = self._terms.pop(existing.id, None)
            if t is not None:
                self._save_locked()
            return t

    def get(self, term_id: int) -> Optional[Term]:
        with self._lock:
            return self._get_locked(term_id)

    def find_by_text(self, category: str, text: str) -> Optional[Term]:
        with self._lock:
            return self._find_by_text_locked(category, text)

    def by_category(self, category: str) -> list[Term]:
        with self._lock:
            return sorted((t for t in self._terms.values() if t.category == category),
                          key=lambda t: t.id)

    def all(self) -> list[Term]:
        with self._lock:
            return self._all_locked()

    def search(self, query: str) -> list[Term]:
        """An exact numeric id always wins outright (returns just that
        one term, even if its text also happens to look like a
        substring query someone typed) -- otherwise a case-insensitive
        substring match against term text, across every category."""
        query = query.strip()
        with self._lock:
            if query.isdigit():
                t = self._get_locked(int(query))
                if t is not None:
                    return [t]
            q = query.lower()
            return [t for t in self._all_locked() if q in t.text.lower()]
