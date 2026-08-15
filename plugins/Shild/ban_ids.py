"""Persisted, ever-incrementing id for each real ban Shild performs, so
the short IRC kick message can carry a permanent `[ID: N]` the same way
SpamGuard's per-term ids do -- but here the id names an ENFORCEMENT
ACTION (also recorded in collector.build_enforcement_record, so the
full record behind any id stays looked-up-able in
data/enforcement_actions.jsonl), not a stored/curated term, since Shild
has no term-list concept to attach an id to in the first place: every
ban comes from the live classifier+evidence pipeline, not a matched
entry an admin added.

No supybot import. Same atomic-write-then-replace persistence pattern
as plugins/GitHubWatch/state.py and plugins/SpamGuard/terms.py, for the
same reason (a crash mid-write must never leave a corrupt/partial state
file) -- simpler than either of those, since this is just a counter,
not a per-entry store.
"""
from __future__ import annotations

import json
from pathlib import Path


class BanIdStore:
    def __init__(self, path):
        self.path = Path(path)
        self._next_id = self._load()

    def _load(self) -> int:
        if self.path.exists():
            try:
                return int(json.loads(self.path.read_text()).get("next_id", 1))
            except (json.JSONDecodeError, OSError, ValueError, TypeError):
                pass
        return 1

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"next_id": self._next_id}))
            tmp.replace(self.path)
        except OSError:
            pass  # id tracking must never crash real enforcement

    def next_id(self) -> int:
        """Returns the id to use for the ban happening right now, then
        advances -- never reused, even if a later ban's own enforcement
        fails after this is called (a small gap in the sequence is
        harmless; a REUSED id printed on two different real bans would
        not be)."""
        assigned = self._next_id
        self._next_id += 1
        self._save()
        return assigned
