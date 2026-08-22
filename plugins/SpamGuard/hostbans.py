"""Persisted host/IP ban history (2026-08-22) -- distinct from terms.py's
admin-managed TermStore: entries here are populated AUTOMATICALLY every
time a real, host-based enforcement fires (never ident- or nick-field
matches, which already target something narrower and more durable than
a host -- see plugin.py's `_enforce`), so a rejoin from that same host
days or weeks later, after the original temporary MODE+b has long since
auto-expired, can be recognized and re-enforced on sight, reusing the
EXACT original kick message rather than recomputing a new one.

Pure: no supybot import, no I/O beyond its own JSON file -- same
convention as terms.py, independently pytest-testable. Not safe for
concurrent writers, same single-thread assumption every other JSON state
file in this repo already makes.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass
class HostBanRecord:
    host: str
    kick_reason: str
    term_id: int
    term_text: str
    field: str
    first_seen_at: float
    last_seen_at: float
    hit_count: int

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "HostBanRecord":
        return HostBanRecord(
            host=d["host"],
            kick_reason=d["kick_reason"],
            term_id=int(d["term_id"]),
            term_text=d.get("term_text", ""),
            field=d.get("field", ""),
            first_seen_at=float(d.get("first_seen_at", 0.0)),
            last_seen_at=float(d.get("last_seen_at", 0.0)),
            hit_count=int(d.get("hit_count", 1)),
        )


class HostBanStore:
    """Loads/saves the full host-ban history from one JSON file, resolved
    relative to the bot's own working directory (runtime/) -- same
    resolution convention as terms.py's TermStore, see hostBansPath's own
    config.py docstring.
    """

    def __init__(self, path):
        self.path = Path(path)
        self._records: dict[str, HostBanRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            # Fails closed to an empty store, same convention as
            # terms.py/Shild's secrets.py -- a corrupt file must never
            # crash plugin load, just silently start from empty (and get
            # overwritten cleanly on the next record()).
            return
        for entry in raw.get("hosts", []):
            try:
                r = HostBanRecord.from_dict(entry)
            except (KeyError, TypeError, ValueError):
                continue
            self._records[r.host] = r

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"hosts": [r.to_dict() for r in self.all()]}
        self.path.write_text(json.dumps(data, indent=2))

    def get(self, host: str, *, now: float, retention_secs: float) -> Optional[HostBanRecord]:
        """None if there's no record at all, OR if the record has aged
        out of the retention window (last_seen_at + retention_secs <
        now) -- an expired record is left in the file (read-only lookup;
        prune_expired() is the only thing that actually deletes one), so
        a rejoin just past the retention boundary doesn't silently lose
        its own hit_count/history if it turns out to still matter.
        """
        r = self._records.get(host)
        if r is None:
            return None
        if r.last_seen_at + retention_secs < now:
            return None
        return r

    def record(self, host: str, kick_reason: str, term_id: int, term_text: str,
               field: str, *, now: float) -> HostBanRecord:
        """A FRESH match (content/realname/pattern/black/a heuristic) on
        this host -- never called for a host_history-triggered reban
        itself (see touch() below). First sighting sets every field;
        a later fresh sighting of the SAME host only refreshes
        last_seen_at/hit_count -- kick_reason/term_id/term_text/field
        stay pinned to whatever the FIRST real match recorded, since
        that's the message a future reban is meant to reuse verbatim.
        """
        existing = self._records.get(host)
        if existing is None:
            r = HostBanRecord(host=host, kick_reason=kick_reason, term_id=term_id,
                               term_text=term_text, field=field,
                               first_seen_at=now, last_seen_at=now, hit_count=1)
        else:
            r = HostBanRecord(host=host, kick_reason=existing.kick_reason,
                               term_id=existing.term_id, term_text=existing.term_text,
                               field=existing.field, first_seen_at=existing.first_seen_at,
                               last_seen_at=now, hit_count=existing.hit_count + 1)
        self._records[host] = r
        self._save()
        return r

    def touch(self, host: str, *, now: float) -> None:
        """A host_history-triggered REBAN itself -- there's nothing new
        to say (the stored kick_reason is being reused verbatim), so
        only the retention clock and hit_count move. A no-op, not an
        error, if the record was somehow removed between the get() that
        triggered this reban and this call (e.g. a concurrent manual
        `spamguardhostbans remove`)."""
        existing = self._records.get(host)
        if existing is None:
            return
        self._records[host] = HostBanRecord(
            host=existing.host, kick_reason=existing.kick_reason,
            term_id=existing.term_id, term_text=existing.term_text,
            field=existing.field, first_seen_at=existing.first_seen_at,
            last_seen_at=now, hit_count=existing.hit_count + 1,
        )
        self._save()

    def remove(self, host: str) -> bool:
        if host in self._records:
            del self._records[host]
            self._save()
            return True
        return False

    def prune_expired(self, *, now: float, retention_secs: float) -> int:
        """Actually deletes every record past the retention window --
        called from a periodic background sweep (plugin.py), never
        inline with a live join. Returns how many were removed."""
        expired = [h for h, r in self._records.items()
                   if r.last_seen_at + retention_secs < now]
        for h in expired:
            del self._records[h]
        if expired:
            self._save()
        return len(expired)

    def all(self) -> list[HostBanRecord]:
        return sorted(self._records.values(), key=lambda r: r.last_seen_at, reverse=True)

    def __len__(self) -> int:
        return len(self._records)
