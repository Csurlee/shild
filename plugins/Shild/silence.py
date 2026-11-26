"""Persisted state for Shild's warn-tier "silence" enforcement
(2026-09-04) -- a real but deliberately LESSER action than the existing
`ban` verdict's kick+ban (see enforcement.py's enforce_silence/
lift_silence): a `warn` verdict, when armed via
protection.warnSilenceEnabled, quiets (on a network whose ircd supports
the +q "quiet" list mode, e.g. Libera's solanum) or bans WITHOUT kicking
(the fallback on a network with no quiet mode, e.g. Undernet's ircu --
see silence.quietCapable's config docstring) the joining host, instead of
removing them outright.

Motivated by a real, live complaint: a registered/exempt-from-SpamGuard
bot (`aop`) flooding a channel it was allowed to be in, where the only
lever Shild had for a `warn`-tier read was "log it and do nothing".

Redemption is PM-based, not a web CAPTCHA -- a public, unauthenticated
web flow was already explicitly ruled out for this project (see
CLAUDE.md's 2026-08-22 BlackTools/Armour investigation, which excluded
Armour's own web CAPTCHA specifically because it needs public web
exposure WebPanel deliberately doesn't have). A silenced user is
NOTICEd a one-time code and told to PM the bot `verify <code>`; a
correct code from the SAME host lifts the mode immediately (see
plugin.py's `verify` command). No code, no problem: the mode still
auto-lifts after silence.durationSecs regardless (a periodic sweep,
plugin.py), same fail-open philosophy as every other timed real action
in this codebase (protection.banDurationSecs, SpamGuard's own
auto-unban).

Pure: no supybot import, no I/O beyond its own JSON file -- same
convention as ban_ids.py/hostbans.py. Locked (matching the 2026-08-24
TermStore/ban_ids.py fix) since this is read/written from both the
worker thread (a fresh warn silences someone) and the main IRC thread
(a `verify` PM, or the periodic auto-lift sweep).
"""
from __future__ import annotations

import json
import secrets
import string
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# Visually-ambiguous characters (0/O, 1/I/L) excluded so a code read off
# an IRC client is easy to type back correctly.
_CODE_ALPHABET = "".join(c for c in string.ascii_uppercase + string.digits if c not in "01IOL")


def generate_code(length: int = 6) -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(length))


@dataclass
class SilenceRecord:
    network: str
    channel: str
    host: str
    nick: str
    mask: str
    mode_char: str  # "q" (quiet, no kick needed) or "b" (ban, no kick -- ircu fallback)
    code: str
    reason: str
    silenced_at: float
    expires_at: float

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "SilenceRecord":
        return SilenceRecord(
            network=d["network"], channel=d["channel"], host=d["host"],
            nick=d.get("nick", ""), mask=d["mask"], mode_char=d.get("mode_char", "b"),
            code=d["code"], reason=d.get("reason", ""),
            silenced_at=float(d.get("silenced_at", 0.0)),
            expires_at=float(d.get("expires_at", 0.0)),
        )

    def key(self) -> tuple:
        return (self.network, self.channel, self.host)


class SilenceStore:
    """Loads/saves every currently-tracked (i.e. not yet lifted) silence
    from one JSON file, resolved relative to the bot's own working
    directory (runtime/) -- same convention as banIdsPath/hostBansPath.
    A record is removed the moment it's lifted (verified or expired) --
    this is live enforcement state, not a history log (unlike
    SpamGuard's HostBanStore, which deliberately keeps expired entries
    around); enforcement_actions.jsonl already carries the permanent
    record via collector.py.
    """

    def __init__(self, path):
        self.path = Path(path)
        self._records: dict[tuple, SilenceRecord] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            # Fails closed to an empty store -- a corrupt file must never
            # crash plugin load, and losing in-flight silence tracking on
            # a restart is not the kind of state loss real enforcement
            # depends on: the actual channel modes stay set on the ircd
            # side regardless, this file only tracks how to LIFT them.
            return
        for entry in raw.get("silences", []):
            try:
                r = SilenceRecord.from_dict(entry)
            except (KeyError, TypeError, ValueError):
                continue
            self._records[r.key()] = r

    def _save_locked(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            data = {"silences": [r.to_dict() for r in self._records.values()]}
            tmp.write_text(json.dumps(data, indent=2))
            tmp.replace(self.path)
        except OSError:
            pass  # tracking must never crash real enforcement

    def add(self, record: SilenceRecord) -> None:
        with self._lock:
            self._records[record.key()] = record
            self._save_locked()

    def get(self, network: str, channel: str, host: str) -> Optional[SilenceRecord]:
        with self._lock:
            return self._records.get((network, channel, host))

    def get_by_code(self, code: str) -> Optional[SilenceRecord]:
        with self._lock:
            for r in self._records.values():
                if r.code == code:
                    return r
            return None

    def remove(self, key: tuple) -> bool:
        with self._lock:
            if key in self._records:
                del self._records[key]
                self._save_locked()
                return True
            return False

    def prune_expired(self, *, now: float) -> list:
        """Deletes and returns every record whose expires_at has passed --
        the caller (plugin.py's periodic sweep) is responsible for
        actually lifting the real IRC mode for each one returned."""
        with self._lock:
            expired = [r for r in self._records.values() if r.expires_at <= now]
            for r in expired:
                del self._records[r.key()]
            if expired:
                self._save_locked()
            return expired

    def all(self) -> list:
        with self._lock:
            return sorted(self._records.values(), key=lambda r: r.silenced_at, reverse=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
