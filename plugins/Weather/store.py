"""Persisted JSON stores: saved per-user locations, and the (mandatory,
see geocode.py's module docstring) Nominatim geocode cache. Pure, no
supybot import.

Record shape/corrupt-handling copied from plugins/SpamGuard/terms.py's
TermStore (dataclass records with defensive to_dict/from_dict, two-layer
corrupt handling: whole-file parse failure -> empty store, one malformed
record -> skip just that record). Save mechanics copied from
plugins/GitHubWatch/state.py's SeenStateStore (atomic .tmp + replace()
write, swallow OSError -- a state-file write failure must never crash
the plugin). Both stores add a threading.Lock, held across the ENTIRE
load-mutate-save sequence -- see cache.py's module docstring for why:
this plugin's `threaded = True` means every command gets its own thread,
unlike every store this pattern was copied from (all single-threaded).
Two threads racing to write the same ".tmp" path is the specific failure
this guards against.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


# -- key derivation --------------------------------------------------

_RFC1459_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\\~",
    "abcdefghijklmnopqrstuvwxyz{}|^",
)


def rfc1459_lower(s: str) -> str:
    """IRC nick/channel case-folding per RFC 1459 -- []\\~ fold to
    {}|^ in addition to plain ASCII case, so e.g. "Foo[x]" and "foo{x}"
    are the same nick. Reimplemented here (rather than importing
    supybot.ircutils.toLower) because this module is deliberately
    supybot-free -- see the module docstring.
    """
    return s.translate(_RFC1459_LOWER)


def location_key(account: Optional[str], network: str, nick: str) -> str:
    """A saved location is always keyed to an identity, never a bare
    nick alone -- a registered ircdb account (stable across host/nick
    changes) if the caller has one, else (network, case-folded nick).
    Two disjoint key namespaces ("acct:"/"nick:") so a nick can never
    collide with an account name.
    """
    if account:
        return f"acct:{account}"
    return f"nick:{network}/{rfc1459_lower(nick)}"


# -- saved locations ---------------------------------------------------

@dataclass
class SavedLocation:
    key: str
    place: str
    label: str
    lat: Optional[float]
    lon: Optional[float]
    saved_by: str
    saved_at: float

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "SavedLocation":
        return SavedLocation(
            key=d["key"],
            place=d["place"],
            label=d.get("label", d["place"]),
            lat=d.get("lat"),
            lon=d.get("lon"),
            saved_by=d.get("saved_by", ""),
            saved_at=d.get("saved_at", 0.0),
        )


class LocationStore:
    """User data -- never pruned, never expired. Resolved relative to
    the bot's own working directory (runtime/); the code default lives
    in config.py as a bare "data/..." path (see that file's docstring
    for the repeated "runtime/runtime/" bug this avoids).
    """

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._locations: dict = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return
        for entry in raw.get("locations", []):
            try:
                loc = SavedLocation.from_dict(entry)
            except (KeyError, TypeError, ValueError):
                continue
            self._locations[loc.key] = loc

    def _save_locked(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {"locations": [loc.to_dict() for loc in self._locations.values()]}
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
            tmp.replace(self.path)
            return True
        except OSError:
            return False

    def get(self, key: str) -> Optional[SavedLocation]:
        with self._lock:
            return self._locations.get(key)

    def set(self, loc: SavedLocation) -> bool:
        """Returns False on a disk write failure -- the caller must not
        claim success to the user in that case (see plugin.py).
        """
        with self._lock:
            self._locations[loc.key] = loc
            return self._save_locked()

    def unset(self, key: str) -> Optional[SavedLocation]:
        with self._lock:
            loc = self._locations.pop(key, None)
            if loc is not None:
                self._save_locked()
            return loc

    def all(self) -> list:
        with self._lock:
            return list(self._locations.values())


# -- geocode cache -------------------------------------------------------

@dataclass
class GeocodeRecord:
    query: str
    lat: Optional[float]
    lon: Optional[float]
    display_name: str
    short_name: str
    country_code: str
    fetched_at: float
    miss: bool

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "GeocodeRecord":
        return GeocodeRecord(
            query=d["query"],
            lat=d.get("lat"),
            lon=d.get("lon"),
            display_name=d.get("display_name", ""),
            short_name=d.get("short_name", ""),
            country_code=d.get("country_code", ""),
            fetched_at=d.get("fetched_at", 0.0),
            miss=bool(d.get("miss", False)),
        )


class GeocodeStore:
    """A CACHE, not user data -- prunable/clearable independently of
    LocationStore. Persisted (not just in-process) because Nominatim's
    usage policy makes client-side caching mandatory, and an in-process
    cache is wiped by every restart/`@reload` -- both frequent in this
    deployment. See geocode.py.
    """

    def __init__(self, path, max_entries: int = 2000):
        self.path = Path(path)
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._records: dict = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return
        for entry in raw.get("records", []):
            try:
                rec = GeocodeRecord.from_dict(entry)
            except (KeyError, TypeError, ValueError):
                continue
            self._records[rec.query] = rec

    def _save_locked(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {"records": [r.to_dict() for r in self._records.values()]}
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
            tmp.replace(self.path)
            return True
        except OSError:
            return False

    def get(self, query: str) -> Optional[GeocodeRecord]:
        """No TTL logic here -- the caller (geocode.py) decides freshness
        and whether to serve a stale record.
        """
        with self._lock:
            return self._records.get(query)

    def put(self, rec: GeocodeRecord) -> bool:
        with self._lock:
            self._records[rec.query] = rec
            self._prune_locked()
            return self._save_locked()

    def _prune_locked(self) -> int:
        if len(self._records) <= self.max_entries:
            return 0
        # Oldest-fetched-first eviction once over the cap.
        overflow = len(self._records) - self.max_entries
        oldest = sorted(self._records.values(), key=lambda r: r.fetched_at)[:overflow]
        for r in oldest:
            del self._records[r.query]
        return overflow

    def prune(self, now: float, hit_ttl: float, miss_ttl: float, max_entries: int = None) -> int:
        """Explicit time-based prune (used by !weathercacheclear's
        maintenance path or a periodic sweep) -- removes any record past
        its TTL (hits and misses use different TTLs) in addition to the
        size-based eviction _prune_locked already does on every put().
        """
        with self._lock:
            if max_entries is not None:
                self.max_entries = max_entries
            removed = 0
            for query in list(self._records):
                rec = self._records[query]
                ttl = miss_ttl if rec.miss else hit_ttl
                if now - rec.fetched_at > ttl:
                    del self._records[query]
                    removed += 1
            if removed:
                self._save_locked()
            return removed

    def clear(self) -> int:
        with self._lock:
            n = len(self._records)
            self._records = {}
            self._save_locked()
            return n

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
