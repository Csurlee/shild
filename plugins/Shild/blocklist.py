"""Local, offline IP-blocklist membership checks backed by files downloaded
from FireHOL's blocklist-ipsets project (github.com/firehol/blocklist-ipsets
-- an aggregator of many free, community-maintained IP threat lists; see
scripts/update_blocklists.py's own docstring for exactly which specific
lists this project pulls and why).

Deliberately a small, curated set of specific, low-cardinality sources
(a few thousand IPs total across all configured lists) -- NOT FireHOL's
giant multi-million-IP composite aggregates (e.g. "firehol_proxies" alone
is ~3.1 million IPs). Two independent reasons: this box has only ~3.4GB
RAM (see CLAUDE.md's own "hardware is tight" gotcha), and a blind mega-
aggregate mixes in far more false-positive-prone sources than the
individually-named, actively-maintained trackers this project picks
instead -- same curation discipline already applied to the DNSBL zones
(see reputation.py's module docstring: several previously-assumed-good
zones, including Spamhaus's PBL, were tested live and dropped for exactly
this reason).

Fails closed everywhere: a missing directory, a missing individual list
file, or a corrupt one all just mean that list contributes no hits, never
a crash and never a fatal error for the other lists. Each list is loaded
into an in-memory set, keyed and cached by its file's (path, mtime) --
unlike geoip.py's mmdb reader (memory-mapped, no need to reload), a plain
text file has to be re-read to pick up a fresh download, so this checks
mtime on every lookup (a cheap stat() call) and only re-parses when it
actually changed. This means a cron-refreshed list is picked up on the
very next lookup with **no plugin reload or bot restart needed** -- a
genuine usability improvement over most of this codebase's other data
sources.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("supybot")


class _LoadedList:
    __slots__ = ("mtime", "ips")

    def __init__(self, mtime: float, ips: frozenset[str]):
        self.mtime = mtime
        self.ips = ips


_cache: dict[str, _LoadedList] = {}


def _load(path: str) -> Optional[frozenset[str]]:
    p = Path(path)
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return None

    cached = _cache.get(path)
    if cached is not None and cached.mtime == mtime:
        return cached.ips

    try:
        ips = set()
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ips.add(line)
    except OSError:
        log.warning("Blocklist: failed to read %s", path, exc_info=True)
        return None

    loaded = _LoadedList(mtime, frozenset(ips))
    _cache[path] = loaded
    return loaded.ips


def lookup(ip: str, lists: dict[str, str]) -> list[str]:
    """lists: {name: file_path}. Returns the names of every list that
    contains ip -- usually empty or a single name, but a host can
    legitimately appear on more than one source. A missing/unreadable
    individual file is silently skipped, not an error (the others still
    get checked) -- same fail-open convention as every other optional
    evidence source in this codebase.
    """
    hits = []
    for name, path in lists.items():
        ips = _load(path)
        if ips and ip in ips:
            hits.append(name)
    return hits


def any_list_present(lists: dict[str, str]) -> bool:
    """True if at least one configured list file actually exists on disk.
    Used to distinguish "checked, found nothing" from "nothing has been
    downloaded yet" (e.g. scripts/update_blocklists.py hasn't run) --
    same "we don't know" vs. "we checked and it's clean" distinction this
    codebase draws everywhere else (see evidence.py's own module docstring).
    """
    return any(Path(path).is_file() for path in lists.values())


def reset_cache() -> None:
    """Test-only: drop cached parsed lists so a test can point at a fresh
    path without a previous test's state leaking in -- same class of
    cross-test leak this codebase has hit repeatedly (see CLAUDE.md),
    just for this module's own process-level cache instead.
    """
    _cache.clear()
