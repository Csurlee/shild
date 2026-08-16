"""Small TTL+LRU cache of the most recent fused decision per (network,
host) -- added 2026-08-16 after a real live incident: a host reconnecting
to a busy channel every 15-90 seconds (a flapping/reconnecting client,
not a fresh attempt each time) was re-running the FULL classifier +
evidence pipeline -- real AbuseIPDB/Scamalytics network calls, real
budget consumption, a real proxy-port scan -- and re-posting an
identical `[shadow] BAN ...` line every single time, for a host that had
already been fully evaluated seconds earlier with nothing new to say.

Keyed by (network, host), NOT (network, nick, host) -- deliberately.
Every hard corroborating signal (AbuseIPDB/Scamalytics score, an open
proxy port, the geo/hosting flag) is a property of the HOST/IP, not the
nick, so caching at the host level is the correct precision: a nick
change from the same host reuses the same well-founded decision instead
of forcing a fresh (and, on this deployment, real-money/rate-limited)
lookup for no new information about the host itself. This is a
deliberate, small precision tradeoff for a large efficiency win --
accepted because context.py's own nick_history_for_host (2026-08-16,
same session) already surfaces a nick change from a given host as a
visible fact in !shildcheck, so ban-evasion via nick-cycling is still
detectable, just not independently re-scored by the expensive pipeline
every single time.

A cache hit skips the shadow-log write and the [shadow] relay (neither
would carry any new information -- see plugin.py's _handle_event), but
STILL runs real enforcement if it's newly eligible (the bot could have
been opped, or the kill switch flipped off, since the original decision
was cached) -- being cached is about not re-deciding, never about
suppressing real protection once it's armed.

IN-FLIGHT TRACKING (2026-08-16, same day, a second real incident): the
cache above only protects a NEW event arriving AFTER a prior evaluation
for the same host has already fully COMPLETED -- it does nothing for a
BURST of near-simultaneous events, none of which have anything cached
yet to hit. Confirmed live: a host (Tarram, 64.44.38.254) flooding
messages roughly every ~2s produced 5 separate full evidence-gathering
passes and 5 separate [shadow] relay lines within seconds, each with a
slightly different classifier confidence (join_rate shifting between
calls) -- verified against shadow_decisions.jsonl's own recorded
lookup_ms (~2000ms each, matching worker.maxConcurrency=1 serializing
them one after another) that these were genuinely five independent,
redundant Tier 1-3 evaluations of the identical host, not five
legitimately different reads. mark_in_flight()/is_in_flight()/
clear_in_flight() close this gap: plugin.py marks a host in-flight the
moment it dispatches a worker evaluation (BEFORE the cache has anything
to show for it) and clears it once that evaluation resolves (in
_finish(), which every resolution path already runs through); a second
event for the same host arriving while it's in-flight is dropped
outright -- no worker dispatch, no shadow-log write, no relay -- since
the in-flight evaluation's own eventual _finish() already covers
enforcement for that host, and a second concurrent lookup of the exact
same IP would never learn anything new anyway.

Pure, no supybot import -- plugin.py holds the actual instance and reads
its config from the registry (decisionCache.enabled/ttlSecs).
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Optional, Tuple

from shildml.evidence import HostEvidence
from shildml.fusion import FusedDecision

CacheKey = Tuple[str, str]  # (network, host)
CacheValue = Tuple[FusedDecision, Optional[HostEvidence]]


class DecisionCache:
    # Ceiling on how long an in-flight marker is trusted before being
    # treated as stale/abandoned, regardless of clear_in_flight() ever
    # being called. Real evidence-gathering (Tier 1-3, worst case) has
    # been measured well under this; the ceiling exists purely to bound
    # the damage from a worker.submit() that silently drops the job
    # (worker.py's Worker.submit: not running, queue full, or the event
    # loop already gone all fail this way with NO callback ever firing)
    # -- without this, a single dropped job would leave that host
    # permanently unmoderated (is_in_flight() always True) until the
    # next full restart, which is a far worse failure mode than the
    # rare double-evaluation this ceiling might occasionally still allow.
    IN_FLIGHT_STALE_AFTER_SECS = 60.0

    def __init__(self, ttl_secs: float = 1800.0, max_entries: int = 2000):
        self.ttl_secs = ttl_secs
        self.max_entries = max_entries
        self._store: "OrderedDict[CacheKey, Tuple[float, CacheValue]]" = OrderedDict()
        # Separate from _store on purpose -- an in-flight host has no
        # CacheValue yet (the evaluation hasn't resolved), so it can't
        # live in the same dict without conflating "decided" with
        # "being decided". Maps key -> the time it was marked, so a
        # stuck entry (see IN_FLIGHT_STALE_AFTER_SECS above) can expire
        # on its own even if clear_in_flight() is never called for it.
        self._in_flight: dict = {}

    def is_in_flight(self, network: str, host: str, *, now: Optional[float] = None) -> bool:
        if not host:
            return False
        key = (network, host)
        marked_at = self._in_flight.get(key)
        if marked_at is None:
            return False
        now = now if now is not None else time.time()
        if now - marked_at > self.IN_FLIGHT_STALE_AFTER_SECS:
            del self._in_flight[key]
            return False
        return True

    def mark_in_flight(self, network: str, host: str, *, now: Optional[float] = None) -> None:
        if host:
            self._in_flight[(network, host)] = now if now is not None else time.time()

    def clear_in_flight(self, network: str, host: str) -> None:
        self._in_flight.pop((network, host), None)

    def get(self, network: str, host: str) -> Optional[CacheValue]:
        """Returns (fused, evidence) if a decision for this host was
        cached within ttl_secs, else None. A hit does NOT refresh the
        entry's own age -- it still expires ttl_secs after the ORIGINAL
        decision, not after the most recent reuse, so a connection that
        flaps continuously still gets a genuinely fresh look periodically
        rather than being able to keep itself cached forever just by
        reconnecting often.
        """
        if not host:
            return None
        key = (network, host)
        entry = self._store.get(key)
        if entry is None:
            return None
        decided_at, value = entry
        if time.time() - decided_at > self.ttl_secs:
            del self._store[key]
            return None
        return value

    def set(self, network: str, host: str, fused: FusedDecision,
            evidence: Optional[HostEvidence]) -> None:
        if not host:
            return
        key = (network, host)
        self._store[key] = (time.time(), (fused, evidence))
        self._store.move_to_end(key)
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def __len__(self) -> int:
        return len(self._store)
