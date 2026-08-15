"""Rate limiting and persisted quota tracking for external reputation
providers. Two independent constraints, tracked per provider:

  - a per-minute token bucket (e.g. ip-api.com's 45 req/min free tier)
  - daily / lifetime counters (e.g. AbuseIPDB's 1000/day, or a "1000 free
    lookups total" style quota) persisted to disk so a bot restart can't
    silently reset a quota an admin is trying to conserve.

Persisted as plain JSON rather than sqlite -- call volume here is low
(only for Tier 1/2 lookups, which are already gated to a minority of
events by evidence.py's trust tiering), so a full write on every consume
is cheap and keeps the file always consistent with no separate flush step.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class TokenBucket:
    """Standard token bucket. Not persisted -- a per-minute rate limit
    resetting on restart is harmless; only the daily/lifetime counters in
    BudgetManager need to survive a restart.
    """

    def __init__(self, rate_per_min: float, capacity: Optional[float] = None):
        self.rate_per_sec = rate_per_min / 60.0
        self.capacity = capacity if capacity is not None else rate_per_min
        self._tokens = self.capacity
        self._last = time.monotonic()

    def try_acquire(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False


@dataclass
class ProviderLimits:
    rate_per_min: Optional[float] = None
    daily_limit: Optional[int] = None
    lifetime_limit: Optional[int] = None


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class BudgetManager:
    """One instance shared by all reputation providers. Thread-safe: the
    worker thread (plugins/Shild/worker.py) is where every call happens,
    but !shildstatus reads `.stats()` from Limnoria's main thread, so
    every access goes through `_lock`.
    """

    def __init__(self, path: str, limits: dict[str, ProviderLimits]):
        self.path = Path(path)
        self.limits = limits
        self._buckets = {
            name: TokenBucket(lim.rate_per_min)
            for name, lim in limits.items() if lim.rate_per_min
        }
        self._lock = threading.Lock()
        self._state: dict = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state, indent=2, sort_keys=True))
            tmp.replace(self.path)
        except OSError:
            pass  # budget tracking must never crash a lookup

    def try_consume(self, name: str) -> bool:
        """True if this provider may be called right now (and records
        that it was). False means: skip the call, record the event as a
        failed/budget-exhausted check, never block waiting for tokens --
        an evidence lookup that stalls the worker defeats the point.
        """
        with self._lock:
            lim = self.limits.get(name)
            if lim is None:
                return True  # untracked provider -- no budget configured
            bucket = self._buckets.get(name)
            if bucket is not None and not bucket.try_acquire():
                return False
            st = self._state.setdefault(name, {"date": _today(), "daily": 0, "lifetime": 0})
            if st.get("date") != _today():
                st["date"] = _today()
                st["daily"] = 0
            if lim.daily_limit is not None and st["daily"] >= lim.daily_limit:
                return False
            if lim.lifetime_limit is not None and st["lifetime"] >= lim.lifetime_limit:
                return False
            st["daily"] += 1
            st["lifetime"] += 1
            self._save()
            return True

    def stats(self) -> dict:
        with self._lock:
            return {name: dict(st) for name, st in self._state.items()}
