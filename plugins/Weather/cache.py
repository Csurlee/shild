"""In-process cache and rate limiter. Pure, no supybot import.

Both classes mirror plugins/Shild/reputation.py's TTLCache and
plugins/Shild/budget.py's TokenBucket in spirit (copied, not imported --
see this plugin's module docstrings for why cross-plugin imports are
avoided in this codebase). ONE deliberate difference: both classes here
carry their own threading.Lock. Shild's originals get away without one
because Shild's worker.py funnels every reputation lookup through a
single dedicated worker thread. This plugin sets `threaded = True` on
its callback class (see plugin.py) so that *every command* runs on its
own thread -- without a lock, two concurrent `!w` calls could interleave
an OrderedDict mutation or a TokenBucket's read-modify-write and corrupt
either structure. This was flagged as the single most likely source of
a subtle bug in this plugin during planning -- see CLAUDE.md.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Optional


class TTLCache:
    """Small in-process LRU+TTL cache, thread-safe. Only successful
    lookups should be cached by the caller -- a transient network
    failure should be retried on the next call, not remembered (same
    convention as plugins/Shild/reputation.py's TTLCache).
    """

    def __init__(self, maxsize: int = 2000):
        self.maxsize = maxsize
        self._store: "OrderedDict[tuple, tuple[float, object]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple) -> tuple:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None, False
            expires, value = item
            if time.monotonic() >= expires:
                del self._store[key]
                return None, False
            self._store.move_to_end(key)
            return value, True

    def set(self, key: tuple, value: object, ttl: float) -> None:
        with self._lock:
            self._store[key] = (time.monotonic() + ttl, value)
            self._store.move_to_end(key)
            while len(self._store) > self.maxsize:
                self._store.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


class TokenBucket:
    """Standard token bucket, thread-safe. Not persisted -- a per-minute
    rate limit resetting on restart is harmless here (same reasoning as
    plugins/Shild/budget.py's TokenBucket).

    `capacity` deliberately does NOT default to `rate_per_min` the way
    Shild's does -- geocode.py always constructs this with capacity=1.0
    explicitly, because Nominatim's usage policy caps at 1 request/
    second with NO burst allowance; a default capacity equal to the
    per-minute rate would let a fresh bucket fire 60 requests at once,
    a direct policy violation.
    """

    def __init__(self, rate_per_min: float, capacity: Optional[float] = None):
        self.rate_per_sec = rate_per_min / 60.0
        self.capacity = capacity if capacity is not None else rate_per_min
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self, cost: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False
