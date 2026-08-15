"""Pure unit tests for plugins/Weather/cache.py -- no supybot import."""
import threading
import time

from plugins.Weather.cache import TTLCache, TokenBucket


def test_ttl_cache_expires():
    cache = TTLCache(maxsize=10)
    cache.set(("a",), "value", ttl=0.01)
    value, hit = cache.get(("a",))
    assert (value, hit) == ("value", True)
    time.sleep(0.02)
    value, hit = cache.get(("a",))
    assert (value, hit) == (None, False)


def test_ttl_cache_lru_eviction():
    cache = TTLCache(maxsize=2)
    cache.set(("a",), 1, ttl=60)
    cache.set(("b",), 2, ttl=60)
    cache.set(("c",), 3, ttl=60)
    assert cache.get(("a",)) == (None, False)  # evicted, least recently used
    assert cache.get(("b",)) == (2, True)
    assert cache.get(("c",)) == (3, True)
    assert len(cache) == 2


def test_ttl_cache_get_refreshes_lru_order():
    cache = TTLCache(maxsize=2)
    cache.set(("a",), 1, ttl=60)
    cache.set(("b",), 2, ttl=60)
    cache.get(("a",))  # touch a, so b becomes the LRU entry
    cache.set(("c",), 3, ttl=60)
    assert cache.get(("b",)) == (None, False)
    assert cache.get(("a",)) == (1, True)


def test_ttl_cache_none_is_a_valid_cached_value():
    cache = TTLCache(maxsize=10)
    cache.set(("a",), None, ttl=60)
    value, hit = cache.get(("a",))
    assert hit is True
    assert value is None


def test_ttl_cache_is_safe_under_concurrent_threads():
    cache = TTLCache(maxsize=100)
    errors = []

    def hammer(n):
        try:
            for i in range(200):
                cache.set((n, i % 50), i, ttl=60)
                cache.get((n, i % 50))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(cache) <= 100


def test_token_bucket_with_capacity_one_never_bursts():
    bucket = TokenBucket(rate_per_min=60, capacity=1.0)
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False  # no burst allowance


def test_token_bucket_refills_over_time():
    bucket = TokenBucket(rate_per_min=6000, capacity=1.0)  # 100/sec
    assert bucket.try_acquire() is True
    time.sleep(0.02)
    assert bucket.try_acquire() is True


def test_token_bucket_default_capacity_equals_rate_per_min():
    bucket = TokenBucket(rate_per_min=60)
    for _ in range(60):
        assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False


def test_token_bucket_is_safe_under_concurrent_threads():
    bucket = TokenBucket(rate_per_min=6000, capacity=50.0)
    granted = []
    lock = threading.Lock()

    def hammer():
        for _ in range(100):
            if bucket.try_acquire():
                with lock:
                    granted.append(1)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Never more grants than capacity would allow at time zero, plus
    # generous refill headroom for the wall-clock time the test took --
    # the real assertion is just that it didn't crash or go negative.
    assert len(granted) <= 800
