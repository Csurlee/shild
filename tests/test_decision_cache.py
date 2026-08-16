from shildml.evidence import HostEvidence
from shildml.fusion import FusedDecision

from plugins.Shild.decision_cache import DecisionCache


def _decision(action="ban", confidence=0.6) -> FusedDecision:
    return FusedDecision(action=action, confidence=confidence, reason="test",
                          source="classifier", degraded=False, gate_applied=False)


def test_miss_on_empty_cache():
    cache = DecisionCache()
    assert cache.get("undernet", "1.2.3.4") is None


def test_hit_returns_the_same_fused_decision():
    cache = DecisionCache()
    fused = _decision()
    cache.set("undernet", "1.2.3.4", fused, None)
    got = cache.get("undernet", "1.2.3.4")
    assert got is not None
    assert got[0] is fused
    assert got[1] is None


def test_hit_returns_the_cached_evidence_too():
    cache = DecisionCache()
    fused = _decision()
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=100)
    cache.set("undernet", "1.2.3.4", fused, ev)
    got_fused, got_ev = cache.get("undernet", "1.2.3.4")
    assert got_fused is fused
    assert got_ev is ev


def test_scoped_per_network():
    cache = DecisionCache()
    cache.set("undernet", "1.2.3.4", _decision(), None)
    assert cache.get("libera", "1.2.3.4") is None


def test_scoped_per_host_not_nick():
    """The whole point: two different nicks from the same host must hit
    the SAME cache entry -- there is no nick parameter at all."""
    cache = DecisionCache()
    fused = _decision()
    cache.set("undernet", "1.2.3.4", fused, None)
    assert cache.get("undernet", "1.2.3.4")[0] is fused


def test_expires_after_ttl():
    cache = DecisionCache(ttl_secs=0.01)
    cache.set("undernet", "1.2.3.4", _decision(), None)
    import time
    time.sleep(0.02)
    assert cache.get("undernet", "1.2.3.4") is None


def test_expired_entry_is_evicted_not_just_hidden():
    cache = DecisionCache(ttl_secs=0.01)
    cache.set("undernet", "1.2.3.4", _decision(), None)
    import time
    time.sleep(0.02)
    cache.get("undernet", "1.2.3.4")  # triggers eviction
    assert len(cache) == 0


def test_a_hit_does_not_refresh_the_entrys_age():
    """A flapping connection reconnecting constantly must still get a
    fresh look eventually -- repeatedly reading a cached entry must not
    keep extending its own life."""
    cache = DecisionCache(ttl_secs=0.03)
    cache.set("undernet", "1.2.3.4", _decision(), None)
    import time
    for _ in range(3):
        time.sleep(0.015)
        cache.get("undernet", "1.2.3.4")
    time.sleep(0.02)
    assert cache.get("undernet", "1.2.3.4") is None


def test_blank_host_never_cached():
    cache = DecisionCache()
    cache.set("undernet", "", _decision(), None)
    assert len(cache) == 0
    assert cache.get("undernet", "") is None


def test_lru_bounded():
    cache = DecisionCache(max_entries=3)
    for i in range(5):
        cache.set("undernet", f"1.1.1.{i}", _decision(), None)
    assert len(cache) == 3
    assert cache.get("undernet", "1.1.1.0") is None
    assert cache.get("undernet", "1.1.1.1") is None
    assert cache.get("undernet", "1.1.1.4") is not None


def test_set_overwrites_existing_entry():
    cache = DecisionCache()
    first = _decision(action="warn", confidence=0.3)
    second = _decision(action="ban", confidence=0.8)
    cache.set("undernet", "1.2.3.4", first, None)
    cache.set("undernet", "1.2.3.4", second, None)
    got, _ev = cache.get("undernet", "1.2.3.4")
    assert got is second


# ---- in-flight tracking (2026-08-16, closes the burst/stampede gap) ----

def test_not_in_flight_by_default():
    cache = DecisionCache()
    assert cache.is_in_flight("undernet", "1.2.3.4") is False


def test_mark_in_flight_then_is_in_flight_true():
    cache = DecisionCache()
    cache.mark_in_flight("undernet", "1.2.3.4", now=100.0)
    assert cache.is_in_flight("undernet", "1.2.3.4", now=100.0) is True


def test_clear_in_flight_makes_it_false_again():
    cache = DecisionCache()
    cache.mark_in_flight("undernet", "1.2.3.4", now=100.0)
    cache.clear_in_flight("undernet", "1.2.3.4")
    assert cache.is_in_flight("undernet", "1.2.3.4", now=100.0) is False


def test_clear_in_flight_is_a_noop_for_an_unmarked_host():
    cache = DecisionCache()
    cache.clear_in_flight("undernet", "1.2.3.4")  # must not raise


def test_in_flight_scoped_by_network_and_host():
    cache = DecisionCache()
    cache.mark_in_flight("undernet", "1.2.3.4", now=100.0)
    assert cache.is_in_flight("libera", "1.2.3.4", now=100.0) is False
    assert cache.is_in_flight("undernet", "5.6.7.8", now=100.0) is False


def test_blank_host_never_marked_in_flight():
    cache = DecisionCache()
    cache.mark_in_flight("undernet", "", now=100.0)
    assert cache.is_in_flight("undernet", "", now=100.0) is False


def test_in_flight_expires_after_the_stale_ceiling():
    # Bounds the damage from a worker.submit() that silently drops the
    # job (worker.py: not running / queue full / event loop gone all
    # skip the on_result callback entirely) -- without this, a single
    # dropped job would leave the host permanently unmoderated.
    cache = DecisionCache()
    cache.mark_in_flight("undernet", "1.2.3.4", now=100.0)
    just_under = 100.0 + DecisionCache.IN_FLIGHT_STALE_AFTER_SECS - 1
    just_over = 100.0 + DecisionCache.IN_FLIGHT_STALE_AFTER_SECS + 1
    assert cache.is_in_flight("undernet", "1.2.3.4", now=just_under) is True
    assert cache.is_in_flight("undernet", "1.2.3.4", now=just_over) is False


def test_in_flight_and_decided_are_independent_states():
    # A host can be genuinely decided (in _store) while ALSO, separately,
    # having a stale/leftover in-flight marker (or vice versa) -- the two
    # trackers must never be conflated with each other.
    cache = DecisionCache()
    cache.set("undernet", "1.2.3.4", _decision(), None)
    cache.mark_in_flight("undernet", "1.2.3.4", now=100.0)
    assert cache.get("undernet", "1.2.3.4") is not None
    assert cache.is_in_flight("undernet", "1.2.3.4", now=100.0) is True
