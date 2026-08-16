import threading
import time

from plugins.Shild.context import ContextStore


def test_identity_recorded_on_snapshot():
    ctx = ContextStore()
    ctx.snapshot("libera", "#windrop", "alice", "~alice", "1.2.3.4")
    assert ctx.identity_for_nick("libera", "alice") == ("~alice", "1.2.3.4")


def test_identity_lookup_is_case_insensitive():
    ctx = ContextStore()
    ctx.snapshot("libera", "#windrop", "Alice", "~alice", "1.2.3.4")
    assert ctx.identity_for_nick("libera", "ALICE") == ("~alice", "1.2.3.4")


def test_identity_scoped_per_network():
    ctx = ContextStore()
    ctx.snapshot("libera", "#windrop", "bob", "~bob", "1.1.1.1")
    assert ctx.identity_for_nick("undernet", "bob") is None


def test_unknown_nick_returns_none():
    ctx = ContextStore()
    assert ctx.identity_for_nick("libera", "nobody") is None


def test_identity_updates_on_new_snapshot_same_nick():
    ctx = ContextStore()
    ctx.snapshot("libera", "#windrop", "carl", "~carl", "1.1.1.1")
    ctx.snapshot("libera", "#other", "carl", "~carl", "2.2.2.2")
    assert ctx.identity_for_nick("libera", "carl") == ("~carl", "2.2.2.2")


def test_identity_cache_is_lru_bounded():
    ctx = ContextStore(max_tracked_nicks=3)
    for i in range(5):
        ctx.snapshot("libera", "#windrop", f"nick{i}", f"~i{i}", f"1.1.1.{i}")
    # Oldest two evicted, most recent three retained.
    assert ctx.identity_for_nick("libera", "nick0") is None
    assert ctx.identity_for_nick("libera", "nick1") is None
    assert ctx.identity_for_nick("libera", "nick4") == ("~i4", "1.1.1.4")


def test_identity_survives_being_kicked_from_state_perspective():
    """The whole point of this cache: it must still answer for a nick
    even after Limnoria's own IrcState would already have forgotten them
    (post-KICK) -- see module docstring. Nothing here depends on
    irc.state at all, which is exactly the property being tested.
    """
    ctx = ContextStore()
    ctx.snapshot("libera", "#windrop", "spammer", "~spam", "203.0.113.9")
    # Simulate time passing / the user being removed from channel state
    # elsewhere -- the identity cache is independent of channel roster.
    assert ctx.identity_for_nick("libera", "spammer") == ("~spam", "203.0.113.9")


# ---- nick_history_for_host (2026-08-16): ban-evasion / alias tracking ----

def test_nick_history_returns_prior_nicks_most_recent_first():
    ctx = ContextStore()
    ctx.snapshot("undernet", "#windrop", "evader1", "~e", "203.0.113.9")
    ctx.snapshot("undernet", "#windrop", "evader2", "~e", "203.0.113.9")
    ctx.snapshot("undernet", "#windrop", "evader3", "~e", "203.0.113.9")
    history = ctx.nick_history_for_host("undernet", "203.0.113.9")
    assert history == ["evader3", "evader2", "evader1"]


def test_nick_history_excludes_the_current_nick_case_insensitively():
    ctx = ContextStore()
    ctx.snapshot("undernet", "#windrop", "Evader", "~e", "203.0.113.9")
    ctx.snapshot("undernet", "#windrop", "evader2", "~e", "203.0.113.9")
    history = ctx.nick_history_for_host("undernet", "203.0.113.9", exclude_nick="EVADER2")
    assert history == ["Evader"]


def test_nick_history_dedupes_same_nick_case_insensitively():
    ctx = ContextStore()
    ctx.snapshot("undernet", "#windrop", "Bob", "~b", "203.0.113.9")
    ctx.snapshot("undernet", "#windrop", "bob", "~b", "203.0.113.9")
    history = ctx.nick_history_for_host("undernet", "203.0.113.9", exclude_nick="nobody")
    assert history == ["bob"]  # one entry, most-recent spelling kept


def test_nick_history_unknown_host_returns_empty_and_creates_no_state():
    ctx = ContextStore()
    assert ctx.nick_history_for_host("undernet", "198.51.100.1") == []


def test_nick_history_scoped_per_network():
    ctx = ContextStore()
    ctx.snapshot("libera", "#windrop", "alice", "~a", "203.0.113.9")
    assert ctx.nick_history_for_host("undernet", "203.0.113.9") == []


def test_nick_history_respects_limit():
    ctx = ContextStore()
    for i in range(5):
        ctx.snapshot("undernet", "#windrop", f"n{i}", "~n", "203.0.113.9")
    assert len(ctx.nick_history_for_host("undernet", "203.0.113.9", limit=2)) == 2


def test_nick_history_is_lru_bounded_per_host():
    ctx = ContextStore(max_nicks_per_host=3)
    for i in range(5):
        ctx.snapshot("undernet", "#windrop", f"n{i}", "~n", "203.0.113.9")
    history = ctx.nick_history_for_host("undernet", "203.0.113.9")
    assert "n0" not in history
    assert "n1" not in history
    assert set(history) == {"n2", "n3", "n4"}


def test_nick_history_a_manual_check_does_not_mutate_state():
    """Same discipline as observed_context: a read must never itself
    become a recorded event -- calling this repeatedly must not add
    entries or otherwise change future results."""
    ctx = ContextStore()
    ctx.snapshot("undernet", "#windrop", "real", "~r", "203.0.113.9")
    for _ in range(10):
        ctx.nick_history_for_host("undernet", "203.0.113.9")
    assert ctx.nick_history_for_host("undernet", "203.0.113.9") == ["real"]


def test_nick_history_blank_host_never_tracked():
    ctx = ContextStore()
    ctx.snapshot("undernet", "#windrop", "cloaked", "~c", "")
    assert ctx.nick_history_for_host("undernet", "") == []


# ---- WebPanel accessors: reads off a second thread, plus the lock that
# makes that safe (see context.py's module/ContextStore docstrings) ----

def test_recent_global_events_returns_newest_first():
    ctx = ContextStore()
    ctx.record_event("libera", "#windrop", "join", "alice", "1.1.1.1", ts=1.0)
    ctx.record_event("libera", "#windrop", "join", "bob", "2.2.2.2", ts=2.0)
    events = ctx.recent_global_events(limit=10)
    assert [e[4] for e in events] == ["bob", "alice"]


def test_recent_global_events_respects_limit():
    ctx = ContextStore()
    for i in range(10):
        ctx.record_event("libera", "#windrop", "join", f"n{i}", "1.1.1.1", ts=float(i))
    assert len(ctx.recent_global_events(limit=3)) == 3


def test_recent_global_events_filters_by_network_and_channel():
    ctx = ContextStore()
    ctx.record_event("libera", "#windrop", "join", "alice", "1.1.1.1", ts=1.0)
    ctx.record_event("undernet", "#windrop", "join", "bob", "2.2.2.2", ts=2.0)
    ctx.record_event("libera", "#other", "join", "carl", "3.3.3.3", ts=3.0)
    events = ctx.recent_global_events(limit=10, network="libera", channel="#windrop")
    assert [e[4] for e in events] == ["alice"]


def test_recent_global_events_returns_a_copy_not_the_live_deque():
    ctx = ContextStore()
    ctx.record_event("libera", "#windrop", "join", "alice", "1.1.1.1", ts=1.0)
    events = ctx.recent_global_events(limit=10)
    events.clear()
    assert len(ctx.recent_global_events(limit=10)) == 1


def test_recent_channel_events_scoped_to_one_channel():
    ctx = ContextStore()
    ctx.record_event("libera", "#windrop", "join", "alice", "1.1.1.1", ts=1.0)
    ctx.record_event("libera", "#other", "join", "bob", "2.2.2.2", ts=2.0)
    events = ctx.recent_channel_events("libera", "#windrop", limit=10)
    assert [e[2] for e in events] == ["alice"]


def test_recent_channel_events_unknown_channel_returns_empty_and_creates_no_state():
    ctx = ContextStore()
    events = ctx.recent_channel_events("libera", "#neverjoined", limit=10)
    assert events == []
    # The real bug this guards against: _chan is a defaultdict, so a
    # naive self._chan[key] lookup here would silently create -- and
    # leak -- state for any channel name a browser happens to type into
    # a URL. tracked_channels() must NOT show it after the read above.
    assert ("libera", "#neverjoined") not in ctx.tracked_channels()


def test_tracked_channels_lists_only_channels_with_events():
    ctx = ContextStore()
    ctx.record_event("libera", "#windrop", "join", "alice", "1.1.1.1")
    ctx.record_event("undernet", "#relay", "join", "bob", "2.2.2.2")
    assert set(ctx.tracked_channels()) == {("libera", "#windrop"), ("undernet", "#relay")}


def test_tracked_nick_count_matches_snapshots_taken():
    ctx = ContextStore()
    ctx.snapshot("libera", "#windrop", "alice", "~alice", "1.1.1.1")
    ctx.snapshot("libera", "#windrop", "bob", "~bob", "2.2.2.2")
    assert ctx.tracked_nick_count() == 2


def test_concurrent_reads_and_writes_do_not_raise():
    """The scenario WebPanel introduces: one thread (IRC) keeps calling
    snapshot()/record_event() while another thread (HTTP) repeatedly
    reads recent_global_events()/recent_channel_events() -- iterating a
    plain deque while another thread appends to it raises
    `RuntimeError: deque mutated during iteration` without the lock in
    context.py. This test fails (via the exception propagating out of
    the thread and being re-raised) if that regresses.
    """
    ctx = ContextStore()
    errors: list[Exception] = []
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            ctx.snapshot("libera", "#windrop", f"nick{i % 50}", "~ident",
                         f"1.2.3.{i % 250}")
            i += 1

    def reader():
        try:
            while not stop.is_set():
                ctx.recent_global_events(limit=50)
                ctx.recent_channel_events("libera", "#windrop", limit=50)
                ctx.tracked_channels()
                ctx.tracked_nick_count()
        except Exception as e:  # pragma: no cover - failure path
            errors.append(e)

    threads = [threading.Thread(target=writer) for _ in range(2)]
    threads += [threading.Thread(target=reader) for _ in range(2)]
    for t in threads:
        t.start()
    time.sleep(0.3)
    stop.set()
    for t in threads:
        t.join(timeout=5)

    assert errors == []
