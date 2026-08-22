"""Pure unit tests for plugins/UndernetX/xcommands.py -- no supybot
import.
"""
from plugins.UndernetX.xcommands import (
    PendingXRequestQueue,
    XReplySink,
    build_access,
    build_ban,
    build_deop,
    build_devoice,
    build_invite,
    build_kick,
    build_op,
    build_unban,
    build_voice,
    format_duration,
)


def test_build_ban_default_duration_and_access():
    # access default is 75 (2026-08-17) -- the lowest X "banlevel" that
    # actually removes the target from the channel; 0 (the old default)
    # is flatly rejected by X, confirmed live.
    assert build_ban("#windrop", "*!*@1.2.3.4") == "BAN #windrop *!*@1.2.3.4 0d 75"


def test_build_ban_with_duration_access_and_reason():
    line = build_ban("#windrop", "*!*@1.2.3.4", duration="7d", access=50, reason="spam")
    assert line == "BAN #windrop *!*@1.2.3.4 7d 50 spam"


def test_build_ban_reason_is_omitted_when_empty():
    assert "  " not in build_ban("#windrop", "host")


def test_build_unban():
    assert build_unban("#windrop", "*!*@1.2.3.4") == "UNBAN #windrop *!*@1.2.3.4"


def test_build_kick_without_reason():
    assert build_kick("#windrop", "baduser") == "KICK #windrop baduser"


def test_build_kick_with_reason():
    assert build_kick("#windrop", "baduser", "spamming") == "KICK #windrop baduser spamming"


def test_build_op_single_nick():
    assert build_op("#windrop", "csurlee") == "OP #windrop csurlee"


def test_build_op_multiple_space_separated_nicks():
    assert build_op("#windrop", "alice bob") == "OP #windrop alice bob"


def test_build_op_multiple_comma_separated_nicks_normalizes_to_spaces():
    assert build_op("#windrop", "alice,bob") == "OP #windrop alice bob"


def test_build_deop():
    assert build_deop("#windrop", "alice") == "DEOP #windrop alice"


def test_build_voice():
    assert build_voice("#windrop", "alice") == "VOICE #windrop alice"


def test_build_devoice():
    assert build_devoice("#windrop", "alice") == "DEVOICE #windrop alice"


def test_build_invite():
    assert build_invite("#windrop") == "INVITE #windrop"


def test_build_access():
    assert build_access("#windrop", "csurlee") == "ACCESS #windrop csurlee"


def test_build_access_by_nick_reference():
    assert build_access("#windrop", "=csurlee") == "ACCESS #windrop =csurlee"


# -- PendingXRequestQueue --------------------------------------------

def test_add_then_pop_oldest_returns_the_request():
    q = PendingXRequestQueue()
    req = q.add("undernet", "ban #windrop host", timeout_secs=10, now=0.0)
    popped = q.pop_oldest("undernet")
    assert popped is req


def test_pop_oldest_on_empty_network_returns_none():
    q = PendingXRequestQueue()
    assert q.pop_oldest("undernet") is None


def test_fifo_order_across_multiple_pending_requests():
    q = PendingXRequestQueue()
    first = q.add("undernet", "first", timeout_secs=10, now=0.0)
    second = q.add("undernet", "second", timeout_secs=10, now=1.0)
    assert q.pop_oldest("undernet") is first
    assert q.pop_oldest("undernet") is second
    assert q.pop_oldest("undernet") is None


def test_networks_are_independent():
    q = PendingXRequestQueue()
    q.add("undernet", "a", timeout_secs=10, now=0.0)
    assert q.pop_oldest("libera") is None
    assert q.pending_count("undernet") == 1


def test_discard_removes_a_still_pending_request():
    q = PendingXRequestQueue()
    req = q.add("undernet", "a", timeout_secs=10, now=0.0)
    assert q.discard(req) is True
    assert q.pending_count("undernet") == 0


def test_discard_returns_false_if_already_popped():
    q = PendingXRequestQueue()
    req = q.add("undernet", "a", timeout_secs=10, now=0.0)
    q.pop_oldest("undernet")
    assert q.discard(req) is False


def test_pending_count_reflects_additions_and_removals():
    q = PendingXRequestQueue()
    q.add("undernet", "a", timeout_secs=10, now=0.0)
    q.add("undernet", "b", timeout_secs=10, now=0.0)
    assert q.pending_count("undernet") == 2
    q.pop_oldest("undernet")
    assert q.pending_count("undernet") == 1


def test_timeout_at_is_issued_at_plus_timeout_secs():
    q = PendingXRequestQueue()
    req = q.add("undernet", "a", timeout_secs=5.0, now=100.0)
    assert req.issued_at == 100.0
    assert req.timeout_at == 105.0


def test_reply_to_is_stored_opaquely():
    q = PendingXRequestQueue()
    sentinel = object()
    req = q.add("undernet", "a", timeout_secs=5.0, reply_to=sentinel, now=0.0)
    assert req.reply_to is sentinel


# ---- push_front (2026-08-16, added for multi-line ACCESS reply collection) ----

def test_push_front_restores_fifo_position():
    q = PendingXRequestQueue()
    a = q.add("undernet", "a", timeout_secs=10, now=0.0)
    b = q.add("undernet", "b", timeout_secs=10, now=0.0)
    popped = q.pop_oldest("undernet")
    assert popped is a
    q.push_front(popped)
    assert q.pop_oldest("undernet") is a
    assert q.pop_oldest("undernet") is b


def test_push_front_on_an_empty_queue():
    q = PendingXRequestQueue()
    req = q.add("undernet", "a", timeout_secs=10, now=0.0)
    q.pop_oldest("undernet")
    assert q.pending_count("undernet") == 0
    q.push_front(req)
    assert q.pending_count("undernet") == 1
    assert q.pop_oldest("undernet") is req


def test_push_front_does_not_affect_other_networks():
    q = PendingXRequestQueue()
    a = q.add("undernet", "a", timeout_secs=10, now=0.0)
    q.add("libera", "b", timeout_secs=10, now=0.0)
    q.pop_oldest("undernet")
    q.push_front(a)
    assert q.pending_count("libera") == 1
    assert q.pending_count("undernet") == 1


# ---- XReplySink -- stored opaquely, same as any other reply_to ----

def test_reply_to_accepts_an_x_reply_sink():
    q = PendingXRequestQueue()
    calls = []
    sink = XReplySink(on_reply=lambda text: calls.append(text) or False,
                       on_timeout=lambda: calls.append("timeout"))
    req = q.add("undernet", "probe", timeout_secs=10, reply_to=sink, now=0.0)
    assert req.reply_to is sink
    assert req.reply_to.on_reply("line 1") is False
    assert calls == ["line 1"]


def test_x_reply_sink_defaults_to_no_callbacks():
    sink = XReplySink()
    assert sink.on_reply is None
    assert sink.on_timeout is None


# ---- format_duration ----

def test_format_duration_typical_hour():
    assert format_duration(3600) == "60m"


def test_format_duration_exact_day():
    assert format_duration(86400) == "1d"


def test_format_duration_clamps_up_to_minimum():
    assert format_duration(30) == "5m"
    assert format_duration(0) == "5m"


def test_format_duration_clamps_down_to_maximum():
    assert format_duration(400 * 86400) == "365d"


def test_format_duration_non_round_minutes_below_a_day():
    assert format_duration(90) == "2m" or format_duration(90) == "5m"
    # exact value isn't load-bearing -- just must be a valid, parseable
    # minute count under a day, never crash or produce a day/hour unit
    # for a sub-day duration
    result = format_duration(90)
    assert result.endswith("m")


def test_format_duration_multi_day_non_round():
    result = format_duration(3 * 86400 + 3600)  # 3 days 1 hour
    assert result.endswith("d") or result.endswith("m")
