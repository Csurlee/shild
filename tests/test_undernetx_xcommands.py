"""Pure unit tests for plugins/UndernetX/xcommands.py -- no supybot
import.
"""
from plugins.UndernetX.xcommands import (
    PendingXRequestQueue,
    build_access,
    build_ban,
    build_deop,
    build_devoice,
    build_invite,
    build_kick,
    build_op,
    build_unban,
    build_voice,
)


def test_build_ban_default_duration_and_access():
    assert build_ban("#windrop", "*!*@1.2.3.4") == "BAN #windrop *!*@1.2.3.4 0d 0"


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
