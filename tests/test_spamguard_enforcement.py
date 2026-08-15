"""Mirrors tests/test_enforcement.py's approach for Shild's own
enforcement.py -- plugins/SpamGuard/enforcement.py is a deliberate
near-copy (see its module docstring for why it's not a shared import),
so these tests are a near-copy too, proving the duplicated module
actually behaves identically.
"""
from plugins.SpamGuard import enforcement


class FakeChannelState:
    def __init__(self, ops):
        self.ops = set(ops)


class FakeState:
    def __init__(self, channels):
        self.channels = channels  # dict[str, FakeChannelState]


class FakeIrc:
    """No real IRC/network needed -- enforcement.py only ever touches
    irc.state.channels[...].ops, irc.nick, and irc.queueMsg."""

    def __init__(self, nick, channels):
        self.nick = nick
        self.state = FakeState(channels)
        self.queued = []

    def queueMsg(self, msg):
        self.queued.append(msg)


def test_is_opped_true_when_bot_in_ops_set():
    irc = FakeIrc("shild", {"#windrop": FakeChannelState(ops=["shild", "otherop"])})
    assert enforcement.is_opped(irc, "#windrop") is True


def test_is_opped_false_when_not_in_ops_set():
    irc = FakeIrc("shild", {"#windrop": FakeChannelState(ops=["otherop"])})
    assert enforcement.is_opped(irc, "#windrop") is False


def test_is_opped_false_when_channel_unknown():
    irc = FakeIrc("shild", {})
    assert enforcement.is_opped(irc, "#nope") is False


def test_ban_mask_is_host_based_for_content_matches():
    assert enforcement.ban_mask("content", "primaryocelo", "~ocelo", "192.0.2.1") \
        == "*!*@192.0.2.1"


def test_ban_mask_is_host_based_for_realname_matches():
    # realname isn't part of an IRC ban mask at all -- no mask field to
    # target, so this falls back to host, same as content.
    assert enforcement.ban_mask("realname", "newuser", "~x", "192.0.2.1") \
        == "*!*@192.0.2.1"


def test_ban_mask_is_ident_based_for_ident_matches():
    # The whole point of an ident-based rule is to catch the SAME ident
    # reconnecting from a different host -- must NOT be host-based.
    assert enforcement.ban_mask("ident", "spammer", "~badident", "192.0.2.1") \
        == "*!~badident@*"


def test_ban_mask_ident_field_falls_back_to_host_if_ident_somehow_empty():
    assert enforcement.ban_mask("ident", "spammer", "", "192.0.2.1") == "*!*@192.0.2.1"


def test_ban_mask_is_nick_based_for_nick_matches():
    # A known-bad literal nick (e.g. a bot's fixed default) -- bans by
    # nick regardless of ident/host.
    assert enforcement.ban_mask("nick", "badbot", "~x", "192.0.2.1") == "badbot!*@*"


def test_ban_mask_nick_field_falls_back_to_host_if_nick_somehow_empty():
    assert enforcement.ban_mask("nick", "", "~x", "192.0.2.1") == "*!*@192.0.2.1"


def test_enforce_ban_queues_ban_then_kick_in_order():
    irc = FakeIrc("shild", {"#windrop": FakeChannelState(ops=["shild"])})
    mask = enforcement.enforce_ban(irc, "#windrop", "primaryocelo", "*!*@192.0.2.1",
                                    "SpamGuard: Czura")

    assert mask == "*!*@192.0.2.1"
    assert len(irc.queued) == 2

    ban_msg, kick_msg = irc.queued
    assert ban_msg.command == "MODE"
    assert ban_msg.args == ("#windrop", "+b", "*!*@192.0.2.1")
    assert kick_msg.command == "KICK"
    assert kick_msg.args == ("#windrop", "primaryocelo", "SpamGuard: Czura")


def test_enforce_ban_uses_the_mask_it_is_given_verbatim():
    # No recomputation from host inside enforce_ban -- the caller
    # (plugin.py) already decided the mask via ban_mask() before calling.
    irc = FakeIrc("shild", {"#windrop": FakeChannelState(ops=["shild"])})
    mask = enforcement.enforce_ban(irc, "#windrop", "spammer", "*!badident@*", "x")

    assert mask == "*!badident@*"
    assert irc.queued[0].args == ("#windrop", "+b", "*!badident@*")


def test_unban_queues_mode_minus_b():
    irc = FakeIrc("shild", {})
    enforcement.unban(irc, "#windrop", "*!*@192.0.2.1")
    assert len(irc.queued) == 1
    assert irc.queued[0].command == "MODE"
    assert irc.queued[0].args == ("#windrop", "-b", "*!*@192.0.2.1")


def test_enforce_ban_does_not_check_op_status_itself():
    """Pure 'do the mechanics' function -- gating (is_opped/kill switch)
    is plugin.py's job, checked before ever calling this."""
    irc = FakeIrc("shild", {"#windrop": FakeChannelState(ops=[])})  # NOT opped
    enforcement.enforce_ban(irc, "#windrop", "primaryocelo", "*!*@192.0.2.1", "x")
    assert len(irc.queued) == 2  # still queues -- caller's job to have checked first
