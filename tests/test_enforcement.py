from plugins.Shild import enforcement


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
    irc = FakeIrc("shildpy", {"#windrop": FakeChannelState(ops=["shildpy", "otherop"])})
    assert enforcement.is_opped(irc, "#windrop") is True


def test_is_opped_false_when_not_in_ops_set():
    irc = FakeIrc("shildpy", {"#windrop": FakeChannelState(ops=["otherop"])})
    assert enforcement.is_opped(irc, "#windrop") is False


def test_is_opped_false_when_channel_unknown():
    irc = FakeIrc("shildpy", {})
    assert enforcement.is_opped(irc, "#nope") is False


def test_ban_mask_is_host_based():
    assert enforcement.ban_mask("203.0.113.9") == "*!*@203.0.113.9"


def test_enforce_ban_queues_ban_then_kick_in_order():
    irc = FakeIrc("shildpy", {"#windrop": FakeChannelState(ops=["shildpy"])})
    mask = enforcement.enforce_ban(irc, "#windrop", "baduser", "203.0.113.9", "corroborated bad host")

    assert mask == "*!*@203.0.113.9"
    assert len(irc.queued) == 2

    ban_msg, kick_msg = irc.queued
    assert ban_msg.command == "MODE"
    assert ban_msg.args == ("#windrop", "+b", "*!*@203.0.113.9")
    assert kick_msg.command == "KICK"
    assert kick_msg.args == ("#windrop", "baduser", "corroborated bad host")


def test_unban_queues_mode_minus_b():
    irc = FakeIrc("shildpy", {})
    enforcement.unban(irc, "#windrop", "*!*@203.0.113.9")
    assert len(irc.queued) == 1
    assert irc.queued[0].command == "MODE"
    assert irc.queued[0].args == ("#windrop", "-b", "*!*@203.0.113.9")


def test_enforce_ban_does_not_check_op_status_itself():
    """enforce_ban is a pure 'do the mechanics' function -- it has no
    opinion on whether it *should* be called. That gating is plugin.py's
    job (is_opped() + kill switch checked there, before ever calling
    this). Confirms enforce_ban acts even when the bot has no op --
    proving the safety property lives in the caller, not here.
    """
    irc = FakeIrc("shildpy", {"#windrop": FakeChannelState(ops=[])})  # NOT opped
    enforcement.enforce_ban(irc, "#windrop", "baduser", "203.0.113.9", "x")
    assert len(irc.queued) == 2  # still queues -- caller's job to have checked first
