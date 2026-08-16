"""The only module in this project allowed to construct a real KICK, BAN,
or UNBAN message. Every other module -- including plugin.py's entire
decision pipeline (classifier, Ollama, evidence gate) -- only ever
computes a *decision*; this module is where that decision, if it clears
`is_opped()` and the kill switch, becomes a real IRC action.

Kept deliberately small and separate so the one place the project's
long-standing "zero moderation capability" invariant is lifted stays easy
to audit in isolation: `grep -rEn "ircmsgs\\.(kick|ban|mode)\\(" plugins/Shild/`
is expected to return exactly the lines in this file, nowhere else.

This module never decides *whether* to act -- that gating (op status,
the global kill switch, which fused actions warrant enforcement) lives in
plugin.py's `_maybe_enforce()`. Functions here are pure "given a decision
to enforce, do the IRC mechanics."

2026-08-16: `_maybe_enforce()` gained a SECOND, explicitly gated route to
a real kick/ban when the bot lacks op -- routing through Undernet's X
service via plugins/UndernetX (`irc.getCallback("UndernetX")`, never a
Python import). That path builds plain `ircmsgs.privmsg()` calls inside
UndernetX's own `plugin.py`, entirely out of scope for the
`ircmsgs.(kick|ban|mode)(` grep above, and is subject to its own layered
gating (a per-channel opt-in, a global arm switch, and a live-verified
capability probe -- see plugins/UndernetX/xprobe.py) on top of the same
kill switch this module's callers already require. This module's own
invariant -- the only place a real `ircmsgs.kick/ban/mode()` call is
constructed -- is unaffected; the X path is a different mechanism
entirely, not a second way to build the same kind of message.
"""
from __future__ import annotations

from supybot import ircmsgs


def is_opped(irc, channel: str) -> bool:
    """Whether the bot currently holds op in `channel`, per Limnoria's own
    IrcState (`irc.state.channels[channel].ops`) -- always current, no
    separate op-tracking state needed. False (never act) if the channel
    isn't in the bot's known state at all, for any reason.
    """
    chan_state = irc.state.channels.get(channel)
    if chan_state is None:
        return False
    return irc.nick in chan_state.ops


def ban_mask(host: str) -> str:
    """A generic host-based ban mask. `*!*@host` bans by host regardless
    of nick/ident -- host-driven evidence (DNSBL/reputation) is what
    actually justifies a ban here, and we have no basis to ban by nick
    alone (nicks are trivially disposable; hosts much less so).
    """
    return f"*!*@{host}"


def enforce_ban(irc, channel: str, nick: str, host: str, reason: str) -> str:
    """Queues a real MODE +b then KICK ("kban", matching the old Eggdrop
    convention) against `nick`/`host` in `channel`. Returns the ban mask
    used, so the caller (plugin.py) can schedule the matching auto-unban
    against the exact same mask. Never called directly by decision logic
    -- only by plugin.py's `_maybe_enforce()`, after it has already
    confirmed `is_opped()` and the kill switch being off.
    """
    mask = ban_mask(host)
    irc.queueMsg(ircmsgs.ban(channel, mask))
    irc.queueMsg(ircmsgs.kick(channel, nick, reason))
    return mask


def unban(irc, channel: str, mask: str) -> None:
    """Lifts a previously-set ban. Called by the scheduled auto-unban
    callback (plugin.py) once `protection.banDurationSecs` has elapsed.
    """
    irc.queueMsg(ircmsgs.unban(channel, mask))
