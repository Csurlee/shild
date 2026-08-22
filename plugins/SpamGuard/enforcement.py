"""The only module in this plugin allowed to construct a real KICK, BAN,
or UNBAN message. Every other module here -- including plugin.py's whole
gate chain -- only ever computes a *decision* (matched, within the join
window, not exempt, ...); this module is where that decision, if it
clears is_opped()/the kill switch, becomes a real IRC action.

Deliberately a near-copy of plugins/Shild/enforcement.py rather than an
import of it: cross-plugin imports are fragile in this codebase (see the
`from Shild.test import ...` import-order failure documented in
CLAUDE.md/memory, fixed by inlining rather than sharing). Duplicating
these ~40 lines keeps each plugin's "the one auditable place that builds
a real kick/ban" invariant intact and independently greppable:

    grep -rEn "ircmsgs\\.(kick|ban|mode)\\(" plugins/SpamGuard/

is expected to return exactly the lines in this file, nowhere else.

This module never decides *whether* to act -- that gating (join window,
exemptions, op status, SpamGuard's own kill switch, separate from
Shild's) lives in plugin.py. Functions here are pure "given a decision to
enforce, do the IRC mechanics."

2026-08-16: plugin.py's gate chain gained a SECOND, explicitly gated
route to a real kick/ban when the bot lacks op -- routing through
Undernet's X service via plugins/UndernetX (`irc.getCallback("UndernetX")`,
never a Python import), mirroring the identical addition to Shild's own
enforcement.py the same day. That path builds plain `ircmsgs.privmsg()`
calls inside UndernetX's own plugin.py, entirely out of scope for the
`ircmsgs.(kick|ban|mode)(` grep above, and carries its own layered gating
(a per-channel opt-in, a global arm switch, and a live-verified capability
probe -- see plugins/UndernetX/xprobe.py) on top of the same kill switch
this module's callers already require. This module's own invariant --
the only place a real `ircmsgs.kick/ban/mode()` call is constructed --
is unaffected.
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


def ban_mask(field: str, nick: str, ident: str, host: str) -> str:
    """The ban mask targets whichever identity component actually
    triggered the match (2026-08-13, found via a live ident-match test):
    an ident-based rule exists to catch that SAME ident reconnecting from
    a different IP -- e.g. a known bad bot that always connects with the
    same forged ident from a rotating pool of hosts. Banning only the
    host it happened to test from would let it straight back in from
    another connection while banning an unrelated host for no reason.
    Same reasoning for a nick match, added the same day per user request.

    `field == "ident"` -> `*!<ident>@*` (the exact ident string observed
    on the connection, tilde and all if present -- not just the matched
    term text, which may only be a substring of it).

    `field == "nick"` -> `<nick>!*@*`. Weaker than an ident/host mask in
    one real sense: nicks are the most freely reusable of the three
    (no identd/hosting-provider friction at all, and without NickServ
    registration+enforcement on this network, literally anyone can pick
    up a banned nick next). Still useful for a known-bad literal nick
    (a bot's fixed default nick), just don't expect it to survive a
    determined nick change the way an ident/host mask would.

    Content matches have no identity component of their own (the match is
    about message text, not who sent it), and realname isn't part of an
    IRC ban mask at all -- masks are strictly `nick!ident@host`, with no
    realname slot -- so both of those, like every field before this
    function existed, fall back to the host-based mask.

    2026-08-22: that host-based fallback is itself now ident-aware, per a
    real incident where a temporary host ban expired and the same spam
    host simply rejoined under a new nick. An ident beginning with `~`
    means the ircd could not verify it against a real identd response on
    that connection -- the overwhelming majority of spam bots connect
    this way, since running a real ident server is extra effort a
    disposable bot has no reason to bother with. Narrowing the mask to
    `*!~*@host` in that case means it can ONLY ever match another
    unverified-ident connection from that host -- a later, unrelated
    person connecting from the same IP/host with a real ident server
    running is never caught by it. A verified ident (no `~`) is treated
    as real evidence this IS a person, not a bot -- ban them normally
    with the full `*!*@host` mask, same as before this change. See
    plugin.py's `hostbans.py`-backed persisted-reban feature, which reuses
    this exact same function (and therefore this exact same ident check)
    for a rejoin days or weeks after the original, now-expired ban.
    """
    if field == "ident" and ident:
        return f"*!{ident}@*"
    if field == "nick" and nick:
        return f"{nick}!*@*"
    if (ident or "").startswith("~"):
        return f"*!~*@{host}"
    return f"*!*@{host}"


def enforce_ban(irc, channel: str, nick: str, mask: str, reason: str) -> str:
    """Queues a real MODE +b then KICK against `nick` in `channel`, using
    the already-decided `mask` (see ban_mask()). Returns `mask` unchanged,
    so the caller (plugin.py) can schedule the matching auto-unban against
    the exact same mask it just used. Never called directly by
    matching/gating logic -- only by plugin.py's enforcement gate, after
    it has already confirmed is_opped() and its own kill switch being off.
    """
    irc.queueMsg(ircmsgs.ban(channel, mask))
    irc.queueMsg(ircmsgs.kick(channel, nick, reason))
    return mask


def unban(irc, channel: str, mask: str) -> None:
    """Lifts a previously-set ban. Called by the scheduled auto-unban
    callback (plugin.py) once protection.banDurationSecs has elapsed.
    """
    irc.queueMsg(ircmsgs.unban(channel, mask))
