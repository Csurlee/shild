"""Pure logic for the X-command passthrough commands (xban/xkick/xop/...)
added to plugins/UndernetX/plugin.py, plus the reply-correlation queue
those commands use. No supybot import -- unit-testable without the
plugin harness, same "pure module + thin supybot-facing plugin.py" split
used throughout this repo (Shild/SpamGuard's enforcement.py, SpamGuard's
matcher.py/terms.py, Weather's entire pure-module set).

Building the raw command TEXT sent to X is kept separate from actually
sending it (plugin.py's job, via irc.sendMsg/queueMsg) so the exact
string this bot sends can be pinned down in a test without a live
network connection.

Command syntax is taken from https://www.undernet.org/docs/x-commands-english
(2026-08-14). BAN's fourth argument was originally guessed from that
page as "the minimum access level EXEMPT from the ban" -- CONFIRMED
WRONG live 2026-08-17 via `/msg X help ban`. It's actually a ban
*severity* level ("banlevel"), 1 to the caller's own X access level:
1-74 only blocks +o; 75-500 removes the target from the channel
entirely (X auto-kicks anyone present who matches a 75+ ban). See
config.py's commands.defaultBanAccess docstring for the full incident
this correction is based on (a real X-routed ban silently failing
outright with the old default of 0, which X flatly rejects).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional


def _split_targets(text: str) -> list:
    """X accepts comma-delimited lists of nicks/hostmasks for several
    commands; this repo's own command args are space-separated (the
    normal Limnoria convention) -- normalize either into a clean list.
    """
    parts = text.replace(",", " ").split()
    return [p for p in parts if p]


def build_ban(channel: str, target: str, duration: str = "0d",
              access: int = 75, reason: str = "") -> str:
    """BAN <#channel> <nick!ident@host> <duration> <banlevel> [reason]
    duration: "0d" is permanent; X accepts values from "5m" to "365d".
    access (really a ban SEVERITY level, 1 to the caller's own X access
    level): 1-74 only blocks +o; 75-500 removes the target from the
    channel entirely, auto-kicking anyone present who matches. 0 (the
    old default here) is flatly rejected by X -- confirmed live
    2026-08-17, see module docstring.
    """
    parts = ["BAN", channel, target, duration, str(access)]
    if reason:
        parts.append(reason)
    return " ".join(parts)


def build_unban(channel: str, target: str) -> str:
    return f"UNBAN {channel} {target}"


def build_kick(channel: str, target: str, reason: str = "") -> str:
    parts = ["KICK", channel, target]
    if reason:
        parts.append(reason)
    return " ".join(parts)


def _build_multi_target(cmd: str, channel: str, targets: str) -> str:
    nicks = _split_targets(targets)
    return " ".join([cmd, channel] + nicks)


def build_op(channel: str, nicks: str) -> str:
    return _build_multi_target("OP", channel, nicks)


def build_deop(channel: str, nicks: str) -> str:
    return _build_multi_target("DEOP", channel, nicks)


def build_voice(channel: str, nicks: str) -> str:
    return _build_multi_target("VOICE", channel, nicks)


def build_devoice(channel: str, nicks: str) -> str:
    return _build_multi_target("DEVOICE", channel, nicks)


def build_invite(channel: str) -> str:
    return f"INVITE {channel}"


def build_access(channel: str, target: str) -> str:
    return f"ACCESS {channel} {target}"


def format_duration(secs: int) -> str:
    """Converts a plain seconds count (e.g. protection.banDurationSecs)
    into X's own BAN duration argument -- X accepts "5m" through "365d"
    (2026-08-14, see build_ban's docstring). Picks the coarsest unit
    that doesn't lose more than a minute of precision, clamping at both
    ends rather than ever producing a value X would reject: below 5
    minutes clamps up to "5m", above 365 days clamps down to "365d".
    """
    minutes = max(1, round(secs / 60))
    if minutes < 5:
        return "5m"
    if minutes % 1440 == 0 and minutes // 1440 <= 365:
        return f"{minutes // 1440}d"
    if minutes <= 1440:
        return f"{minutes}m"
    days = minutes // 1440
    if days >= 365:
        return "365d"
    return f"{days}d"


@dataclass
class XReplySink:
    """What plugin.py stashes as a PendingXRequest's `reply_to` for any
    caller that wants to inspect the raw reply text programmatically
    instead of just relaying it to a channel (2026-08-16, added for the
    X-capability probe and the silent enforcement send path). The queue
    itself still never inspects `reply_to` -- see PendingXRequest's own
    docstring -- this is purely a convention plugin.py's _handle_x_reply
    understands.

    on_reply(text) -> bool: called once per NOTICE correlated to this
        request. Return True to indicate MORE lines are expected (the
        request is re-armed via PendingXRequestQueue.push_front, same
        timeout deadline); return False or None to indicate this reply
        is complete. Needed because X's ACCESS reply is multi-line
        (header/rows/terminator) and the existing one-NOTICE-consumes-
        one-request model can't represent that on its own.
    on_timeout(): called if the deadline elapses before on_reply ever
        returns a non-True result. For a multi-line collector this is
        the NORMAL "the reply window closed" finish, not necessarily an
        error -- the caller decides what to do with whatever was
        collected so far.
    """
    on_reply: Optional[object] = None
    on_timeout: Optional[object] = None


@dataclass
class PendingXRequest:
    network: str
    description: str
    issued_at: float
    timeout_at: float
    # Opaque -- plugin.py's own (irc, msg) tuple or callback, and the
    # scheduled timeout event's name (so it can be cancelled on an early
    # reply). Never inspected here; this module doesn't know or care
    # what a "reply" even does, only how to track that one is expected.
    reply_to: object = None
    timeout_event_name: Optional[str] = None


class PendingXRequestQueue:
    """FIFO, per-network. X's NOTICE replies carry no request id at all,
    so correlation is necessarily best-effort: the next NOTICE from X on
    a given network is assumed to answer the OLDEST still-pending
    request on that same network. Two commands fired back-to-back before
    either replies could have their replies swapped -- acceptable for an
    admin-invoked, low-frequency command, not something worth building
    heavier machinery for (there is no existing request/response-over-
    IRC pattern anywhere in this repo to build on -- this is genuinely
    new machinery, kept as simple as the guarantee it can actually make).
    """

    def __init__(self):
        self._queues: dict = {}

    def add(self, network: str, description: str, timeout_secs: float,
            reply_to: object = None, now: Optional[float] = None) -> PendingXRequest:
        now = now if now is not None else time.time()
        req = PendingXRequest(
            network=network, description=description,
            issued_at=now, timeout_at=now + timeout_secs, reply_to=reply_to,
        )
        self._queues.setdefault(network, []).append(req)
        return req

    def pop_oldest(self, network: str) -> Optional[PendingXRequest]:
        q = self._queues.get(network)
        if not q:
            return None
        return q.pop(0)

    def push_front(self, req: PendingXRequest) -> None:
        """Re-inserts a request at the FRONT of its network's queue --
        used when a request's XReplySink.on_reply says "I need more
        lines" (2026-08-16): the request was already popped by
        pop_oldest to correlate the NOTICE just received, and must go
        back to being the NEXT one correlated (not the last), so a
        multi-line reply's second/third NOTICE doesn't get matched
        against some other, unrelated pending request instead.
        """
        self._queues.setdefault(req.network, []).insert(0, req)

    def discard(self, req: PendingXRequest) -> bool:
        """Removes a specific request (used when its timeout fires
        before a reply arrived) -- returns False if it was already
        popped by a reply in the meantime, so the caller can tell a
        genuine timeout from a race it lost.
        """
        q = self._queues.get(req.network)
        if q and req in q:
            q.remove(req)
            return True
        return False

    def pending_count(self, network: str) -> int:
        return len(self._queues.get(network, []))

    def all_requests(self) -> list:
        """Every still-pending request across every network -- used for
        cleanup (e.g. cancelling scheduled timeout events) when the
        owning plugin is unloaded, not part of normal request flow.
        """
        result = []
        for reqs in self._queues.values():
            result.extend(reqs)
        return result
