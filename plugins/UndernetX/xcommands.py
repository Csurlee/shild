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
(2026-08-14) -- BAN's "access" argument in particular is thinly
documented there (it's the minimum access level EXEMPT from the ban, per
X's own convention for this kind of parameter, but this was not
confirmed against a live `/msg X help ban`). Treated as an explicit,
overridable parameter with a conservative default (0 -- exempts no one)
rather than silently guessing a value into the vendored login-only
codepath. Verify against the real network before trusting this for
anything but a manual, supervised command.
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
              access: int = 0, reason: str = "") -> str:
    """BAN <#channel> <nick!ident@host> <duration> <access> [reason]
    duration: "0d" is permanent; X accepts values from "5m" to "365d".
    access: minimum access level exempt from this ban (0 -- everyone is
    subject to it). See module docstring's caveat on this parameter.
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
