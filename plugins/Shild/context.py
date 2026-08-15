"""Per-(network, channel) state: recent event log (for building LLM
context strings) and per-host join/cross-channel tracking, replacing
::shild::chan_log / ::shild::host_tracker / ::shild::global_log from the
Tcl codebase.

The one entry point that matters architecturally is snapshot(): it MUST
be called before any evaluation (classifier/Ollama) happens for an
event, and its result passed by value through the whole decision
pipeline. This is what makes the old system's in_global_bad-style leak
(a feature set by the action taken on the same event it was recorded
for) structurally impossible here, rather than just a discipline/review
concern -- nothing can mutate tracked state and have that mutation feed
back into the SAME event's features, because snapshot() is a pure read
taken up front, and nothing about "would this event be acted on" is
knowable yet at the point it's called.

Also fixes a real bug in the Tcl original: host_context there matched
via `[string match "*$host*" $detail]`, a plain substring check against
free-text detail, so "1.2.3.4" would match "11.2.3.45". Here, host
identity is tracked as its own field, not inferred from substring
matching against a rendered log line.

Also holds the nick->(ident,host) identity cache used to observe kicks
by others (plugin.py's doKick): Limnoria's IrcState.addMsg processes a
KICK and removes the target from the channel roster BEFORE callbacks
fire (confirmed against irclib.py's feedMsg -- state update happens,
then callbacks), so `irc.state.nickToHostmask()` is already stale by the
time doKick runs. This is the same class of bug the Tcl original's
`on_quit` had (looked up the user's channel via `onchan` *after* they'd
already quit) -- fixed the same way: capture identity when we last saw
it ourselves (every join/message already gives us nick+ident+host),
never look it up after the fact.
"""
from __future__ import annotations

import datetime
import threading
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

ChanKey = Tuple[str, str]  # (network, channel)
NickKey = Tuple[str, str]  # (network, nick.lower())


@dataclass
class ContextSnapshot:
    join_rate: float
    cross_chan_count: int
    account_present: bool
    channel_context: str
    host_context: str


@dataclass
class _ChannelState:
    # (ts, event_type, nick, host, detail)
    log: Deque[tuple] = field(default_factory=lambda: deque(maxlen=150))


def _fmt_ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


class ContextStore:
    """One instance per Shild plugin instance (shared across all
    connected networks -- see plugin.py). Every method that reads or
    writes per-channel/per-host state takes `network` explicitly, since
    channel names aren't unique across networks (Libera's #help isn't
    Undernet's #help).
    """

    def __init__(self, join_window_secs: float = 10.0, global_log_max: int = 300,
                 max_tracked_nicks: int = 5000):
        self._chan: Dict[ChanKey, _ChannelState] = defaultdict(_ChannelState)
        self._host_joins: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._host_channels: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        # (ts, network, channel, event_type, nick, host, detail)
        self._global_log: Deque[tuple] = deque(maxlen=global_log_max)
        self.join_window_secs = join_window_secs
        # LRU-bounded so long uptimes (the 72h+ target) don't grow this
        # unboundedly -- see module docstring for why this exists at all.
        self._nick_identity: "OrderedDict[NickKey, Tuple[str, str]]" = OrderedDict()
        self.max_tracked_nicks = max_tracked_nicks
        # Every read/write of the state above goes through this lock.
        # Originally single-threaded (IRC main thread only), but
        # WebPanel's HTTP server thread now reads this state too (see
        # plugins/WebPanel's overview/scans pages) -- iterating a deque
        # while another thread appends to it raises
        # `RuntimeError: deque mutated during iteration`, and the dicts
        # above aren't safe against concurrent read+write either.
        # Contention is negligible (microsecond-scale critical sections,
        # IRC thread vs. at most one HTTP thread) so a plain RLock (not
        # per-key locking) is deliberately simple here. This must not
        # change snapshot()'s documented semantics -- see module
        # docstring -- it only serializes access to the same state.
        self._lock = threading.RLock()

    def record_event(self, network: str, channel: str, event_type: str,
                      nick: str, host: str = "", detail: str = "",
                      ts: Optional[float] = None) -> None:
        import time
        ts = ts if ts is not None else time.time()
        with self._lock:
            self._chan[(network, channel)].log.append((ts, event_type, nick, host, detail))
            self._global_log.append((ts, network, channel, event_type, nick, host, detail))

    def snapshot(self, network: str, channel: str, nick: str, ident: str,
                 host: str, account: Optional[str] = None,
                 ts: Optional[float] = None) -> ContextSnapshot:
        """Pure-ish read: computes the snapshot from state as of *before*
        this call, then records the join itself so future snapshots see
        it. Must be called before any decision logic runs for this event.
        """
        import time
        now = ts if ts is not None else time.time()
        with self._lock:
            self._note_identity(network, nick, ident, host)
            cutoff = now - self.join_window_secs

            joins = self._host_joins[(network, host)]
            while joins and joins[0] < cutoff:
                joins.pop(0)
            join_rate = float(len(joins))
            joins.append(now)

            chans = self._host_channels[(network, host)]
            cross_chan_count = len(chans)
            chans.add(channel)

            chan_state = self._chan[(network, channel)]
            channel_context = "\n".join(
                f"{_fmt_ts(e_ts)} {etype} {n} {d}".rstrip()
                for e_ts, etype, n, _h, d in list(chan_state.log)[-10:]
            )
            host_context = "\n".join(
                f"{_fmt_ts(e_ts)} {c} {etype} {n} {d}".rstrip()
                for e_ts, net, c, etype, n, h, d in self._global_log
                if net == network and h == host
            )

        return ContextSnapshot(
            join_rate=join_rate,
            cross_chan_count=cross_chan_count,
            account_present=bool(account),
            channel_context=channel_context,
            host_context=host_context[-2000:],  # defensive cap for prompt size
        )

    def _note_identity(self, network: str, nick: str, ident: str, host: str) -> None:
        # Caller (snapshot) already holds self._lock.
        key = (network, nick.lower())
        self._nick_identity[key] = (ident, host)
        self._nick_identity.move_to_end(key)
        while len(self._nick_identity) > self.max_tracked_nicks:
            self._nick_identity.popitem(last=False)

    def identity_for_nick(self, network: str, nick: str) -> Optional[Tuple[str, str]]:
        """Best-effort (ident, host) for a nick we've seen join/speak on
        this network, or None if we never saw them. Used by doKick, which
        cannot rely on `irc.state` for the just-kicked nick -- see module
        docstring.
        """
        with self._lock:
            return self._nick_identity.get((network, nick.lower()))

    # ---- read-only accessors for WebPanel (or anything else off the IRC
    # thread) -- all return freshly-copied lists, never the live deque/
    # dict, and never touch the filesystem or the network. ----

    def recent_global_events(self, limit: int = 50, network: Optional[str] = None,
                              channel: Optional[str] = None) -> List[tuple]:
        """Newest-first copy of the cross-network event ring, optionally
        filtered by network and/or channel. `limit` bounds the copy size
        -- this walks the whole (bounded, <=global_log_max) deque either
        way, but never returns more than asked for."""
        with self._lock:
            events = list(self._global_log)
        if network is not None:
            events = [e for e in events if e[1] == network]
        if channel is not None:
            events = [e for e in events if e[2] == channel]
        events.reverse()
        return events[:limit]

    def recent_channel_events(self, network: str, channel: str,
                               limit: int = 50) -> List[tuple]:
        """Newest-first copy of one channel's own event log. Uses
        `.get()`, NEVER `self._chan[key]` -- `_chan` is a defaultdict,
        so a `[]` lookup for a channel name that only exists because a
        browser typed it into a URL would silently create (and leak)
        state for it forever. A channel this store has never seen just
        returns an empty list."""
        with self._lock:
            state = self._chan.get((network, channel))
            events = list(state.log) if state is not None else []
        events.reverse()
        return events[:limit]

    def observed_context(self, network: str, host: str,
                          ts: Optional[float] = None) -> Tuple[float, int]:
        """Read-only `(join_rate, cross_chan_count)` for a host, WITHOUT
        recording anything. `snapshot()` deliberately mutates -- it
        appends the current join and channel before returning, because a
        real join genuinely is another data point. A manual `!shildcheck`
        is not: counting it would inflate the very join_rate feature the
        check is meant to read, and would do so differently depending on
        how many times an operator ran the command.

        Uses `.get()` for the same defaultdict reason as
        `recent_channel_events` above -- an operator can type any host
        into the command, and a `[]` lookup would create permanent state
        for every typo. A host this store has never seen returns
        `(0.0, 0)`.
        """
        import time
        now = ts if ts is not None else time.time()
        cutoff = now - self.join_window_secs
        with self._lock:
            joins = self._host_joins.get((network, host))
            join_rate = float(len([t for t in joins if t >= cutoff])) if joins else 0.0
            chans = self._host_channels.get((network, host))
            cross_chan_count = len(chans) if chans else 0
        return join_rate, cross_chan_count

    def tracked_channels(self) -> List[ChanKey]:
        """(network, channel) pairs this store currently holds any
        recent-event state for."""
        with self._lock:
            return list(self._chan.keys())

    def tracked_nick_count(self) -> int:
        with self._lock:
            return len(self._nick_identity)
