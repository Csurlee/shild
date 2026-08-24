"""SpamGuard -- deterministic content-match kick+ban for spam bots that
join a channel and immediately paste a known template message, or that
consistently reuse a bad ident/realname signature.

Motivating example (real, from Undernet #windrop, Armour/idefix already
handles it there by blacklisting the token "Czura"):

    <primaryocelo> Hi Guys! It's Madeleine Czura! Just thought I'd leave
                   my number here in case you're lonely ;) .
    idefix sets mode +b *!~*@192.0.2.1
    idefix kicked primaryocelo (Armour: blacklisted -- Czura (reason:
                   You are not welcome here!) [id: 12])

Every term SpamGuard matches on carries a permanent numeric id (see
terms.py), shown in the kick reason exactly like Armour's own `[id: N]`
convention above -- `spamguard <category> add`/`spamguardsearch`/
`spamguardlist`/`spamguardremove` all key off it.

Deliberately NOT part of Shild: this is an exact-content match against a
known spam signature, not an ML/evidence decision, and Shild's own
protection.killSwitch/enforcement machinery is scoped to its classifier+
evidence pipeline specifically (see plugins/Shild/plugin.py's module
docstring). SpamGuard has its own, independent kill switch
(protection.killSwitch, defaults True/safe) -- flipping one plugin's
switch never arms the other.

Four independent matchers, all sharing the same enforcement gate chain
(_handle_match): message content (words/phrases/patterns, checked on
PRIVMSG within joinWindowSecs of a tracked join), ident (checked at JOIN
itself -- ident is always present, standard IRC, no capability needed),
nick (also checked at JOIN, added 2026-08-13, and re-checked on a NICK
CHANGE, added 2026-08-22 -- see doNick's own docstring), and realname
(also checked at JOIN, but ONLY when the server negotiated the IRCv3
"extended-join" capability -- see doJoin's docstring for the caveat).
ident/nick/realname matches skip the join-window check entirely since
the match IS the join event; content matches still require it. At JOIN,
black is checked first (see below), then nick, then ident, then realname
-- the first hit wins and the others are never checked for that join.

A fifth category, "black" (2026-08-14), is different in kind from the
other four: one stored entry matches against BOTH a joining/present
user's nick AND host (whichever hits), not one specific field, and
`spamguard black add <nick/host>` doesn't just block future joins --
it ALSO immediately sweeps every network the bot is connected to
(_sweep_black_term) for anyone ALREADY sitting in an enabled channel who
matches, kick+banning them right then (subject to the same exemption/
kill-switch/op gates as any other match -- an already-present halfop or
registered user is still exempt). This is the one command in this plugin
that acts on state beyond "the event just received."

"clone_scan" (2026-08-22, see _scan_clones/_scan_clones_all) is also
state-beyond-the-current-event, same family as "black": a periodic AND
on-demand (`spamguardclonescan`) STATELESS snapshot of a channel's
current userlist grouped by host -- cloneScanMaxClones or more distinct
nicks sharing one host right now is acted on, catching slow trickle-in
clones and clones already present before this feature existed, which
raid/groupFlood's own burst-in-a-time-window detection structurally
cannot see. Adapted from the IDEA in BlackTools' `CloneScan` module,
reimplemented independently, nothing vendored (GPLv3). Every member of a
qualifying cluster is acted on (not just one "tipping" member, unlike
raid/groupFlood) since a clone cluster has no innocent members by
construction -- but a cluster where ANY member is exempt is skipped
entirely, since the ban mask is host-scoped and would otherwise also
lock out the exempt member. Suppresses a repeat report of the same
still-present cluster within cloneScanRepeatSuppressSecs (the periodic
sweep only -- `spamguardclonescan` always ignores it).

Four more, non-term, threshold-based message heuristics were added
2026-08-14 (see _check_heuristics, heuristics.py, mojibake.py): flood,
mass nick-highlight, excessive caps, and mojibake/garbled encoding --
adapted from ideas in Libera Chat's own `ozone` network-abuse bot
(github.com/Libera-Chat/ozone), reimplemented independently for this
codebase's conventions rather than copied (mojibake.py's regex table is
the one exception -- vendored verbatim, MIT-licensed, see its own module
docstring). All four funnel through the SAME _handle_match gate chain as
the term-based matchers above, checked only when no content term already
matched, and each is its own per-channel opt-in (default off) since --
unlike a term list, which is implicitly inert until something's added to
it -- a threshold is always "live" the moment the code exists to check
it.

A sixth heuristic, "raid" (2026-08-16, see _check_join_heuristics), is
join-based rather than message-based: raidJoinLimit distinct nicks joining
within raidWindowSecs. Adapted the same "idea, not code" way from the
"grouped flood" concept in progval's AttackProtector plugin
(github.com/progval/Supybot-plugins/tree/master/AttackProtector, 2010-era
Python 2 code, not vendored). Funnels through the same _handle_match gate
chain as everything else -- exemption/killSwitch/op all still apply -- and
enforces against only the ONE joiner who tips the threshold, never the
whole burst, since a legitimate netsplit-reconnect burst of real regulars
can look identical to a coordinated raid at the network level.

A seventh heuristic, "group_flood" (2026-08-22, see _check_heuristics), is
the message-side counterpart to raid: groupFloodMessageLimit DISTINCT
nicks each sending a message in the same channel within
groupFloodWindowSecs, even where every individual nick stays under
floodMessageLimit. Same "grouped flood" idea from progval's
AttackProtector, adapted the same "idea, not code" way, and enforcing
against only the ONE message that tips the count over the limit -- never
the whole burst -- for the same reason raid only acts on the
tipping-point joiner.

An eighth heuristic, "repeat_chars" (2026-08-22, see _check_heuristics),
flags a message where one character repeats repeatCharsMinRun or more
times in a row ("!!!!!!!!!!", "aaaaaaaaaa") -- adapted from the IDEA in
BlackTools' `repetitivechars` Eggdrop/TCL module
(github.com/tclscripts/BlackTools-TCL, GPLv3), reimplemented
independently, nothing vendored.

A new trigger point (2026-08-22, see doQuit/doPart/_handle_leave_match),
NOT a new category: a leaving user's QUIT/PART reason text is checked
against the EXISTING content word/phrase/pattern terms -- adapted from
the IDEA in BlackTools' `antibadquitpart` module, same no-vendoring
treatment. Deliberately, permanently OBSERVE-ONLY: the user is already
gone from irc.state by the time either callback fires, so a match is
logged and relayed (outcome "observed") and NEVER enforced -- see
_handle_leave_match's own docstring for the full reasoning (a guaranteed
no-op kick, the ban/kick coupling in _enforce(), and the netsplit
mass-QUIT hazard).

Every matched message is logged to data/spamguard_actions.jsonl and
relayed (if configured) REGARDLESS of whether it was acted on, tagged
with why (killswitch / not-opped / outside-window / exempt / enforced)
and which field matched -- same "log unconditionally, act conditionally"
philosophy as Shild's shadow mode, and for the same reason: the term
lists can be tuned against real traffic with the kill switch left on the
whole time.

`plugins/SpamGuard/enforcement.py` is the ONLY module allowed to
construct a real KICK/MODE(+b)/UNBAN message -- verify with:

    grep -rEn "ircmsgs\\.(kick|ban|mode)\\(" plugins/SpamGuard/

which is expected to return exactly the lines in enforcement.py, nowhere
else (see that module's docstring).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from supybot import callbacks, conf, ircdb, ircmsgs, ircutils, log, schedule, world
from supybot.commands import wrap, additional
from supybot.commands import any as anyArgs

from shildml.schema import write_jsonl_line

from . import enforcement
from . import heuristics
from . import hostbans
from . import matcher
from . import mojibake
from . import terms as termstore

# Same IRC line-length safety net added to Shild this session --
# irc.queueMsg() with a raw ircmsgs.privmsg() does no length checking at
# all, unlike irc.reply()'s own more-system.
_MAX_LINE = 400

_CATEGORIES = ("word", "ident", "nick", "realname", "pattern", "black")

# 2026-08-14: fixed pseudo-ids for the four message heuristics below --
# these aren't TermStore entries (no user-managed text to add/remove, just
# a threshold), so they don't get a real, persisted, ever-incrementing id
# the way word/phrase/pattern/ident/nick/realname terms do. Negative and
# fixed so they can never collide with a real TermStore id (always a
# positive, sequentially-assigned int -- see terms.py) while still
# satisfying every place that reads term.id/term.text (the kick reason,
# the JSONL log, spamguardstatus).
_HEURISTIC_IDS = {"flood": -1, "hilight": -2, "caps": -3, "mojibake": -4, "raid": -5,
                   "host_history": -6, "group_flood": -7, "clone_scan": -8,
                   "repeat_chars": -9}


def _heuristic_term(category: str, text: str) -> termstore.Term:
    return termstore.Term(id=_HEURISTIC_IDS[category], category=category, text=text,
                           added_by="builtin", added_at=0.0)


class SpamGuard(callbacks.Plugin):
    """Watches for known spam signatures (message content, ident, nick,
    or realname) from a recently-joined user and kick+bans, but only
    where the bot holds real op and its own kill switch is off. Matching/
    logging/relay is always active (regardless of enforcement state) in
    any enabled channel.
    """

    threaded = False

    def __init__(self, irc):
        self.__parent = super(SpamGuard, self)
        self.__parent.__init__(irc)

        # (network, channel, nick) -> join timestamp. Bounded implicitly
        # by _prune_joins() below; unbounded growth would only happen if
        # a channel saw joins faster than joinWindowSecs, which is not a
        # realistic scenario for the channels this is deployed on.
        self._joins: dict[tuple[str, str, str], float] = {}
        # (network, channel, nick) -> recent message timestamps, for the
        # flood heuristic (2026-08-14). Pruned the same way as _joins --
        # see _prune_recent_messages -- and only populated at all while
        # floodEnabled is on somewhere, so an all-heuristics-off
        # deployment (the code default) never allocates anything here.
        self._recent_messages: dict[tuple[str, str, str], list[float]] = {}
        # (network, channel) -> [(join timestamp, nick), ...], for the
        # raid heuristic (2026-08-16). Pruned the same way as
        # _recent_messages -- see _prune_recent_joins -- and only
        # populated at all while raidEnabled is on somewhere.
        self._recent_joins: dict[tuple[str, str], list[tuple[float, str]]] = {}
        # (network, channel) -> [(message timestamp, nick), ...], for the
        # group_flood heuristic (2026-08-22) -- deliberately the SAME
        # shape as _recent_joins above, not _recent_messages': this
        # counts DISTINCT nicks across the whole channel, not one nick's
        # own message rate, so it must not be keyed by nick. Pruned via
        # _prune_recent_group_messages and only populated at all while
        # groupFloodEnabled is on somewhere.
        self._recent_group_messages: dict[tuple[str, str], list[tuple[float, str]]] = {}
        # (network, channel, host) -> last time this clone cluster was
        # reported, for the clone-scan heuristic (2026-08-22). Stamped
        # on REPORT (not just successful enforcement) -- see
        # _scan_clones's own docstring for why. The on-demand
        # spamguardclonescan command always ignores this.
        self._clone_scan_seen: dict[tuple[str, str, str], float] = {}
        self._stats = {"messages": 0, "matches": 0, "enforced": 0}
        self._pending_unbans: dict[str, None] = {}

        self._terms = termstore.TermStore(self.registryValue("termsPath"))
        self._migrate_legacy_registry_terms()

        # 2026-08-22: persisted host/IP ban history -- see hostbans.py's
        # own module docstring. Recording is always on; only the real
        # auto-reban action is gated (hostBanAutoRebanEnabled).
        self._host_bans = hostbans.HostBanStore(self.registryValue("hostBansPath"))
        self._host_ban_prune_event_name = f"spamguard-hostban-prune-{id(self)}"
        schedule.addPeriodicEvent(
            self._prune_host_bans,
            self.registryValue("hostBanPruneIntervalSecs"),
            self._host_ban_prune_event_name,
        )

        self._content_matchers: list[tuple[termstore.Term, object]] = []
        self._matcher_skipped: list[termstore.Term] = []
        self._ident_matchers: list[tuple[termstore.Term, object]] = []
        self._nick_matchers: list[tuple[termstore.Term, object]] = []
        self._realname_matchers: list[tuple[termstore.Term, object]] = []
        self._black_matchers: list[tuple[termstore.Term, object]] = []
        self._rebuild_matchers()

        self._pin_network_values()
        self._pin_event_name = f"spamguardPinNetworkValues-{id(self)}"
        try:
            schedule.removeEvent(self._pin_event_name)
        except KeyError:
            pass
        schedule.addPeriodicEvent(
            self._pin_network_values, 60, self._pin_event_name, now=False)

        self._clone_scan_event_name = f"spamguard-clonescan-{id(self)}"
        try:
            schedule.removeEvent(self._clone_scan_event_name)
        except KeyError:
            pass
        schedule.addPeriodicEvent(
            self._scan_clones_all,
            self.registryValue("cloneScanIntervalSecs"),
            self._clone_scan_event_name,
            now=False,  # a sweep firing inside every test's setUp() would be a mess
        )

    def _pin_network_values(self) -> None:
        """2026-08-22: relayChannel (registerNetworkValue) is only
        persisted through a clean shutdown's registry write-back if it was
        actually READ during this process's run -- see Shild's own
        matching fix (plugin.py) for the full explanation, including WHY
        this must also run on a periodic retry (a single __init__-time
        call isn't enough: getSpecific(network=X) silently falls back to
        the bare value whenever world.getIrc(X) isn't registered yet at
        that exact moment, and Undernet routinely hasn't finished
        connecting by the time this process-wide __init__ runs).
        Force-activates every configured network's relayChannel by
        writing it back to its own current value, so it survives the next
        write-back regardless of whether real relay traffic happens to
        occur first."""
        for network in conf.supybot.networks():
            current = self.registryValue("relayChannel", network=network)
            if current:
                self.setRegistryValue("relayChannel", current, network=network)

    def _migrate_legacy_registry_terms(self) -> None:
        """One-time migration from the old flat config-registry lists
        (words/phrases/patterns/identWords/realnameWords/
        realnamePhrases) into the id-keyed TermStore, added 2026-08-10
        alongside per-term ids. Only runs when the store is completely
        empty (a brand-new deployment, or the first load after this
        change) -- once ANY term exists in the store, it's the sole
        source of truth from then on and this never runs again, even if
        the legacy registry values still have something in them (e.g.
        from a stale bootstrap_runtime.py reseed of SPAMGUARD_WORDS)."""
        if self._terms.all():
            return
        legacy = (
            ("word", self.registryValue("words")),
            ("phrase", self.registryValue("phrases")),
            ("pattern", self.registryValue("patterns")),
            ("ident", self.registryValue("identWords")),
            ("realname_word", self.registryValue("realnameWords")),
            ("realname_phrase", self.registryValue("realnamePhrases")),
        )
        for category, values in legacy:
            for text in values:
                # text.strip(), not just `if text` -- a legacy list whose
                # raw stored value was a single space (confirmed live
                # 2026-08-11: CommaSeparatedListOfStrings.splitter() on a
                # stray " " value returns [" "], one non-empty-but-blank
                # entry) must never migrate into a real term. A
                # whitespace-only "word"/"pattern" would match almost
                # ANY message once compiled -- re.escape(" ") or a raw
                # " " regex both hit virtually every real chat line.
                if text.strip() and self._terms.find_by_text(category, text) is None:
                    self._terms.add(category, text, added_by="migration")

    def die(self):
        for event_name in list(self._pending_unbans):
            try:
                schedule.removeEvent(event_name)
            except KeyError:
                pass
        try:
            schedule.removeEvent(self._host_ban_prune_event_name)
        except KeyError:
            pass
        try:
            schedule.removeEvent(self._pin_event_name)
        except KeyError:
            pass
        try:
            schedule.removeEvent(self._clone_scan_event_name)
        except KeyError:
            pass
        self.__parent.die()

    def _prune_host_bans(self) -> None:
        retention = self.registryValue("hostBanRetentionDays") * 86400
        self._host_bans.prune_expired(now=time.time(), retention_secs=retention)

    # ---- matchers (rebuilt on demand -- see `spamguard <category> add/remove`) ----

    def _rebuild_matchers(self) -> None:
        """Compiles every stored Term into its own (term, regex) pair --
        see matcher.py's module docstring for why per-term rather than
        one combined regex (it's what lets a hit map straight back to
        the id that fired)."""
        def build(categories):
            compiled = []
            skipped = []
            for category in categories:
                for term in self._terms.by_category(category):
                    regex = matcher.compile_term(term.text, is_pattern=(category == "pattern"))
                    if regex is None:
                        skipped.append(term)
                        continue
                    compiled.append((term, regex))
            return compiled, skipped

        self._content_matchers, self._matcher_skipped = build(("word", "phrase", "pattern"))
        for bad in self._matcher_skipped:
            log.warning("SpamGuard: skipping invalid content pattern regex [id:%d]: %r",
                        bad.id, bad.text)

        # No phrase/pattern category for ident or nick -- neither can
        # ever contain a space (RFC 2812), so there's nothing a phrase
        # list would add over words alone.
        self._ident_matchers, _ = build(("ident",))
        self._nick_matchers, _ = build(("nick",))
        self._realname_matchers, _ = build(("realname_word", "realname_phrase"))
        self._black_matchers, _ = build(("black",))

    # ---- helpers ----

    def _enabled(self, irc, channel: str) -> bool:
        return self.registryValue("enabled", channel, irc.network)

    @staticmethod
    def _queue_wrapped(irc, target: str, text: str) -> None:
        for chunk in ircutils.wrap(text, _MAX_LINE):
            irc.queueMsg(ircmsgs.privmsg(target, chunk))

    def _relay(self, irc, text: str) -> None:
        relay_chan = self.registryValue("relayChannel", network=irc.network)
        if not relay_chan:
            return
        try:
            self._queue_wrapped(irc, relay_chan, text)
        except Exception:
            log.exception("SpamGuard: failed to relay match notice")

    def _log(self, *, network, channel, nick, ident, host, term, field: str, outcome: str,
             via: str = "native") -> None:
        record = {
            "schema_version": 2,  # 2026-08-16: added "via" (native op-based
            # MODE+KICK vs. X-routed BAN+KICK -- see _x_fallback/_enforce)
            "source": "limnoria-spamguard",
            "ts": time.time(),
            "network": network,
            "channel": channel,
            "target": {"nick": nick, "ident": ident, "host": host},
            "field": field,
            "term": term.text,
            "term_id": term.id,
            "outcome": outcome,
            "via": via,
        }
        try:
            write_jsonl_line(self.registryValue("logPath"), record)
        except Exception:
            log.exception("SpamGuard: failed to write action log")

    def _prune_joins(self, now: float) -> None:
        window = self.registryValue("joinWindowSecs")
        stale = [key for key, ts in self._joins.items() if now - ts > window]
        for key in stale:
            self._joins.pop(key, None)

    def _prune_recent_messages(self, now: float) -> None:
        window = self.registryValue("floodWindowSecs")
        stale = [key for key, times in self._recent_messages.items()
                 if not times or now - times[-1] > window]
        for key in stale:
            self._recent_messages.pop(key, None)

    def _prune_recent_joins(self, now: float) -> None:
        window = self.registryValue("raidWindowSecs")
        stale = [key for key, events in self._recent_joins.items()
                 if not events or now - events[-1][0] > window]
        for key in stale:
            self._recent_joins.pop(key, None)

    def _prune_recent_group_messages(self, now: float) -> None:
        window = self.registryValue("groupFloodWindowSecs")
        stale = [key for key, events in self._recent_group_messages.items()
                 if not events or now - events[-1][0] > window]
        for key in stale:
            self._recent_group_messages.pop(key, None)

    def _is_exempt(self, irc, channel: str, msg) -> bool:
        """Voice+ in-channel (voiced, halfop, or op -- irclib.py's
        IrcChannelState.isVoicePlus), holding this channel's own ircdb
        'op' capability, or (if exemptRegistered) any recognized
        registered user -- the first two started as the exemption set
        Limnoria's own bundled BadWords plugin uses (originally
        halfop+ only), widened to voice+ 2026-08-22 per explicit user
        request: a channel op vouching for someone with +v is a real,
        deliberate trust signal, same in kind as the halfop+ case, just
        one rung lower. This only ever exempts real ENFORCEMENT --
        _handle_match still logs/relays every match regardless (outcome
        "exempt"), same "log unconditionally, act conditionally"
        discipline as everywhere else in this plugin, so a voiced
        user's matches stay fully observable for tuning."""
        chan_state = irc.state.channels.get(channel)
        if chan_state is not None and chan_state.isVoicePlus(msg.nick):
            return True
        cap = ircdb.makeChannelCapability(channel, "op")
        if ircdb.checkCapability(msg.prefix, cap):
            return True
        if self.registryValue("exemptRegistered"):
            try:
                ircdb.users.getUserId(msg.prefix)
                return True
            except KeyError:
                pass
        return False

    # ---- event hooks ----

    def doJoin(self, irc, msg):
        channel = msg.channel
        if channel is None or msg.nick == irc.nick:
            return
        if not self._enabled(irc, channel):
            return
        now = time.time()
        self._prune_joins(now)
        self._joins[(irc.network, channel, msg.nick)] = now

        nick, ident, host = msg.nick, msg.user, msg.host

        # Persisted host-ban history (2026-08-22) is checked FIRST, ahead
        # of even "black" -- an exact host we've already convicted via a
        # real host-based enforcement needs no string matching at all.
        # Off by default (hostBanAutoRebanEnabled) -- recording into the
        # store still always happens in _enforce(), so this can be
        # watched via `spamguardhostbans` before being armed. Only fires
        # when the REJOINING identity is ALSO running unverified (`~`)
        # ident -- a real ident server here means "not evidence this is
        # the same actor," and it's a plain fall-through to the normal
        # black/nick/ident/realname chain below, not a separate exemption.
        if host and self.registryValue("hostBanAutoRebanEnabled"):
            retention = self.registryValue("hostBanRetentionDays") * 86400
            record = self._host_bans.get(host, now=now, retention_secs=retention)
            if record is not None and (ident or "").startswith("~"):
                term = _heuristic_term("host_history", host)
                self._handle_match(irc, msg, channel, nick, ident, host, term,
                                    field="host_history", require_join_window=False,
                                    override_kick_reason=record.kick_reason)
                return

        # "black" is checked first among the term-matching categories
        # (after the persisted host-ban history above, which needs no
        # term matching at all) -- an explicit admin blacklist entry
        # (2026-08-14) is the most deliberate signal SpamGuard has, and
        # matches against BOTH the nick AND the host (whichever hits),
        # unlike every category below it which only ever checks one
        # specific field.
        black_term = (
            matcher.first_match(self._black_matchers, nick) if nick else None
        ) or (
            matcher.first_match(self._black_matchers, host) if host else None
        )
        if black_term is not None:
            self._handle_match(irc, msg, channel, nick, ident, host,
                                black_term, field="black", require_join_window=False)
            return  # already matched -- no need to also check nick/ident/realname

        nick_term = matcher.first_match(self._nick_matchers, nick) if nick else None
        if nick_term is not None:
            self._handle_match(irc, msg, channel, nick, ident, host,
                                nick_term, field="nick", require_join_window=False)
            return  # already matched -- no need to also check ident/realname

        ident_term = matcher.first_match(self._ident_matchers, ident) if ident else None
        if ident_term is not None:
            self._handle_match(irc, msg, channel, nick, ident, host,
                                ident_term, field="ident", require_join_window=False)
            return  # already matched -- no need to also check realname

        # Realname (gecos) is ONLY present here when the server negotiated
        # IRCv3 "extended-join" -- Limnoria requests it automatically
        # (irclib.py's REQUEST_CAPABILITIES), and when active the JOIN
        # message's args become (channel, account, realname) instead of
        # just (channel,). Not every ircd supports it (verify per network
        # live -- see config.py's realnamePhrases docstring); if it's not
        # active, len(msg.args) < 3 always and this silently never fires,
        # which is the correct fail-safe behavior, not a bug.
        realname = msg.args[2] if len(msg.args) >= 3 else None
        if realname:
            realname_term = matcher.first_match(self._realname_matchers, realname)
            if realname_term is not None:
                self._handle_match(irc, msg, channel, nick, ident, host,
                                    realname_term, field="realname", require_join_window=False)
                return  # already matched -- no need to also check raid

        self._check_join_heuristics(irc, msg, channel, nick, ident, host)

    def _check_join_heuristics(self, irc, msg, channel, nick, ident, host) -> None:
        """Threshold-based JOIN heuristics, checked only when no black/
        nick/ident/realname term already matched this join (same
        first-match-wins convention as the term checks in doJoin above).
        Currently just "raid" (2026-08-16) -- see this module's own
        docstring and heuristics.py's for the full reasoning behind
        adapting the idea from progval's AttackProtector rather than
        vendoring it, and why only the tipping-point joiner is acted on.
        """
        network = irc.network
        now = time.time()

        if self.registryValue("raidEnabled", channel, network):
            key = (network, channel)
            window = self.registryValue("raidWindowSecs")
            events = heuristics.prune_join_events(
                self._recent_joins.get(key, []) + [(now, nick)], now, window)
            self._recent_joins[key] = events
            distinct = {n for _, n in events}
            limit = self.registryValue("raidJoinLimit")
            if len(distinct) >= limit:
                # Reset so the next join doesn't immediately re-trigger
                # before a fresh window has genuinely built back up --
                # same convention as the flood heuristic.
                self._recent_joins.pop(key, None)
                term = _heuristic_term(
                    "raid", f"{len(distinct)} distinct joins within {window:.0f}s")
                self._handle_match(irc, msg, channel, nick, ident, host, term,
                                    field="raid", require_join_window=False)
                return
            self._prune_recent_joins(now)

    def doNick(self, irc, msg):
        """Re-checks the nick terms on a NICK CHANGE, not just at JOIN
        (idea from BlackTools' `badnick`, reimplemented -- nothing
        vendored, GPLv3). Closes the obvious evasion: join under a
        clean nick, change to the real one once nobody is watching the
        join.

        msg.nick is the OLD nick, msg.args[0] is the NEW one.
        Critically, Limnoria updates IrcState BEFORE dispatching to
        callbacks (irclib.py's feedMsg: state.addMsg() runs before the
        callback loop), so IrcState.doNick's own
        `chan.replaceUser(oldNick, newNick)` has ALREADY happened by
        the time this runs -- which is why this builds a SYNTHETIC
        message carrying the NEW nick rather than passing `msg`
        straight through. _is_exempt() calls
        chan_state.isVoicePlus(msg.nick); with the raw message that
        would look up the OLD nick, which no longer exists in the
        channel's user list, and a voiced user would silently lose
        their voice+ exemption (2026-08-22).
        """
        if msg.nick == irc.nick:
            return
        old_nick, new_nick = msg.nick, msg.args[0]
        ident, host = msg.user, msg.host
        network = irc.network

        channels = msg.tagged("channels") or [
            c for c, st in irc.state.channels.items() if new_nick in st.users
        ]

        # Carry the tracked join timestamp across the rename, so a
        # spammer who joins clean, renames, then pastes a template is
        # still INSIDE the content join window. Deliberately does NOT
        # re-key _recent_messages -- that would change the flood
        # heuristic's own behavior, which is a separate decision.
        for key in [k for k in self._joins if k[0] == network and k[2] == old_nick]:
            self._joins[(key[0], key[1], new_nick)] = self._joins.pop(key)

        term = matcher.first_match(self._nick_matchers, new_nick) if new_nick else None
        if term is None:
            return

        synth = ircmsgs.IrcMsg(command="NICK", args=(new_nick,),
                                prefix=f"{new_nick}!{ident}@{host}")
        for channel in channels:
            if not self._enabled(irc, channel):
                continue
            self._handle_match(irc, synth, channel, new_nick, ident, host, term,
                                field="nick", require_join_window=False)

    def _handle_leave_match(self, irc, msg, channel, nick, ident, host, term, *,
                             field: str, event: str) -> None:
        """The ONE matcher path in this plugin that deliberately does
        NOT funnel through _handle_match. By the time a QUIT/PART
        reaches a callback, Limnoria has already removed the user from
        irc.state (IrcState updates before the callback loop runs) --
        they are gone. A KICK against them is a guaranteed no-op, and
        _enforce()'s ban and kick are one coupled unit -- splitting
        that unit for a signal this cheap to fake (a quit/part reason
        costs an actor nothing to set) would be real blast radius on
        the plugin's most safety-critical code for marginal benefit.
        A netsplit also delivers one QUIT per affected user with an
        identical reason ("*.net *.split"-shaped) -- observing turns
        that into a burst of log lines; banning on match would risk a
        mass-ban on a routine network event.

        So this logs and relays with outcome "observed" and stops.
        Turning a real observation into real enforcement is the
        operator's call: `spamguard black add <host>` sweeps everyone
        already present AND blocks the next join with the correct
        mask at the correct moment, and hostBanAutoRebanEnabled covers
        a repeat offender. Nothing is lost by not banning at quit/part
        time -- this path is structurally incapable of enforcing, and
        that's the point, which is why it's its own method rather than
        a flag on _handle_match.
        """
        self._stats["matches"] += 1
        self._log(network=irc.network, channel=channel, nick=nick, ident=ident,
                   host=host, term=term, field=field, outcome="observed")
        self._relay(
            irc,
            f"[spamguard] matched {field} '{term.text}' [id:{term.id}] in a "
            f"{event} reason from {nick} ({ident}@{host}) in {irc.network}/{channel} "
            f"-- already gone, observed only",
        )

    def _check_leave_reason(self, irc, msg, channels, reason, *, field: str, event: str) -> None:
        if not reason:
            return
        text = ircutils.stripFormatting(reason)
        term = matcher.first_match(self._content_matchers, text)
        if term is None:
            return
        nick, ident, host = msg.nick, msg.user, msg.host
        for channel in channels:
            if not self._enabled(irc, channel):
                continue
            if not self.registryValue("quitPartEnabled", channel, irc.network):
                continue
            self._handle_leave_match(irc, msg, channel, nick, ident, host, term,
                                      field=field, event=event)

    def doQuit(self, irc, msg):
        """QUIT's reason is msg.args[0] -- but args may be entirely
        empty (a bare QUIT with no reason has NO args at all), so this
        must be guarded rather than indexed unconditionally. Observe-
        only -- see _handle_leave_match's own docstring."""
        if msg.nick == irc.nick:
            return
        reason = msg.args[0] if msg.args else ""
        channels = msg.tagged("channels") or ()
        self._check_leave_reason(irc, msg, channels, reason,
                                  field="quit_reason", event="quit")

    def doPart(self, irc, msg):
        """PART's msg.args[0] is the channel(s) -- possibly comma-
        separated for a multi-channel part (ircmsgs.parts() joins with
        ',', and IrcState.doPart splits on it the same way). The
        reason, if given at all, is msg.args[1]. Observe-only -- see
        _handle_leave_match's own docstring."""
        if msg.nick == irc.nick:
            return
        reason = msg.args[1] if len(msg.args) > 1 else ""
        channels = msg.args[0].split(",") if msg.args else ()
        self._check_leave_reason(irc, msg, channels, reason,
                                  field="part_reason", event="part")

    def doPrivmsg(self, irc, msg):
        channel = msg.channel
        if channel is None or msg.nick == irc.nick or ircmsgs.isCtcp(msg):
            return
        if not self._enabled(irc, channel):
            return

        text = ircutils.stripFormatting(msg.args[1]) if len(msg.args) > 1 else ""
        nick, ident, host = msg.nick, msg.user, msg.host

        term = matcher.first_match(self._content_matchers, text)
        if term is not None:
            self._stats["messages"] += 1
            self._handle_match(irc, msg, channel, nick, ident, host,
                                term, field="content", require_join_window=True)
            return

        self._check_heuristics(irc, msg, channel, nick, ident, host, text)

    def _check_heuristics(self, irc, msg, channel, nick, ident, host, text: str) -> None:
        """Non-term, threshold-based message heuristics (2026-08-14,
        adapted from ideas in Libera Chat's own `ozone` network-abuse bot
        -- see heuristics.py/mojibake.py's own module docstrings): flood,
        mass nick-highlight, excessive caps, and mojibake/garbled
        encoding, plus group_flood (2026-08-22, message-side counterpart
        to raid -- see heuristics.py's prune_join_events docstring) and
        repeat_chars (2026-08-22, adapted from BlackTools' TCL
        `repetitivechars`, see heuristics.py's longest_char_run
        docstring). Each is a per-channel opt-in (default off, see
        config.py's module comment on this block) -- unlike content/
        ident/nick/realname, which are implicitly off until a term is
        added, these have no natural "off" state otherwise, since a
        threshold always applies once code exists to check it. First hit
        wins, same convention as doJoin's nick/ident/realname chain --
        checked in this order: flood, group_flood, hilight, caps,
        mojibake, repeat_chars. group_flood is checked right after flood
        since it's flood's grouped sibling -- same window mechanics, but
        counting distinct nicks across the whole channel instead of one
        nick's own rate. repeat_chars is checked last, the lowest-risk
        position to add a ninth check without disturbing the existing
        order. None require the join window (require_join_window=False)
        -- these are general per-message conduct signals, not
        specifically the "just joined and pasted a template" pattern
        content matching targets.
        """
        network = irc.network
        now = time.time()

        if self.registryValue("floodEnabled", channel, network):
            key = (network, channel, nick)
            window = self.registryValue("floodWindowSecs")
            times = heuristics.prune_window(
                self._recent_messages.get(key, []) + [now], now, window)
            self._recent_messages[key] = times
            limit = self.registryValue("floodMessageLimit")
            if len(times) >= limit:
                # Reset so the next message doesn't immediately re-trigger
                # before a fresh window has genuinely built back up.
                self._recent_messages.pop(key, None)
                term = _heuristic_term(
                    "flood", f"{len(times)} messages within {window:.0f}s")
                self._handle_match(irc, msg, channel, nick, ident, host, term,
                                    field="flood", require_join_window=False)
                return
            self._prune_recent_messages(now)

        if self.registryValue("groupFloodEnabled", channel, network):
            key = (network, channel)
            window = self.registryValue("groupFloodWindowSecs")
            # prune_join_events, despite the name, is generic
            # (timestamp, nick) pruning -- shared with the raid
            # heuristic rather than duplicated under a second name.
            events = heuristics.prune_join_events(
                self._recent_group_messages.get(key, []) + [(now, nick)], now, window)
            self._recent_group_messages[key] = events
            distinct = {n for _, n in events}
            limit = self.registryValue("groupFloodMessageLimit")
            if len(distinct) >= limit:
                # Reset so the next message doesn't immediately
                # re-trigger before a fresh window has genuinely built
                # back up -- same convention as flood and raid.
                self._recent_group_messages.pop(key, None)
                term = _heuristic_term(
                    "group_flood",
                    f"{len(distinct)} distinct nicks messaging within {window:.0f}s")
                self._handle_match(irc, msg, channel, nick, ident, host, term,
                                    field="group_flood", require_join_window=False)
                return
            self._prune_recent_group_messages(now)

        if self.registryValue("hilightEnabled", channel, network):
            chan_state = irc.state.channels.get(channel)
            if chan_state is not None:
                min_len = self.registryValue("hilightMinNickLen")
                count = heuristics.highlighted_nick_count(
                    text, chan_state.users, nick, min_len)
                limit = self.registryValue("hilightNickLimit")
                if count >= limit:
                    term = _heuristic_term(
                        "hilight", f"{count} distinct nicks highlighted in one message")
                    self._handle_match(irc, msg, channel, nick, ident, host, term,
                                        field="hilight", require_join_window=False)
                    return

        if self.registryValue("capsEnabled", channel, network):
            min_len = self.registryValue("capsMinLength")
            if len(text) >= min_len:
                pct = heuristics.caps_percentage(text)
                threshold = self.registryValue("capsPercent")
                if pct >= threshold:
                    term = _heuristic_term(
                        "caps", f"{pct:.0%} caps ({len(text)} chars)")
                    self._handle_match(irc, msg, channel, nick, ident, host, term,
                                        field="caps", require_join_window=False)
                    return

        if self.registryValue("mojibakeEnabled", channel, network):
            score = mojibake.mojibake_score(text)
            threshold = self.registryValue("mojibakeScore")
            if score >= threshold:
                term = _heuristic_term("mojibake", f"mojibake score {score}")
                self._handle_match(irc, msg, channel, nick, ident, host, term,
                                    field="mojibake", require_join_window=False)
                return

        if self.registryValue("repeatCharsEnabled", channel, network):
            run = heuristics.longest_char_run(text)
            threshold = self.registryValue("repeatCharsMinRun")
            if run >= threshold:
                term = _heuristic_term(
                    "repeat_chars", f"{run}-character repeated run ({len(text)} chars)")
                self._handle_match(irc, msg, channel, nick, ident, host, term,
                                    field="repeat_chars", require_join_window=False)
                return

    # ---- shared gate chain (content/ident/nick/realname all funnel through here) ----

    def _handle_match(self, irc, msg, channel, nick, ident, host, term, *,
                       field: str, require_join_window: bool,
                       override_kick_reason: Optional[str] = None) -> None:
        """Common path once ANY matcher has found a hit: join-window check
        (content matches only -- ident/realname matches ARE the join
        event, nothing to be "outside" of), exemption, kill switch, real
        op -- then enforce. Every branch logs+relays with an outcome tag
        so a tuned-but-not-yet-armed word list is fully observable.

        override_kick_reason (2026-08-22): set only by the persisted
        host-ban-history reban path in doJoin -- when given, _enforce()
        reuses this exact string instead of building a fresh one from
        protection.kickReason, so a rejoin from a known-bad host shows
        the SAME kick message the original conviction did.
        """
        self._stats["matches"] += 1
        network = irc.network

        if require_join_window:
            now = time.time()
            self._prune_joins(now)
            joined_at = self._joins.get((network, channel, nick))
            within_window = (
                joined_at is not None
                and now - joined_at <= self.registryValue("joinWindowSecs")
            )
            if not within_window:
                self._log(network=network, channel=channel, nick=nick, ident=ident,
                           host=host, term=term, field=field, outcome="outside-window")
                self._relay(irc, f"[spamguard] matched {field} '{term.text}' [id:{term.id}] "
                                  f"from {nick} ({ident}@{host}) in {network}/{channel} but "
                                  f"outside join window -- not acted on")
                return

        if self._is_exempt(irc, channel, msg):
            self._log(network=network, channel=channel, nick=nick, ident=ident,
                       host=host, term=term, field=field, outcome="exempt")
            self._relay(irc, f"[spamguard] matched {field} '{term.text}' [id:{term.id}] "
                              f"from {nick} ({ident}@{host}) in {network}/{channel} but "
                              f"sender is exempt -- not acted on")
            return

        if self.registryValue("protection.killSwitch"):
            self._log(network=network, channel=channel, nick=nick, ident=ident,
                       host=host, term=term, field=field, outcome="killswitch")
            self._relay(irc, f"[spamguard] would kban {nick} ({ident}@{host}) in "
                              f"{network}/{channel} for {field} '{term.text}' [id:{term.id}] "
                              f"-- killSwitch is on")
            return

        xcb = None
        if not enforcement.is_opped(irc, channel):
            xcb = self._x_fallback(irc, channel)
            if xcb is None:
                self._log(network=network, channel=channel, nick=nick, ident=ident,
                           host=host, term=term, field=field, outcome="not-opped")
                # 2026-08-16: distinguish "no X fallback was even
                # configured for this channel" from "opted in, but not
                # usable" in the relay text only -- the "not-opped"
                # outcome tag stays unchanged so nothing that already
                # consumes the JSONL log needs a new value.
                # enforcement.preferXCommands lives in UndernetX's OWN
                # registry, not SpamGuard's -- read it via the live
                # callback's own public accessor, never a bare
                # self.registryValue (that would look up
                # plugins.SpamGuard.enforcement.preferXCommands, which
                # doesn't exist).
                suffix = ""
                x_cb_raw = irc.getCallback("UndernetX")
                if x_cb_raw is not None:
                    try:
                        if x_cb_raw.prefers_x_commands(irc, channel):
                            suffix = " (X fallback unavailable)"
                    except Exception:
                        pass
                self._relay(irc, f"[spamguard] would kban {nick} ({ident}@{host}) in "
                                  f"{network}/{channel} for {field} '{term.text}' [id:{term.id}] "
                                  f"-- not opped{suffix}")
                return

        self._enforce(irc, network, channel, nick, ident, host, term, field, xcb=xcb,
                      override_kick_reason=override_kick_reason)

    def _x_fallback(self, irc, channel):
        """The live UndernetX plugin instance iff X-routed enforcement
        would actually work in `channel` RIGHT NOW, else None
        (2026-08-16) -- mirrors plugins/Shild/plugin.py's own
        `_x_fallback` exactly, deliberately inlined here rather than
        shared (same "near-copy, not an import" convention this
        plugin's own enforcement.py already documents for the reasons
        cross-plugin imports are fragile in this codebase).
        """
        cb = irc.getCallback("UndernetX")
        if cb is None:
            return None
        try:
            return cb if cb.x_enforcement_available(irc, channel) else None
        except Exception:
            log.exception("SpamGuard: UndernetX availability check failed")
            return None

    def _sweep_black_term(self, term: termstore.Term) -> int:
        """2026-08-14: "black add" doesn't just block future joins/
        messages -- it also immediately acts on anyone ALREADY sitting
        in an enabled channel who matches, across EVERY network the bot
        is currently connected to (world.ircs), not just the network the
        command was issued on. Every hit still goes through the full
        _handle_match gate chain (exemption/killSwitch/op), so an
        already-present halfop or a registered user is exempt here
        exactly like a live join/message would be -- this only changes
        WHEN the check runs, never what it's allowed to act on. Returns
        the number of real enforcements that fired, for the command's
        own reply.
        """
        regex = matcher.compile_term(term.text, is_pattern=False)
        if regex is None:
            return 0
        pair = (term, regex)
        hits = 0
        for irc in world.ircs:
            network = irc.network
            for channel in list(irc.state.channels):
                if not self.registryValue("enabled", channel, network):
                    continue
                chan_state = irc.state.channels[channel]
                for nick in list(chan_state.users):
                    if nick == irc.nick:
                        continue
                    try:
                        hostmask = irc.state.nickToHostmask(nick)
                    except KeyError:
                        continue
                    if not hostmask or not ircutils.isUserHostmask(hostmask):
                        continue
                    _n, ident, host = ircutils.splitHostmask(hostmask)
                    if not (matcher.first_match([pair], nick) or matcher.first_match([pair], host)):
                        continue
                    synth_msg = ircmsgs.IrcMsg(command="JOIN", args=(channel,), prefix=hostmask)
                    before = self._stats["enforced"]
                    self._handle_match(irc, synth_msg, channel, nick, ident, host,
                                        term, field="black", require_join_window=False)
                    if self._stats["enforced"] > before:
                        hits += 1
        return hits

    def _scan_clones_all(self, *, force: bool = False) -> tuple[int, int]:
        """Every connected network, every channel where BOTH `enabled`
        and `cloneScanEnabled` are on. Returns (clusters_found,
        enforcements) summed across every channel scanned."""
        clusters = enforced = 0
        for irc in world.ircs:
            network = irc.network
            for channel in list(irc.state.channels):
                if not self.registryValue("enabled", channel, network):
                    continue
                if not self.registryValue("cloneScanEnabled", channel, network):
                    continue
                c, e = self._scan_clones(irc, channel, force=force)
                clusters += len(c)
                enforced += e
        return clusters, enforced

    def _scan_clones(self, irc, channel: str, *, force: bool = False):
        """Groups every currently-present user in `channel` by host and
        acts on any host with cloneScanMaxClones or more distinct
        nicks. This is a STATELESS snapshot (unlike raid/groupFlood,
        which are burst-in-a-time-window detectors) -- it catches slow
        trickle-in clones and clones that were already sitting in the
        channel before this feature existed.

        Returns (clusters, enforced_count) where clusters is a list of
        (host, [(nick, ident), ...]) for the command's own reply.

        Two things happen before a cluster is acted on, in order:

        1. Suppression (skipped when force=True, i.e. the on-demand
           spamguardclonescan command): if this (network, channel, host)
           cluster was already REPORTED within cloneScanRepeatSuppressSecs,
           skip it this pass. Enforcement firing is self-limiting (the
           cluster is gone next scan) -- the real failure mode is
           enforcement NOT firing (kill switch on, the default; or not
           opped; or exempt), in which case _handle_match still
           logs+relays every pass by design ("log unconditionally, act
           conditionally"), which would otherwise produce a fresh relay
           line every single interval, forever, during exactly the
           observe-with-killswitch-on phase that convention exists to
           keep readable. Stamped on REPORT, not only on successful
           enforcement.
        2. Cluster-level exemption: the ban mask this feature produces
           is per-HOST, but exemptRegistered/voice+/op capability are
           evaluated per-NICK inside _handle_match. In a shared-host
           cluster where one member is voiced, kicking the unvoiced
           members and banning the host would also lock out the voiced
           one on their next reconnect -- a failure mode no existing
           heuristic has, since every one of them acts on exactly one
           user. If ANY member is exempt, the whole cluster is skipped
           after producing exactly one outcome="exempt" record (for the
           first exempt member found, nick-sorted) -- the cluster stays
           fully observable for tuning, and nothing here bypasses the
           normal exemption/killSwitch/op gate chain.

        Otherwise, EVERY member is acted on (not just a "tipping" one,
        unlike raid/groupFlood) -- a clone cluster has no innocent
        members by construction, unlike a join/message burst which
        could be genuine regulars reconnecting after a netsplit. The
        host-scoped mask already bans the whole cluster from rejoining
        after the first call; the remaining calls exist to actually
        remove the others from the channel now.
        """
        now = time.time()
        network = irc.network
        chan_state = irc.state.channels.get(channel)
        if chan_state is None:
            return [], 0

        by_host: dict[str, list[tuple[str, str]]] = {}
        for nick in list(chan_state.users):
            if nick == irc.nick:
                continue
            try:
                hostmask = irc.state.nickToHostmask(nick)
            except KeyError:
                continue
            if not hostmask or not ircutils.isUserHostmask(hostmask):
                continue
            _n, ident, host = ircutils.splitHostmask(hostmask)
            if not host:
                continue
            by_host.setdefault(host, []).append((nick, ident))

        limit = self.registryValue("cloneScanMaxClones")
        suppress = self.registryValue("cloneScanRepeatSuppressSecs")
        clusters = []
        enforced = 0
        for host in sorted(by_host):
            members = sorted(by_host[host])
            if len(members) < limit:
                continue
            clusters.append((host, members))

            if not force:
                last = self._clone_scan_seen.get((network, channel, host), 0.0)
                if now - last < suppress:
                    continue
            self._clone_scan_seen[(network, channel, host)] = now

            term = _heuristic_term(
                "clone_scan", f"{len(members)} nicks sharing host {host}")

            exempt_member = None
            for nick, ident in members:
                synth = ircmsgs.IrcMsg(command="JOIN", args=(channel,),
                                        prefix=f"{nick}!{ident}@{host}")
                if self._is_exempt(irc, channel, synth):
                    exempt_member = (nick, ident, synth)
                    break

            if exempt_member is not None:
                nick, ident, synth = exempt_member
                self._handle_match(irc, synth, channel, nick, ident, host, term,
                                    field="clone_scan", require_join_window=False)
                continue

            before = self._stats["enforced"]
            for nick, ident in members:
                synth = ircmsgs.IrcMsg(command="JOIN", args=(channel,),
                                        prefix=f"{nick}!{ident}@{host}")
                self._handle_match(irc, synth, channel, nick, ident, host, term,
                                    field="clone_scan", require_join_window=False)
            if self._stats["enforced"] > before:
                enforced += 1

        # Prune stale suppression entries for this channel while we're here.
        stale = [k for k, ts in self._clone_scan_seen.items()
                 if k[0] == network and k[1] == channel and now - ts > suppress]
        for k in stale:
            self._clone_scan_seen.pop(k, None)

        return clusters, enforced

    # ---- enforcement ----

    def _enforce(self, irc, network, channel, nick, ident, host, term, field: str,
                 *, xcb=None, override_kick_reason: Optional[str] = None) -> None:
        duration = self.registryValue("protection.banDurationSecs")
        mask = enforcement.ban_mask(field, nick, ident, host)
        if override_kick_reason is not None:
            # 2026-08-22: the persisted host-ban-history reban path --
            # reuse the ORIGINAL conviction's kick message verbatim,
            # rather than building a fresh one below (there's no live
            # term match to build one from anyway).
            kick_reason = override_kick_reason
        else:
            default_reason = self.registryValue("protection.kickReason")
            # {term} is substituted if present in the configured reason text
            # (2026-08-13, per explicit request) -- a malformed value (e.g. an
            # unrelated stray '{' from a typo) falls back to the raw
            # configured string rather than ever crashing enforcement over a
            # bad config value.
            try:
                reason_text = default_reason.format(term=term.text)
            except (KeyError, IndexError, ValueError):
                reason_text = default_reason
            # Shows the actual connecting hostmask (nick!ident@host), not the
            # ban mask -- the mask is a wildcard pattern that can now differ
            # from this (e.g. an ident match bans *!<ident>@*, not this exact
            # host) and is always visible live via /mode +b regardless; this
            # line is about showing ops exactly WHO was kicked. Format agreed
            # with the user 2026-08-10/2026-08-13, mirroring Armour/idefix's
            # own "(reason: ...) [id: N]" blacklist-kick style -- term text,
            # hostmask, reason, and the term's permanent id are all visible
            # directly in the channel, not just in the JSONL log/relay line.
            hostmask = f"{nick}!{ident}@{host}"
            kick_reason = f'SpamGuard: "{term.text}" - {hostmask} - reason: {reason_text} - [id: {term.id}]'

        via = "x" if xcb is not None else "native"
        try:
            if xcb is not None:
                if not xcb.enforce_ban_via_x(irc, channel, nick, mask, kick_reason,
                                              duration_secs=duration):
                    log.warning("SpamGuard: X enforcement declined for %s in %s/%s",
                                mask, network, channel)
                    return
            else:
                enforcement.enforce_ban(irc, channel, nick, mask, kick_reason)
        except Exception:
            log.exception("SpamGuard: failed to enforce kban")
            return

        unban_at = time.time() + duration
        event_name = f"spamguard-unban-{id(self)}-{network}-{channel}-{mask}-{unban_at}"

        def _do_unban():
            self._pending_unbans.pop(event_name, None)
            live_irc = world.getIrc(network)
            if live_irc is None:
                return
            try:
                if via == "x":
                    x_cb = live_irc.getCallback("UndernetX")
                    if x_cb is None:
                        log.warning("SpamGuard: UndernetX no longer loaded; cannot "
                                    "lift X ban %s in %s/%s", mask, network, channel)
                        return
                    x_cb.unban_via_x(live_irc, channel, mask)
                else:
                    enforcement.unban(live_irc, channel, mask)
            except Exception:
                log.exception("SpamGuard: failed to auto-unban %s in %s/%s",
                               mask, network, channel)

        self._pending_unbans[event_name] = None
        schedule.addEvent(_do_unban, unban_at, name=event_name)

        # Persisted host-ban history (2026-08-22): only for a HOST-based
        # mask (never ident/nick, which already target something
        # narrower and more durable than a host -- same scope as
        # ban_mask()'s own fallback branch). A host_history-triggered
        # reban itself only touches (bumps hit_count/last_seen_at) --
        # there's nothing new to record, the reused kick_reason IS the
        # thing being replayed. A fresh match records/refreshes,
        # pinning kick_reason to whatever the FIRST real match set.
        if field not in ("ident", "nick"):
            if field == "host_history":
                self._host_bans.touch(host, now=time.time())
            else:
                self._host_bans.record(host, kick_reason, term.id, term.text, field,
                                        now=time.time())

        self._stats["enforced"] += 1
        self._log(network=network, channel=channel, nick=nick, ident=ident,
                   host=host, term=term, field=field, outcome="enforced", via=via)
        via_suffix = " (via X)" if via == "x" else ""
        self._relay(irc, f"[spamguard] kbanned {nick} ({ident}@{host}) in "
                          f"{network}/{channel} for {field} '{term.text}' [id:{term.id}]"
                          f"{via_suffix}")

    # ---- commands (all owner-only, same reasoning as Shild's: real
    # people's nicks/hosts and real moderation surface) ----

    def spamguardstatus(self, irc, msg, args):
        """takes no arguments

        Reports SpamGuard's match/enforcement counters and kill-switch
        state. Run in a channel to also see that channel's per-heuristic
        (flood/groupflood/hilight/caps/mojibake/raid/repeatchars/
        clonescan) enable state.
        """
        counts = {cat: len(self._terms.by_category(cat)) for cat in termstore.CATEGORIES}
        irc.reply(
            f"SpamGuard: messages_checked={self._stats['messages']} "
            f"matches={self._stats['matches']} enforced={self._stats['enforced']} | "
            f"protection: killSwitch="
            f"{'ON (safe)' if self.registryValue('protection.killSwitch') else 'OFF (live)'} "
            f"pending_unbans={len(self._pending_unbans)} | "
            f"content: words={counts['word']} phrases={counts['phrase']} "
            f"patterns={counts['pattern']}"
            + (f" ({len(self._matcher_skipped)} invalid, skipped)" if self._matcher_skipped else "")
            + f" | ident: words={counts['ident']} | nick: words={counts['nick']} "
            f"| realname: words={counts['realname_word']} phrases={counts['realname_phrase']} "
            f"| black: entries={counts['black']} "
            f"| total_terms={len(self._terms.all())} "
            f"| host_bans={len(self._host_bans)} "
            f"(auto-reban {'ON' if self.registryValue('hostBanAutoRebanEnabled') else 'off'})"
        )
        if msg.channel:
            def on(name: str) -> str:
                return "on" if self.registryValue(name, msg.channel, irc.network) else "off"
            irc.reply(
                f"SpamGuard heuristics in {msg.channel}: flood={on('floodEnabled')} "
                f"groupflood={on('groupFloodEnabled')} "
                f"hilight={on('hilightEnabled')} caps={on('capsEnabled')} "
                f"mojibake={on('mojibakeEnabled')} raid={on('raidEnabled')} "
                f"repeatchars={on('repeatCharsEnabled')} "
                f"clonescan={on('cloneScanEnabled')}"
            )
    spamguardstatus = wrap(spamguardstatus, ["owner"])

    def spamguardlist(self, irc, msg, args):
        """takes no arguments

        Lists every term with its id, grouped by category.
        """
        def fmt(category: str, label: str) -> str:
            entries = self._terms.by_category(category)
            if not entries:
                return f"{label}: (none)"
            return f"{label}: " + ", ".join(f"[id:{t.id}] {t.text!r}" for t in entries)

        irc.reply(fmt("word", "content words"))
        irc.reply(fmt("phrase", "content phrases"))
        irc.reply(fmt("pattern", "content patterns"))
        irc.reply(fmt("ident", "idents"))
        irc.reply(fmt("nick", "nicks"))
        irc.reply(fmt("realname_word", "realname words"))
        irc.reply(fmt("realname_phrase", "realname phrases"))
        irc.reply(fmt("black", "blacklist (nick/host)"))
    spamguardlist = wrap(spamguardlist, ["owner"])

    def spamguardsearch(self, irc, msg, args, query):
        """<id or text>

        Looks up a term by its permanent id, or substring-searches term
        text across every category.
        """
        results = self._terms.search(query)
        if not results:
            irc.reply(f"No terms matching {query!r}.")
            return
        shown = results[:20]
        lines = [f"[id:{t.id}] {t.category}: {t.text!r}" for t in shown]
        suffix = "" if len(results) <= 20 else f" (+{len(results) - 20} more, refine your query)"
        irc.reply(f"{len(results)} match(es): " + "  ".join(lines) + suffix)
    spamguardsearch = wrap(spamguardsearch, ["owner", "text"])

    def spamguardremove(self, irc, msg, args, term_id):
        """<id>

        Removes a single term by its permanent id, any category. See
        `spamguardsearch`/`spamguardlist` to find the id first.
        """
        removed = self._terms.remove(term_id)
        if removed is None:
            irc.error(f"No term with id {term_id}.")
            return
        self._rebuild_matchers()
        irc.replySuccess(f"removed [id:{removed.id}] {removed.category}: {removed.text!r}")
    spamguardremove = wrap(spamguardremove, ["owner", "int"])

    def spamguardhostbans(self, irc, msg, args):
        """takes no arguments

        Lists every persisted host-ban record (2026-08-22) -- host,
        field/term it was originally convicted on, hit count, and
        whether it's still within the retention window (i.e. would
        actually fire a reban right now). See hostBanAutoRebanEnabled
        for the switch that arms real auto-reban action on these.
        """
        retention = self.registryValue("hostBanRetentionDays") * 86400
        now = time.time()
        records = self._host_bans.all()
        if not records:
            irc.reply("No persisted host-ban records.")
            return
        lines = []
        for r in records[:20]:
            live = "active" if r.last_seen_at + retention >= now else "expired"
            age_days = (now - r.last_seen_at) / 86400
            lines.append(f"{r.host} ({r.field} '{r.term_text}' [id:{r.term_id}], "
                          f"hits={r.hit_count}, last seen {age_days:.1f}d ago, {live})")
        suffix = "" if len(records) <= 20 else f" (+{len(records) - 20} more)"
        irc.reply(f"{len(records)} host-ban record(s): " + "  ".join(lines) + suffix)
    spamguardhostbans = wrap(spamguardhostbans, ["owner"])

    def spamguardhostbansremove(self, irc, msg, args, host):
        """<host or IP>

        Removes a single persisted host-ban record -- manual override
        for a false positive. See spamguardhostbans to find the exact
        host string first.
        """
        if self._host_bans.remove(host):
            irc.replySuccess(f"removed host-ban record for {host}")
        else:
            irc.error(f"No host-ban record for {host!r}.")
    spamguardhostbansremove = wrap(spamguardhostbansremove, ["owner", "something"])

    def spamguardclonescan(self, irc, msg, args, channel):
        """[<channel>]

        Snapshots a channel's CURRENT userlist, groups by host, and
        acts on any host with cloneScanMaxClones or more distinct nicks
        present right now -- the slow-trickle/already-seated case raid
        and groupFlood structurally cannot see (idea from BlackTools'
        CloneScan module, reimplemented, nothing vendored). Runs the
        same gate chain as any other match (exemption / killSwitch / op
        / X fallback), so nothing here can act where a live match
        couldn't. Ignores the repeat-suppression window -- an operator
        explicitly asking for a scan always wants a full answer. With
        no argument in a channel, scans that channel; in a PM with no
        argument, scans every enabled channel on every connected
        network.
        """
        if channel is None:
            if msg.channel:
                targets = [(irc, msg.channel)]
            else:
                targets = [
                    (i, c) for i in world.ircs for c in list(i.state.channels)
                    if self.registryValue("enabled", c, i.network)
                ]
        else:
            if not ircutils.isChannel(channel):
                irc.error(f"{channel!r} doesn't look like a channel.")
                return
            targets = [(irc, channel)]

        total_clusters = 0
        total_enforced = 0
        lines = []
        for target_irc, target_channel in targets:
            clusters, enforced = self._scan_clones(target_irc, target_channel, force=True)
            total_clusters += len(clusters)
            total_enforced += enforced
            for host, members in clusters:
                shown = ", ".join(nick for nick, _ident in members[:5])
                suffix = "" if len(members) <= 5 else f" (+{len(members) - 5} more)"
                lines.append(f"{host} ({len(members)}: {shown}{suffix})")

        reply = f"clone scan: {total_clusters} cluster(s), {total_enforced} enforced"
        if lines:
            reply += " | " + " | ".join(lines)
        irc.reply(reply)
    spamguardclonescan = wrap(spamguardclonescan, ["owner", additional("channel")])

    def spamguard(self, irc, msg, args, category, action, terms):
        """<word|ident|nick|realname|pattern|black> <add|remove> <term> [...]

        Adds/removes terms (a space auto-stores as a phrase; patterns
        are regex, validated on add). Every term gets a permanent id --
        see spamguardlist/spamguardsearch/spamguardremove. "black add"
        also immediately kick+bans anyone ALREADY sitting in an enabled
        channel who matches, across every connected network -- not just
        future joins/messages.
        """
        if not terms:
            irc.error("Need at least one term for add/remove.")
            return

        added_by = msg.prefix
        results = []
        for term_text in terms:
            if category == "pattern":
                store_category = "pattern"
            elif category == "ident":
                store_category = "ident"
            elif category == "nick":
                store_category = "nick"
            elif category == "black":
                store_category = "black"
            elif category == "realname":
                store_category = "realname_phrase" if " " in term_text else "realname_word"
            else:  # word
                store_category = "phrase" if " " in term_text else "word"

            if action == "add":
                if store_category == "pattern":
                    if matcher.compile_term(term_text, is_pattern=True) is None:
                        results.append(f"{term_text!r}: invalid regex, skipped")
                        continue
                    # 2026-08-24 fix (found via code review): pattern
                    # terms run synchronously on this plugin's single,
                    # unthreaded main loop (threaded=False) for every
                    # message -- a catastrophic-backtracking pattern
                    # would hang the whole bot. Best-effort heuristic,
                    # not exhaustive -- see matcher.py's own comment.
                    if matcher.looks_catastrophically_backtracking(term_text):
                        results.append(
                            f"{term_text!r}: looks like it could cause "
                            "catastrophic regex backtracking (nested "
                            "quantifier), refusing to add"
                        )
                        continue
                existing = self._terms.find_by_text(store_category, term_text)
                if existing is not None:
                    results.append(f"{term_text!r}: already present [id:{existing.id}]")
                    continue
                added = self._terms.add(store_category, term_text, added_by=added_by)
                results.append(f"{term_text!r}: added [id:{added.id}]")
                if store_category == "black":
                    self._rebuild_matchers()  # so the sweep below uses the new term
                    hits = self._sweep_black_term(added)
                    if hits:
                        results[-1] += f" -- kbanned {hits} already-present match(es)"
            else:  # remove
                removed = self._terms.remove_by_text(store_category, term_text)
                results.append(
                    f"{term_text!r}: removed [id:{removed.id}]" if removed
                    else f"{term_text!r}: not found"
                )

        self._rebuild_matchers()
        irc.reply("; ".join(results))
    # any("something"), not many("something") -- avoids many()'s
    # ArgumentError-on-zero-match syntax-help reply; the "need at least
    # one term" case is handled explicitly above instead, where the
    # message can be specific to add/remove rather than generic.
    spamguard = wrap(spamguard, [
        "owner", ("literal", _CATEGORIES), ("literal", ("add", "remove")), anyArgs("something"),
    ])


Class = SpamGuard
