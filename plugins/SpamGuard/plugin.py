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
nick (also checked at JOIN, added 2026-08-13), and realname (also
checked at JOIN, but ONLY when the server negotiated the IRCv3
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

from supybot import callbacks, ircdb, ircmsgs, ircutils, log, schedule, world
from supybot.commands import wrap
from supybot.commands import any as anyArgs

from shildml.schema import write_jsonl_line

from . import enforcement
from . import heuristics
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
_HEURISTIC_IDS = {"flood": -1, "hilight": -2, "caps": -3, "mojibake": -4}


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
        self._stats = {"messages": 0, "matches": 0, "enforced": 0}
        self._pending_unbans: dict[str, None] = {}

        self._terms = termstore.TermStore(self.registryValue("termsPath"))
        self._migrate_legacy_registry_terms()

        self._content_matchers: list[tuple[termstore.Term, object]] = []
        self._matcher_skipped: list[termstore.Term] = []
        self._ident_matchers: list[tuple[termstore.Term, object]] = []
        self._nick_matchers: list[tuple[termstore.Term, object]] = []
        self._realname_matchers: list[tuple[termstore.Term, object]] = []
        self._black_matchers: list[tuple[termstore.Term, object]] = []
        self._rebuild_matchers()

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
        self.__parent.die()

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

    def _log(self, *, network, channel, nick, ident, host, term, field: str, outcome: str) -> None:
        record = {
            "schema_version": 1,
            "source": "limnoria-spamguard",
            "ts": time.time(),
            "network": network,
            "channel": channel,
            "target": {"nick": nick, "ident": ident, "host": host},
            "field": field,
            "term": term.text,
            "term_id": term.id,
            "outcome": outcome,
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

    def _is_exempt(self, irc, channel: str, msg) -> bool:
        """Halfop+ in-channel, holding this channel's own ircdb 'op'
        capability, or (if exemptRegistered) any recognized registered
        user -- same exemption set Limnoria's own bundled BadWords plugin
        uses for its first two, plus the registered-user check from the
        2026-08-04 Misc hardening pass for the third."""
        chan_state = irc.state.channels.get(channel)
        if chan_state is not None and chan_state.isHalfopPlus(msg.nick):
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

        # "black" is checked FIRST, ahead of nick/ident/realname -- an
        # explicit admin blacklist entry (2026-08-14) is the most
        # deliberate signal SpamGuard has, and matches against BOTH the
        # nick AND the host (whichever hits), unlike every category
        # below it which only ever checks one specific field.
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
        encoding. Each is a per-channel opt-in (default off, see
        config.py's module comment on this block) -- unlike content/
        ident/nick/realname, which are implicitly off until a term is
        added, these have no natural "off" state otherwise, since a
        threshold always applies once code exists to check it. First hit
        wins, same convention as doJoin's nick/ident/realname chain --
        checked in this order: flood, hilight, caps, mojibake. None
        require the join window (require_join_window=False) -- these are
        general per-message conduct signals, not specifically the
        "just joined and pasted a template" pattern content matching
        targets.
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

    # ---- shared gate chain (content/ident/nick/realname all funnel through here) ----

    def _handle_match(self, irc, msg, channel, nick, ident, host, term, *,
                       field: str, require_join_window: bool) -> None:
        """Common path once ANY matcher has found a hit: join-window check
        (content matches only -- ident/realname matches ARE the join
        event, nothing to be "outside" of), exemption, kill switch, real
        op -- then enforce. Every branch logs+relays with an outcome tag
        so a tuned-but-not-yet-armed word list is fully observable.
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

        if not enforcement.is_opped(irc, channel):
            self._log(network=network, channel=channel, nick=nick, ident=ident,
                       host=host, term=term, field=field, outcome="not-opped")
            self._relay(irc, f"[spamguard] would kban {nick} ({ident}@{host}) in "
                              f"{network}/{channel} for {field} '{term.text}' [id:{term.id}] "
                              f"-- not opped")
            return

        self._enforce(irc, network, channel, nick, ident, host, term, field)

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

    # ---- enforcement ----

    def _enforce(self, irc, network, channel, nick, ident, host, term, field: str) -> None:
        duration = self.registryValue("protection.banDurationSecs")
        mask = enforcement.ban_mask(field, nick, ident, host)
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

        try:
            enforcement.enforce_ban(irc, channel, nick, mask, kick_reason)
        except Exception:
            log.exception("SpamGuard: failed to enforce kban")
            return

        unban_at = time.time() + duration
        event_name = f"spamguard-unban-{id(self)}-{network}-{channel}-{mask}-{unban_at}"

        def _do_unban():
            self._pending_unbans.pop(event_name, None)
            live_irc = world.getIrc(network)
            if live_irc is not None:
                try:
                    enforcement.unban(live_irc, channel, mask)
                except Exception:
                    log.exception("SpamGuard: failed to auto-unban %s in %s/%s",
                                   mask, network, channel)

        self._pending_unbans[event_name] = None
        schedule.addEvent(_do_unban, unban_at, name=event_name)

        self._stats["enforced"] += 1
        self._log(network=network, channel=channel, nick=nick, ident=ident,
                   host=host, term=term, field=field, outcome="enforced")
        self._relay(irc, f"[spamguard] kbanned {nick} ({ident}@{host}) in "
                          f"{network}/{channel} for {field} '{term.text}' [id:{term.id}]")

    # ---- commands (all owner-only, same reasoning as Shild's: real
    # people's nicks/hosts and real moderation surface) ----

    def spamguardstatus(self, irc, msg, args):
        """takes no arguments

        Reports SpamGuard's match/enforcement counters and kill-switch
        state. Run in a channel to also see that channel's per-heuristic
        (flood/hilight/caps/mojibake) enable state.
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
            f"| total_terms={len(self._terms.all())}"
        )
        if msg.channel:
            def on(name: str) -> str:
                return "on" if self.registryValue(name, msg.channel, irc.network) else "off"
            irc.reply(
                f"SpamGuard heuristics in {msg.channel}: flood={on('floodEnabled')} "
                f"hilight={on('hilightEnabled')} caps={on('capsEnabled')} "
                f"mojibake={on('mojibakeEnabled')}"
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
                if store_category == "pattern" and matcher.compile_term(
                        term_text, is_pattern=True) is None:
                    results.append(f"{term_text!r}: invalid regex, skipped")
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
