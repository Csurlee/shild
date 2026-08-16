###
# Copyright (c) 2017, Ken Spencer
# Copyright (c) 2020, oddluck <oddluck@riseup.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
###

import time

import supybot.log as log
import supybot.ircmsgs as ircmsgs
import supybot.utils as utils
import supybot.schedule as schedule
import supybot.world as world
from supybot.commands import *
import supybot.plugins as plugins
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks
from supybot.i18n import PluginInternationalization, internationalizeDocstring

from . import xcommands
from . import xprobe


_ = PluginInternationalization("UndernetX")

# shild-py addition (2026-08-14): real X reply texts that mean "you are
# genuinely identified" -- see _is_login_success_notice() below for why
# there are two, and why it deliberately does NOT use the builtin any().
_LOGIN_SUCCESS_MARKERS = ("AUTHENTICATION SUCCESSFUL as", "already authenticated as")


@internationalizeDocstring
class UndernetX(callbacks.Plugin):
    """Logins to Undernet's X Service"""

    threaded = True

    def __init__(self, irc):
        global instance
        instance = self
        self.__parent = super(UndernetX, self)
        callbacks.Plugin.__init__(self, irc)
        instance.irc = irc
        self.reset()
        self._pending = xcommands.PendingXRequestQueue()
        # shild-py addition (2026-08-16): in-memory X-capability probe
        # cache for the enforcement fallback -- see xprobe.py's module
        # docstring. Wiped on every @reload, same as self.identified
        # above and for the same reason: old verdicts from a prior
        # session/instance are meaningless.
        self._capabilities = xprobe.XCapabilityCache()
        # Names of scheduled events for the staggered post-join/post-login
        # probe triggers below -- tracked separately from _pending's own
        # timeout events so die() can cancel these too (a probe trigger
        # firing after this instance has already been reload'd/unloaded
        # would run against a dead instance for no reason).
        self._scheduled_probe_events = set()
        # shild-py addition (2026-08-14): re-identify immediately if this
        # __init__ is running because of a MID-SESSION "@reload
        # UndernetX", not a fresh cold start. A reload recreates this
        # plugin instance from scratch, which wipes self.identified back
        # to False via reset() above -- but the bot's real IRC session
        # almost certainly never actually lost its X authentication, only
        # this object's own bookkeeping went stale (confirmed live: a
        # user reported "undernetxstatus says identified=False... but
        # it's logged in" immediately after a plain @reload). Login is
        # idempotent/harmless to repeat, so just do it, rather than
        # leaving identified wrong until someone happens to run "login"
        # by hand. Only fires when it actually can: irc.state.supported
        # is empty at a genuine fresh connect (ISUPPORT hasn't arrived
        # yet), so this is a no-op there -- do376 handles that case, same
        # as before this existed.
        if irc.state.supported.get("NETWORK", "") == "UnderNet":
            if self.registryValue("auth.username") and self.registryValue("auth.password"):
                self._login(irc)

    def _login(self, irc):
        self.reset()
        username = self.registryValue("auth.username")
        password = self.registryValue("auth.password")
        xserv = self.registryValue("auth.xservice")
        irc.sendMsg(ircmsgs.privmsg(xserv, "login {} {}".format(username, password)))

    def _is_login_success_notice(self, text: str) -> bool:
        # Real X reply text that means "you are genuinely identified" --
        # found live the same day the __init__-triggered reload-relogin
        # fix (below) started making it possible to attempt a login
        # while ALREADY authenticated (previously never happened: only
        # do376, which fires once per connection, ever triggered a
        # login). X's real response in that case is "Sorry, You are
        # already authenticated as <account>", NOT "AUTHENTICATION
        # SUCCESSFUL as ..." -- confirmed via runtime/logs/messages.log's
        # own raw NOTICE record, not guessed. Without this,
        # self.identified stayed permanently False after any reload on
        # an already-logged-in bot, exactly the discrepancy a live user
        # report surfaced (undernetxstatus said identified=False right
        # after a successful, confirmed-live login).
        #
        # Deliberately NOT the builtin any() -- `from supybot.commands
        # import *` (this file's own top-of-file import, vendored)
        # shadows it with supybot.commands.any, a wrap-converter CLASS,
        # not a function. Confirmed live: any(generator) silently became
        # commands.any(generator), which asserts its argument is a wrap
        # spec and raises AssertionError deep in commands.py for
        # anything else -- same class of gotcha as the already-documented
        # `import supybot` monkeypatching the builtin format() (see
        # CLAUDE.md), just for a wildcard-imported name instead of a
        # process-wide monkeypatch. A plain loop sidesteps it entirely.
        for marker in _LOGIN_SUCCESS_MARKERS:
            if marker in text:
                return True
        return False

    def doNotice(self, irc, msg):
        if irc.state.supported.get("NETWORK", "") == "UnderNet":
            # A NOTICE with fewer than 2 args (no text) has nothing for
            # either branch below to read -- bail before the unguarded
            # msg.args[1] indexing that used to be able to raise here.
            if len(msg.args) < 2:
                return
            xhostmask = self.registryValue("auth.xserviceHostmask")
            if xhostmask in msg.prefix:
                if self._is_login_success_notice(msg.args[1]):
                    log.info("Authed to X (or already was): %s", msg.args[1])
                    modex = self.registryValue("modeXonID")
                    if modex:
                        log.info("Setting +x")
                        irc.sendMsg(ircmsgs.IrcMsg("MODE {} +x".format(irc.nick)))
                    # shild-py addition (2026-08-16): a FRESH identification
                    # (was False, now True) invalidates every previously
                    # cached X-capability verdict on this network -- old
                    # verdicts were checked under a different (or no)
                    # session and are meaningless now. Re-probe every
                    # already-joined, opted-in channel so a verdict is
                    # ready before enforcement ever needs one, rather than
                    # waiting for the first lazy on-demand probe.
                    was_identified = self.identified
                    self.identified = True
                    if not was_identified:
                        self._capabilities.clear(irc.network)
                        self._probe_all_opted_in_channels(irc)
                    waitingJoins = self.waitingJoins.pop(irc.network, None)
                    if waitingJoins:
                        for m in waitingJoins:
                            irc.sendMsg(m)
                else:
                    self._handle_x_reply(irc, msg)
            else:
                if self._is_login_success_notice(msg.args[1]):
                    log.warning("Someone is impersonating X!")
        else:
            log.debug("Notice isn't from UnderNet.. Ignoring")

    def reset(self):
        self.identified = False
        self.waitingJoins = {}

    def outFilter(self, irc, msg):
        if irc.state.supported.get("NETWORK", "") == "UnderNet":
            if msg.command == "JOIN":
                if not self.identified:
                    if self.registryValue("auth.noJoinsUntilAuthed"):
                        self.log.info(
                            "Holding JOIN to %s @ %s until identified.",
                            msg.channel,
                            irc.network,
                        )
                        self.waitingJoins.setdefault(irc.network, [])
                        self.waitingJoins[irc.network].append(msg)
                        return None
        return msg

    def do376(self, irc, msg):
        """Watch for the MOTD and login if we can"""
        if irc.state.supported.get("NETWORK", "") == "UnderNet":
            if self.registryValue("auth.username") and self.registryValue(
                "auth.password"
            ):
                log.info("Attempting login to XService")
            else:
                log.warning("username and password not set, this plugin will not work")
                return
            self._login(irc)

    do422 = do377 = do376

    # Similar to Services->Identify
    def login(self, irc, msg, args):
        """takes no arguments
        Logins to Undernet's X Service"""
        if irc.state.supported.get("NETWORK", "") == "UnderNet":
            if self.registryValue("auth.username") and self.registryValue(
                "auth.password"
            ):
                log.info("Attempting login to XService")
            else:
                log.warning("username and password not set, this plugin will not work")
                # 2026-08-14: this branch used to return with no IRC
                # reply at all -- an admin running "undernetx login" with
                # blank credentials got no bot response whatsoever, only
                # a log line. See "xsetpass" below for setting them.
                irc.error(_(
                    'No X username/password configured -- see "xsetpass".'
                ))
                return
            self._login(irc)
            irc.replySuccess()
        else:
            log.error("We're not on UnderNet, we can't use this.")
            irc.error("We're not on UnderNet, this is useless.")

    login = wrap(login, ["admin"])

    # ------------------------------------------------------------------
    # shild-py additions (2026-08-14) -- everything above this line is
    # the original vendored oddluck/limnoria-plugins UndernetX plugin,
    # left otherwise untouched. Everything below is new: a credential-
    # setting command mirroring Services' own "password"/"identify",
    # manual X moderation commands (xban/xkick/xop/...), and the
    # reply-correlation machinery those commands need (see
    # xcommands.py's module docstring -- there was no existing
    # request/response-over-IRC pattern anywhere in this repo to build
    # on, so this is genuinely new, deliberately best-effort machinery).
    # ------------------------------------------------------------------

    def _require_undernet(self, irc) -> bool:
        return irc.state.supported.get("NETWORK", "") == "UnderNet"

    def _deferred_reply(self, network: str, msg, text: str) -> None:
        """Replies to an ORIGINAL command invocation from OUTSIDE that
        command's own call stack (a later NOTICE from X, or a timeout)
        -- the live Irc object for `network` may not be the same object
        the command ran against if the bot reconnected meanwhile, so
        this re-fetches it fresh, same pattern Shild's/SpamGuard's own
        scheduled auto-unban callbacks already use (world.getIrc).
        """
        live_irc = world.getIrc(network)
        if live_irc is None:
            return
        target = msg.nick if msg.channel is None else msg.channel
        live_irc.queueMsg(ircmsgs.privmsg(target, text))

    def _handle_x_reply(self, irc, msg) -> None:
        """Every NOTICE from the verified X hostmask that ISN'T the
        login-success string reaches here. Correlated against the
        oldest still-pending request on this network, if any; otherwise
        logged exactly as this plugin always has (a NOTICE with nothing
        awaiting it -- e.g. an unsolicited X message).

        2026-08-16: `req.reply_to` is now always an XReplySink (see
        xcommands.py). If its on_reply callback says "I need more
        lines" (True), the request goes back to the FRONT of the queue
        via push_front rather than being considered answered -- this is
        what lets a multi-line reply (e.g. ACCESS's header/rows/
        terminator) span several NOTICEs without losing correlation to
        an unrelated request that might get queued in between.
        """
        text = msg.args[1]
        req = self._pending.pop_oldest(irc.network)
        if req is None:
            log.info("Received a NOTICE from X. msg: {}".format(text))
            return
        sink = req.reply_to
        want_more = False
        if sink is not None and sink.on_reply is not None:
            try:
                want_more = bool(sink.on_reply(text))
            except Exception:
                log.exception("UndernetX: X reply handler failed")
        if want_more:
            self._pending.push_front(req)
            return
        if req.timeout_event_name:
            try:
                schedule.removeEvent(req.timeout_event_name)
            except KeyError:
                pass

    def _send_x_raw(self, irc, description: str, text: str, *,
                     on_reply=None, on_timeout=None, timeout=None):
        """Sends `text` to X and registers reply correlation. Sends NO
        acknowledgement to anyone and expects no particular reply shape
        -- callers that want either of those build them via on_reply/
        on_timeout themselves (see _send_x_command below for the
        user-command wrapper, and _maybe_probe_channel/
        enforce_ban_via_x for the silent/programmatic callers this was
        added for, 2026-08-16). Returns the PendingXRequest, mainly so
        a caller can log/inspect it if needed.
        """
        xserv = self.registryValue("auth.xservice")
        irc.queueMsg(ircmsgs.privmsg(xserv, text))
        timeout = timeout if timeout is not None else self.registryValue(
            "commands.replyTimeoutSecs")
        network = irc.network
        sink = xcommands.XReplySink(on_reply=on_reply, on_timeout=on_timeout)
        req = self._pending.add(network, description, timeout, reply_to=sink)

        def _on_timeout():
            if self._pending.discard(req) and sink.on_timeout is not None:
                try:
                    sink.on_timeout()
                except Exception:
                    log.exception("UndernetX: X reply timeout handler failed")

        event_name = f"undernetx-xreply-{id(self)}-{network}-{id(req)}-{time.time()}"
        req.timeout_event_name = event_name
        schedule.addEvent(_on_timeout, time.time() + timeout, name=event_name)
        return req

    def _send_x_command(self, irc, msg, description: str, text: str) -> None:
        """The user-invoked command path (xban/xkick/xaccess/x/...) --
        unchanged behavior from before the 2026-08-16 _send_x_raw
        refactor: one NOTICE always finishes the request, relayed back
        to whoever ran the original command, or a "no reply" message
        after commands.replyTimeoutSecs.
        """
        network = irc.network
        timeout = self.registryValue("commands.replyTimeoutSecs")

        def _relay(reply_text):
            self._deferred_reply(network, msg, f"X: {reply_text}")
            return False  # one line always finishes a user command's reply

        def _relay_timeout():
            self._deferred_reply(
                network, msg,
                f'X: no reply for "{description}" (timed out after {timeout}s).',
            )

        self._send_x_raw(irc, description, text,
                          on_reply=_relay, on_timeout=_relay_timeout, timeout=timeout)
        irc.replySuccess(_(
            "sent to X: %s -- watching for a reply (up to %ss)."
        ) % (description, timeout))

    # ---- X-capability probe (2026-08-16) ----

    def _probe_all_opted_in_channels(self, irc) -> None:
        """Kicks off a probe for every channel this network is currently
        joined to that has enforcement.preferXCommands=True -- called
        after a fresh X login and from doJoin below. Staggered a few
        seconds apart so joining/logging into many opted-in channels at
        once doesn't burst several ACCESS queries at X simultaneously.
        """
        channels = [c for c in irc.state.channels
                    if self.registryValue("enforcement.preferXCommands", c, network=irc.network)]
        for n, channel in enumerate(channels):
            delay = 2.0 + 3.0 * n
            self._schedule_probe(irc, channel, delay)

    def doJoin(self, irc, msg):
        """The bot's OWN join to an opted-in channel triggers a
        capability probe (2026-08-16) -- so a verdict is ready before
        it's ever needed by enforcement, rather than only via the lazy
        on-demand path. Ignores every other nick's join (this plugin
        has no other use for doJoin).
        """
        if msg.nick != irc.nick:
            return
        if not self._require_undernet(irc):
            return
        if not self.identified:
            return
        channel = msg.channel
        if not self.registryValue("enforcement.preferXCommands", channel, network=irc.network):
            return
        self._schedule_probe(irc, channel, 2.0)

    def _schedule_probe(self, irc, channel, delay: float) -> None:
        network = irc.network
        event_name = f"undernetx-probe-{id(self)}-{network}-{channel}-{time.time()}-{delay}"

        def _fire():
            self._scheduled_probe_events.discard(event_name)
            live_irc = world.getIrc(network)
            if live_irc is not None:
                self._maybe_probe_channel(live_irc, channel)

        schedule.addEvent(_fire, time.time() + delay, name=event_name)
        self._scheduled_probe_events.add(event_name)

    def _maybe_probe_channel(self, irc, channel, *, force: bool = False,
                              on_verdict=None) -> bool:
        """Fires ONE ACCESS query if the cache says it's due (or
        `force`). Returns whether a probe was actually sent. Never
        sends when: not UnderNet, not identified, the master arm switch
        is off, the channel hasn't opted in (unless `force` -- the
        manual "xprobe" command bypasses the opt-in so it can be used to
        CHECK a channel before opting it in), no X username is
        configured (rule 2 of the classifier has nothing to anchor to,
        so a probe would be pointless), a probe is already in flight
        for this channel, within probeMinIntervalSecs of the last
        attempt, or a manual x* command is still awaiting a reply on
        this network (the FIFO correlation can't safely interleave a
        silent probe with a human's own pending command -- see the
        module-level caveat in xprobe.py; the probe just skips this
        round and tries again once the queue is clear).

        `on_verdict(verdict, lines)`, if given, is called once the probe
        resolves (whether via a definitive line, a terminator, or the
        timeout window closing) -- IN ADDITION TO the cache being
        recorded and the routine log.info() line, never instead of
        either. The automatic background triggers (doJoin, post-login
        reprobe, the lazy on-demand check inside x_enforcement_available)
        all pass nothing here, on purpose -- they're silent background
        housekeeping, correctly generating no IRC output. Found live
        2026-08-16: the "xprobe" COMMAND was calling this exact same
        silent path with no callback at all, so a real user running
        "xprobe #channel" got the immediate "sent, watching" ack and
        then NOTHING -- the verdict was only ever logged, never reported
        back. `on_verdict` is what fixes that (see the xprobe command
        below), without duplicating the classification logic here.
        """
        network = irc.network
        key_chan = ircutils.toLower(channel)
        if not self._require_undernet(irc) or not self.identified:
            return False
        if not force and not self.registryValue("enforcement.xFallbackEnabled"):
            return False
        if not force and not self.registryValue("enforcement.preferXCommands", channel,
                                                  network=network):
            return False
        username = self.registryValue("auth.username")
        if not username:
            return False
        ttl = self.registryValue("enforcement.probeTtlSecs")
        min_interval = self.registryValue("enforcement.probeMinIntervalSecs")
        now = time.time()
        if not force and not self._capabilities.should_probe(
                network, key_chan, ttl=ttl, min_interval=min_interval, now=now):
            return False
        if not force and self._pending.pending_count(network) > 0:
            # Don't steal correlation from an outstanding human command;
            # try again on the next lazy check instead.
            return False

        min_access = self.registryValue("enforcement.minAccessLevel")
        self._capabilities.mark_in_flight(network, key_chan, now)
        lines = []
        finished = []

        def _finish(verdict):
            if finished:
                return
            finished.append(True)
            self._capabilities.record(network, key_chan, verdict, list(lines), time.time())
            log.info("UndernetX: X capability for %s/%s = %s (%s)",
                      network, channel, verdict.state, verdict.reason)
            if on_verdict is not None:
                try:
                    on_verdict(verdict, list(lines))
                except Exception:
                    log.exception("UndernetX: on_verdict callback failed")

        def _on_line(text):
            lines.append(text)
            v = xprobe.classify_access_line(text, username=username, min_access=min_access)
            if v.state != xprobe.UNKNOWN:
                _finish(v)
                return False
            if xprobe.is_terminator(text):
                _finish(xprobe.classify_access_reply(
                    lines, username=username, min_access=min_access))
                return False
            return True

        def _on_window_closed():
            _finish(xprobe.classify_access_reply(
                lines, username=username, min_access=min_access))

        self._send_x_raw(
            irc, f"X capability probe for {channel}",
            xcommands.build_access(channel, f"={irc.nick}"),
            on_reply=_on_line, on_timeout=_on_window_closed,
        )
        return True

    def x_enforcement_available(self, irc, channel) -> bool:
        """True iff a kick/ban routed through X would actually work in
        `channel` RIGHT NOW: UnderNet + identified + the master arm
        switch + the channel's own opt-in + a non-expired, USABLE cached
        probe verdict. Never sends anything itself and never blocks --
        on an unknown/stale entry it kicks off an async probe (subject
        to the same rate limiting as every other trigger) and returns
        False for the CURRENT call regardless, so the caller always
        fails closed for the incident actually in front of it; a later
        call (the next incident) can succeed once the probe lands.
        """
        if not self._require_undernet(irc) or not self.identified:
            return False
        if not self.registryValue("enforcement.xFallbackEnabled"):
            return False
        if not self.registryValue("enforcement.preferXCommands", channel, network=irc.network):
            return False
        key_chan = ircutils.toLower(channel)
        ttl = self.registryValue("enforcement.probeTtlSecs")
        usable = self._capabilities.is_usable(irc.network, key_chan, ttl=ttl)
        if not usable:
            self._maybe_probe_channel(irc, channel)
        return usable

    def enforce_ban_via_x(self, irc, channel, nick, mask, reason,
                           duration_secs=None) -> bool:
        """Queues 'BAN <chan> <mask> <dur> <access> <reason>' then
        'KICK <chan> <nick> <reason>' to X. Re-checks
        x_enforcement_available() itself -- a caller cannot bypass the
        gate by holding a stale reference or skipping the check. Watches
        the eventual reply(ies); a denial-shaped one demotes the cache
        to unusable (self-correcting for an imperfect probe verdict or
        access revoked between the probe and now). Returns True iff both
        commands were actually queued -- this reflects "we attempted the
        action", not confirmation X actually carried it out (same
        best-effort limitation every other X command in this plugin
        already has).
        """
        if not self.x_enforcement_available(irc, channel):
            return False
        # duration_secs comes from the CALLER's own
        # protection.banDurationSecs (Shild's or SpamGuard's, whichever
        # is enforcing) -- UndernetX has no opinion of its own on how
        # long a ban should last, it only knows how to phrase one for X.
        # 3600s (1h) is a safe fallback if a caller ever omits it.
        duration = xcommands.format_duration(
            duration_secs if duration_secs is not None else 3600)
        access = self.registryValue("commands.defaultBanAccess")
        ban_text = xcommands.build_ban(channel, mask, duration=duration,
                                        access=access, reason=reason)
        kick_text = xcommands.build_kick(channel, nick, reason)
        network = irc.network
        key_chan = ircutils.toLower(channel)

        def _watch_reply(text):
            if xprobe.looks_like_denial(text):
                self._capabilities.invalidate(network, key_chan)
                log.warning("UndernetX: X denied enforcement in %s/%s: %s",
                            network, channel, text)
            else:
                log.info("UndernetX: X enforcement reply in %s/%s: %s",
                          network, channel, text)
            return False

        self._send_x_raw(irc, f"enforcement ban {mask} in {channel}", ban_text,
                          on_reply=_watch_reply)
        self._send_x_raw(irc, f"enforcement kick {nick} in {channel}", kick_text,
                          on_reply=_watch_reply)
        return True

    def unban_via_x(self, irc, channel, mask) -> bool:
        """'UNBAN <chan> <mask>'. Deliberately does NOT gate on
        x_enforcement_available() -- lifting a ban this bot already set
        via X must not get stuck just because access was later revoked
        or the cache went stale; the worst case is a harmless X error
        reply, never a permanently stuck ban.
        """
        if not self._require_undernet(irc) or not self.identified:
            return False
        text = xcommands.build_unban(channel, mask)
        self._send_x_raw(irc, f"enforcement unban {mask} in {channel}", text)
        return True

    def xprobe(self, irc, msg, args, channel):
        """<channel>

        Forces a fresh X-capability probe for <channel> right now
        (bypassing the normal opt-in/rate-limit gating -- this is the
        tool for checking whether a channel WOULD be usable before
        opting it in) and reports the raw reply lines collected plus the
        resulting verdict. Owner-only surface for the enforcement
        fallback feature, admin-gated same as the other x* commands.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        if not self.identified:
            irc.error(_("Not identified to X yet."))
            return
        username = self.registryValue("auth.username")
        if not username:
            irc.error(_("No X username configured -- see \"xsetpass\"."))
            return
        network = irc.network

        def _report(verdict, lines):
            # Fires from _handle_x_reply's call stack (a NOTICE handler),
            # well after this command method has already returned -- same
            # "re-fetch the live Irc, use _deferred_reply" pattern every
            # other async X-command result in this plugin already uses.
            raw = " | ".join(lines) if lines else "(no reply lines collected)"
            self._deferred_reply(
                network, msg,
                f"X capability for {channel}: {verdict.state} "
                f"(access={verdict.access_level}, {verdict.reason}) -- raw: {raw}",
            )

        sent = self._maybe_probe_channel(irc, channel, force=True, on_verdict=_report)
        if not sent:
            irc.error(_("Could not start a probe (already in flight?)."))
            return
        timeout = self.registryValue("commands.replyTimeoutSecs")
        irc.replySuccess(_(
            "probing X capability for %s -- watching for a reply (up to %ss)."
        ) % (channel, timeout))

    xprobe = wrap(xprobe, [("checkCapability", "admin"), "channel"])

    def xsetpass(self, irc, msg, args, username, password):
        """<username> <password>

        Sets X's login username/password and immediately re-attempts
        login if currently on UnderNet. Must be sent in a private
        message, like Services' own "password" command -- a channel is
        never an acceptable place to type a password. Only updates the
        LIVE registry value (masked in @config output as of 2026-08-14)
        -- a future "scripts/bootstrap_runtime.py" regen would otherwise
        silently wipe it, same as every other live-only credential
        change documented in CLAUDE.md, so this also prints the exact
        runtime/secrets.json lines to paste in yourself for that to
        survive a regen.
        """
        self.setRegistryValue("auth.username", username)
        self.setRegistryValue("auth.password", password)
        irc.replySuccess(_(
            'X credentials updated for this session. To survive a future '
            'bootstrap_runtime.py regen, also add to runtime/secrets.json: '
            '"undernet_x_username": "%s", "undernet_x_password": '
            '"<the password you just set>".'
        ) % username)
        if self._require_undernet(irc):
            self._login(irc)

    xsetpass = wrap(xsetpass, [
        ("checkCapability", "admin"), "private", "somethingWithoutSpaces", "text",
    ])

    def xban(self, irc, msg, args, channel, target, duration, reason):
        """<channel> <host/nick> [duration] [reason]

        Bans <host/nick> from <channel> via X's own BAN command instead
        of a raw IRC MODE +b -- works even where the bot holds no real
        channel op, as long as it's identified to X with enough access
        on <channel>. <duration> defaults to "commands.defaultBanDuration"
        ("0d", permanent) when omitted; X accepts "5m" through "365d".
        The ban's access-level exemption comes from
        "commands.defaultBanAccess", not a command argument -- see that
        value's own docstring for why it isn't exposed here directly.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        duration = duration or self.registryValue("commands.defaultBanDuration")
        access = self.registryValue("commands.defaultBanAccess")
        text = xcommands.build_ban(channel, target, duration=duration,
                                    access=access, reason=reason)
        self._send_x_command(irc, msg, f"ban {target} in {channel}", text)

    xban = wrap(xban, [
        ("checkCapability", "admin"), "channel", "something",
        optional("something"), optional("text", ""),
    ])

    def xunban(self, irc, msg, args, channel, target):
        """<channel> <host/nick>

        Unbans <host/nick> in <channel> via X.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_unban(channel, target)
        self._send_x_command(irc, msg, f"unban {target} in {channel}", text)

    xunban = wrap(xunban, [("checkCapability", "admin"), "channel", "something"])

    def xkick(self, irc, msg, args, channel, target, reason):
        """<channel> <nick> [reason]

        Kicks <nick> from <channel> via X's own KICK command.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_kick(channel, target, reason)
        self._send_x_command(irc, msg, f"kick {target} in {channel}", text)

    xkick = wrap(xkick, [
        ("checkCapability", "admin"), "channel", "something", optional("text", ""),
    ])

    def xop(self, irc, msg, args, channel, nicks):
        """<channel> <nick> [nick2 ...]

        Ops the given nick(s) in <channel> via X.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_op(channel, nicks)
        self._send_x_command(irc, msg, f"op {nicks} in {channel}", text)

    xop = wrap(xop, [("checkCapability", "admin"), "channel", "text"])

    def xdeop(self, irc, msg, args, channel, nicks):
        """<channel> <nick> [nick2 ...]

        Deops the given nick(s) in <channel> via X.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_deop(channel, nicks)
        self._send_x_command(irc, msg, f"deop {nicks} in {channel}", text)

    xdeop = wrap(xdeop, [("checkCapability", "admin"), "channel", "text"])

    def xvoice(self, irc, msg, args, channel, nicks):
        """<channel> <nick> [nick2 ...]

        Voices the given nick(s) in <channel> via X.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_voice(channel, nicks)
        self._send_x_command(irc, msg, f"voice {nicks} in {channel}", text)

    xvoice = wrap(xvoice, [("checkCapability", "admin"), "channel", "text"])

    def xdevoice(self, irc, msg, args, channel, nicks):
        """<channel> <nick> [nick2 ...]

        Devoices the given nick(s) in <channel> via X.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_devoice(channel, nicks)
        self._send_x_command(irc, msg, f"devoice {nicks} in {channel}", text)

    xdevoice = wrap(xdevoice, [("checkCapability", "admin"), "channel", "text"])

    def xinvite(self, irc, msg, args, channel):
        """<channel>

        Asks X to invite the bot into <channel> -- useful for an
        invite-only, key-protected, or banned channel.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_invite(channel)
        self._send_x_command(irc, msg, f"invite to {channel}", text)

    xinvite = wrap(xinvite, [("checkCapability", "admin"), "channel"])

    def xaccess(self, irc, msg, args, channel, target):
        """<channel> <username/=nick/pattern>

        Reports <target>'s access level in <channel>, via X. A bare
        target is looked up as an X USERNAME -- to look up whoever
        currently holds a given NICK instead, prefix it with "=" (e.g.
        "=csurlee"), per X's own ACCESS syntax. Confirmed live
        2026-08-14: a bare nick that isn't also that user's X username
        returns "No Match!" rather than resolving the nick.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        text = xcommands.build_access(channel, target)
        self._send_x_command(irc, msg, f"access for {target} in {channel}", text)

    xaccess = wrap(xaccess, [("checkCapability", "admin"), "channel", "something"])

    def x(self, irc, msg, args, text):
        """<raw X command text>

        Sends <text> verbatim to X -- an escape hatch for anything not
        wrapped in its own command above. Same reply-correlation/timeout
        as the typed commands.
        """
        if not self._require_undernet(irc):
            irc.error(_("This only works on UnderNet."))
            return
        self._send_x_command(irc, msg, text, text)

    x = wrap(x, [("checkCapability", "admin"), "text"])

    def prefers_x_commands(self, irc, channel) -> bool:
        """Public seam for another plugin to check whether THIS channel's
        moderation should route through X, reached via
        irc.getCallback("UndernetX") -- never a Python import, matching
        this repo's "cross-plugin imports are fragile" discipline (see
        CLAUDE.md). Consumed by SpamGuard's plugin.py (2026-08-16, for its
        relay-text suffix) and internally by x_enforcement_available.

        2026-08-16: `network=irc.network` is REQUIRED here (and at every
        other enforcement.preferXCommands read in this file) --
        registryValue()'s own docstring says channel/network "allow
        getting the most specific value", but omitting `network` doesn't
        just skip an optimization: registry.py's getSpecific() only ever
        consults the net+chan-specific tree inside its `if network and
        channel:` branch, so a bare 2-arg call silently reads ONLY the
        plain per-channel value and never sees a `config channel <network>
        <channel> ...`-style override at all. Found live the same day
        this seam got its first real consumer: a channel armed via
        exactly that command still worked, but only because the plain
        per-channel value happened to ALSO be set (separately, by the
        admin, for reasons unrelated to this bug) -- a channel armed via
        ONLY the network-scoped form would have silently read as
        `False`/not-opted-in. `getSpecific`'s own `fallback_to_channel`
        default (True) means passing both is always safe: a net+chan
        value wins if set, else the plain per-channel value is used
        exactly as before, so this fix cannot break an existing bare-only
        setup (including this plugin's own pre-existing tests).
        """
        if not self._require_undernet(irc):
            return False
        return self.registryValue("enforcement.preferXCommands", channel, network=irc.network)

    def undernetxstatus(self, irc, msg, args):
        """takes no arguments

        Reports whether this network is UnderNet, whether the bot is
        currently identified to X, how many xban/xkick/etc. commands are
        still awaiting a reply, and (2026-08-16) a summary of the
        X-capability probe cache used by the enforcement fallback.
        Read-only, never prints a credential.
        """
        if not self._require_undernet(irc):
            irc.reply(_("UndernetX: not connected to UnderNet on this network."))
            return
        pending = self._pending.pending_count(irc.network)
        configured = bool(
            self.registryValue("auth.username") and self.registryValue("auth.password")
        )
        irc.reply(_(
            "UndernetX: identified=%s -- credentials configured=%s -- "
            "pending X replies=%d"
        ) % (self.identified, configured, pending))
        fallback_enabled = self.registryValue("enforcement.xFallbackEnabled")
        entries = [(chan, entry) for net, chan, entry in self._capabilities.snapshot()
                   if net == irc.network]
        if entries:
            summary = ", ".join(f"{chan}={entry.state}" for chan, entry in entries)
        else:
            summary = "no channels probed yet"
        irc.reply(_(
            "UndernetX: X enforcement fallback armed=%s -- capability cache: %s"
        ) % (fallback_enabled, summary))

    undernetxstatus = wrap(undernetxstatus)

    def die(self):
        for req in self._pending.all_requests():
            if req.timeout_event_name:
                try:
                    schedule.removeEvent(req.timeout_event_name)
                except KeyError:
                    pass
        # 2026-08-16: cancel any still-pending scheduled probe triggers
        # (post-join/post-login stagger) too -- see _schedule_probe.
        for event_name in list(self._scheduled_probe_events):
            try:
                schedule.removeEvent(event_name)
            except KeyError:
                pass
        self._scheduled_probe_events.clear()
        self.__parent.die()


Class = UndernetX

# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
