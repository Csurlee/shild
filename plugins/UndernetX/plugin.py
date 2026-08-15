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
                    self.identified = True
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
        oldest still-pending xban/xkick/etc. request on this network, if
        any; otherwise logged exactly as this plugin always has (a NOTICE
        with nothing awaiting it -- e.g. an unsolicited X message).
        """
        text = msg.args[1]
        req = self._pending.pop_oldest(irc.network)
        if req is None:
            log.info("Received a NOTICE from X. msg: {}".format(text))
            return
        if req.timeout_event_name:
            try:
                schedule.removeEvent(req.timeout_event_name)
            except KeyError:
                pass
        self._deferred_reply(irc.network, req.reply_to, f"X: {text}")

    def _send_x_command(self, irc, msg, description: str, text: str) -> None:
        """Sends `text` verbatim to X, registers a pending reply
        correlation, and gives the caller an immediate "sent, waiting"
        acknowledgement -- the actual result arrives later (via
        _handle_x_reply, or the timeout below) as a second, separate
        reply, since there is no way to block a command handler waiting
        on an async IRC NOTICE without stalling this plugin's own
        callback dispatch for everyone else.
        """
        xserv = self.registryValue("auth.xservice")
        irc.queueMsg(ircmsgs.privmsg(xserv, text))
        timeout = self.registryValue("commands.replyTimeoutSecs")
        network = irc.network
        req = self._pending.add(network, description, timeout, reply_to=msg)

        def _on_timeout():
            if self._pending.discard(req):
                self._deferred_reply(
                    network, msg,
                    f'X: no reply for "{description}" (timed out after {timeout}s).',
                )

        event_name = f"undernetx-xreply-{id(self)}-{network}-{id(req)}-{time.time()}"
        req.timeout_event_name = event_name
        schedule.addEvent(_on_timeout, time.time() + timeout, name=event_name)
        irc.replySuccess(_(
            "sent to X: %s -- watching for a reply (up to %ss)."
        ) % (description, timeout))

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
        CLAUDE.md). Not yet called from anywhere: Shild's and SpamGuard's
        own enforcement.py modules don't consume this as of 2026-08-14 --
        see enforcement.preferXCommands's own docstring in config.py.
        """
        if not self._require_undernet(irc):
            return False
        return self.registryValue("enforcement.preferXCommands", channel)

    def undernetxstatus(self, irc, msg, args):
        """takes no arguments

        Reports whether this network is UnderNet, whether the bot is
        currently identified to X, and how many xban/xkick/etc. commands
        are still awaiting a reply. Read-only, never prints a
        credential.
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

    undernetxstatus = wrap(undernetxstatus)

    def die(self):
        for req in self._pending.all_requests():
            if req.timeout_event_name:
                try:
                    schedule.removeEvent(req.timeout_event_name)
                except KeyError:
                    pass
        self.__parent.die()


Class = UndernetX

# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
