"""Limnoria PluginTestCase tests for UndernetX's shild-py additions
(everything past the "shild-py additions" marker in plugin.py) -- the
credential command, the manual xban/xkick/xop/... commands, and the
reply-correlation queue those commands use.

The original vendored login/do376/doNotice/outFilter behavior has no
offline tests here (same reasoning the original stub test.py gave: it
needs a real Undernet X service to authenticate against -- see
CLAUDE.md), but the pieces this session added ARE fully offline-
testable: pure command-string building (tests/test_undernetx_xcommands.py)
and, here, the actual IRC command surface using ChannelPluginTestCase.

Every test that needs the plugin to think it's on UnderNet sets
self.irc.state.supported["NETWORK"] = "UnderNet" directly -- there's no
lighter-weight way to fake ISUPPORT in this harness than mutating the
same dict irclib.py itself populates from a real 005 line.
"""
import supybot.conf as conf
import supybot.ircdb as ircdb
import supybot.ircutils as ircutils
from supybot.test import ChannelPluginTestCase


class UndernetXTestCase(ChannelPluginTestCase):
    plugins = ("UndernetX",)

    def setUp(self):
        super().setUp()
        self.irc.state.supported["NETWORK"] = "UnderNet"
        self._plugin = self.irc.getCallback("UndernetX")
        # auth.username/password are GLOBAL registry values, not reset
        # by PluginTestCase's automatic per-test config restore (that
        # only covers the class-level `config` dict) -- reset explicitly
        # so no test's credentials leak into a later one regardless of
        # run order.
        conf.supybot.plugins.UndernetX.auth.username.setValue("")
        conf.supybot.plugins.UndernetX.auth.password.setValue("")
        # 2026-08-16: enforcement.preferXCommands (channel-scoped) was
        # ALREADY a real, pre-existing leak here -- two existing tests
        # below set it via .setValue() and never reset it, only "safe"
        # by alphabetical test-ordering luck. Reset it and the four new
        # X-enforcement-fallback registry values explicitly, same
        # discipline as auth.username/.password just above.
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(False)
        # The network-scoped form (2026-08-16, see the network=irc.network
        # fix) is a SEPARATE registry value from the bare one above -- a
        # test setting it directly (e.g. to prove the fix works) would
        # otherwise leak into every later test the same way the bare form
        # already did before it had this reset. Plain .setValue(False)
        # is NOT enough here and would actually be actively wrong: per
        # registry.py's getSpecific(), a net+chan value that was EVER
        # explicitly set (._wasSet=True) -- even set to False -- takes
        # ABSOLUTE PRECEDENCE over the bare per-channel value, regardless
        # of which is actually True. .setValue() always sets ._wasSet,
        # so leaving that flag set here would make every test relying on
        # ONLY the bare form (i.e. almost all of them, via _arm() below)
        # silently read False instead -- caught live via a real test
        # failure the same day this reset was first added. Must also
        # clear ._wasSet directly to genuinely restore "never touched".
        net_specific = conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            ":test").get(self.channel)
        net_specific.setValue(False)
        net_specific._wasSet = False
        conf.supybot.plugins.UndernetX.enforcement.xFallbackEnabled.setValue(False)
        conf.supybot.plugins.UndernetX.enforcement.minAccessLevel.setValue(100)
        conf.supybot.plugins.UndernetX.enforcement.probeTtlSecs.setValue(3600)
        conf.supybot.plugins.UndernetX.enforcement.probeMinIntervalSecs.setValue(60)

        u = ircdb.users.newUser()
        u.name = "test-admin"
        u.addCapability("admin")
        u.addHostmask(self.prefix)
        ircdb.users.setUser(u)

    def _unprivileged_prefix(self):
        # __no_testcap__ is required in the host part, or ircdb's own
        # checkCapability short-circuits to True for every capability
        # during supybot-test runs (world.testing) -- same gotcha
        # documented repeatedly in Shild's/SpamGuard's own test.py.
        return ircutils.joinHostmask("rando", "user", "unregistered.example__no_testcap__")

    def _assert_denied_admin_capability(self, command):
        m = self.getMsg(command, frm=self._unprivileged_prefix())
        self.assertIn("Error:", m.args[1])
        self.assertIn("admin capability", m.args[1])

    # ---- reload re-identifies (2026-08-14 real-incident regression) ----
    #
    # Confirmed live: a plain "@reload UndernetX" while already connected
    # to UnderNet left undernetxstatus reporting identified=False even
    # though the bot's real IRC session had never actually lost its X
    # auth -- only the plugin's own fresh __init__ (which reset()s
    # identified back to False) went stale. __init__ now re-triggers
    # login immediately if the ISUPPORT NETWORK token is ALREADY known
    # to be UnderNet (true only on a mid-session reload, never on a cold
    # start, since ISUPPORT hasn't arrived yet at a real connect's
    # __init__ time -- do376 covers that case unchanged).

    def test_reinitializing_the_plugin_immediately_relogs_in_if_already_on_undernet(self):
        conf.supybot.plugins.UndernetX.auth.username.setValue("myuser")
        conf.supybot.plugins.UndernetX.auth.password.setValue("mypass")
        from plugins.UndernetX.plugin import UndernetX as UndernetXClass
        UndernetXClass(self.irc)  # simulates the object recreation a real @reload does
        sent = self.irc.takeMsg()
        self.assertIsNotNone(sent)
        self.assertEqual(sent.command, "PRIVMSG")
        self.assertIn("login myuser mypass", sent.args[1])

    def test_reinitializing_without_credentials_does_not_attempt_login(self):
        # auth.username/password are GLOBAL registry values -- explicitly
        # blanked here rather than assuming a clean slate, since another
        # test in this same run (test_reinitializing_the_plugin_
        # immediately_relogs_in_if_already_on_undernet) sets them and
        # PluginTestCase's config-dict auto-restore doesn't cover a
        # value set directly via conf.supybot.plugins...setValue().
        conf.supybot.plugins.UndernetX.auth.username.setValue("")
        conf.supybot.plugins.UndernetX.auth.password.setValue("")
        from plugins.UndernetX.plugin import UndernetX as UndernetXClass
        UndernetXClass(self.irc)
        self.assertIsNone(self.irc.takeMsg())

    def test_reinitializing_off_undernet_does_not_attempt_login(self):
        conf.supybot.plugins.UndernetX.auth.username.setValue("myuser")
        conf.supybot.plugins.UndernetX.auth.password.setValue("mypass")
        self.irc.state.supported["NETWORK"] = "Libera.Chat"
        from plugins.UndernetX.plugin import UndernetX as UndernetXClass
        UndernetXClass(self.irc)
        self.assertIsNone(self.irc.takeMsg())

    # ---- network gate ----

    def test_xban_errors_off_undernet(self):
        self.irc.state.supported["NETWORK"] = "Libera.Chat"
        m = self.getMsg("xban #test *!*@1.2.3.4 spamming")
        self.assertIn("only works on UnderNet", m.args[1])

    def test_xkick_errors_off_undernet(self):
        self.irc.state.supported["NETWORK"] = ""
        m = self.getMsg("xkick #test baduser")
        self.assertIn("only works on UnderNet", m.args[1])

    # ---- capability gate ----

    def test_xban_requires_admin_capability(self):
        self._assert_denied_admin_capability("xban #test *!*@1.2.3.4 reason")

    def test_xsetpass_requires_admin_capability(self):
        m = self.getMsg("xsetpass myuser mypass", private=True,
                         frm=self._unprivileged_prefix())
        self.assertIn("Error:", m.args[1])

    def test_x_raw_requires_admin_capability(self):
        self._assert_denied_admin_capability("x flags #test +o csurlee")

    # ---- xsetpass ----

    def test_xsetpass_must_be_sent_privately(self):
        # Sent to the channel, not a query -- the 'private' wrap
        # converter should reject this before ever touching the
        # registry, same as Services' own "password" command.
        before = conf.supybot.plugins.UndernetX.auth.password()
        m = self.getMsg("xsetpass myuser mypass")
        self.assertEqual(conf.supybot.plugins.UndernetX.auth.password(), before)

    def test_xsetpass_sets_registry_values_and_relogs_in(self):
        # irc.sendMsg (used by _login, jumping ahead of anything already
        # queued -- see its own docstring/the vendored do376's comment)
        # is what getMsg() picks up first here, NOT the reply: xsetpass's
        # own irc.replySuccess() call happens first in source order and
        # is queued via the normal (FIFO) irc.queueMsg, but _login's
        # irc.sendMsg() call, made second, jumps ahead of it.
        xserv = conf.supybot.plugins.UndernetX.auth.xservice()
        login_msg = self.getMsg("xsetpass myuser mypass", private=True)
        self.assertEqual(login_msg.command, "PRIVMSG")
        self.assertEqual(login_msg.args[0], xserv)
        self.assertIn("login myuser mypass", login_msg.args[1])
        self.assertEqual(conf.supybot.plugins.UndernetX.auth.username(), "myuser")
        self.assertEqual(conf.supybot.plugins.UndernetX.auth.password(), "mypass")

    def test_xsetpass_reply_never_echoes_the_password(self):
        self.getMsg("xsetpass myuser s3cr3t-password", private=True)  # the login PRIVMSG
        reply = self.irc.takeMsg()  # the actual command reply, sent as NOTICE (private)
        self.assertNotIn("s3cr3t-password", reply.args[1])

    def test_xsetpass_reply_includes_secretsjson_paste_lines(self):
        self.getMsg("xsetpass myuser mypass", private=True)  # the login PRIVMSG
        reply = self.irc.takeMsg()
        self.assertIn("secrets.json", reply.args[1])
        self.assertIn("undernet_x_username", reply.args[1])

    def test_xsetpass_does_not_relogin_off_undernet(self):
        self.irc.state.supported["NETWORK"] = "Libera.Chat"
        self.getMsg("xsetpass myuser mypass", private=True)
        # No PRIVMSG to X should have been queued -- only the command's
        # own reply is in the queue.
        self.assertIsNone(self.irc.takeMsg())

    # ---- xban / xunban / xkick ----
    #
    # irc.queueMsg(X command) runs before irc.replySuccess(...) in
    # _send_x_command's own source order, and both go through the real
    # Irc's normal (FIFO) queueMsg -- so getMsg() (which is just "feed,
    # then take the first queued message") returns the X command itself,
    # and the "sent to X..." acknowledgement is the SECOND message,
    # picked up by a subsequent self.irc.takeMsg().

    def test_xban_sends_correct_command_to_x(self):
        sent = self.getMsg("xban #test *!*@1.2.3.4 7d spamming here")
        self.assertEqual(sent.command, "PRIVMSG")
        self.assertEqual(sent.args[1], "BAN #test *!*@1.2.3.4 7d 0 spamming here")

    def test_xban_defaults_duration_when_omitted(self):
        sent = self.getMsg("xban #test *!*@1.2.3.4")
        self.assertEqual(sent.args[1], "BAN #test *!*@1.2.3.4 0d 0")

    def test_xban_replies_sent_immediately(self):
        self.getMsg("xban #test *!*@1.2.3.4")  # the BAN command itself
        reply = self.irc.takeMsg()
        self.assertIn("sent to X", reply.args[1])

    def test_xunban_sends_correct_command(self):
        sent = self.getMsg("xunban #test *!*@1.2.3.4")
        self.assertEqual(sent.args[1], "UNBAN #test *!*@1.2.3.4")

    def test_xkick_sends_correct_command_with_reason(self):
        sent = self.getMsg("xkick #test baduser get out")
        self.assertEqual(sent.args[1], "KICK #test baduser get out")

    def test_xkick_sends_correct_command_without_reason(self):
        sent = self.getMsg("xkick #test baduser")
        self.assertEqual(sent.args[1], "KICK #test baduser")

    def test_xop_sends_correct_command(self):
        sent = self.getMsg("xop #test alice bob")
        self.assertEqual(sent.args[1], "OP #test alice bob")

    def test_xinvite_sends_correct_command(self):
        sent = self.getMsg("xinvite #test")
        self.assertEqual(sent.args[1], "INVITE #test")

    def test_xaccess_sends_correct_command(self):
        sent = self.getMsg("xaccess #test csurlee")
        self.assertEqual(sent.args[1], "ACCESS #test csurlee")

    def test_raw_x_passthrough_sends_verbatim_text(self):
        sent = self.getMsg("x flags #test +ov csurlee")
        self.assertEqual(sent.args[1], "flags #test +ov csurlee")

    # ---- login success detection (2026-08-14 real-incident regression) ----

    def test_authentication_successful_notice_sets_identified(self):
        from supybot import ircmsgs
        xhostmask = conf.supybot.plugins.UndernetX.auth.xserviceHostmask()
        self.assertFalse(self._plugin.identified)
        notice = ircmsgs.notice(self.nick, "AUTHENTICATION SUCCESSFUL as ExampleAccount",
                                 prefix=xhostmask)
        self.irc.feedMsg(notice)
        self.assertTrue(self._plugin.identified)

    def test_already_authenticated_notice_also_sets_identified(self):
        # The exact real text X sends when a login is attempted while
        # already logged in -- confirmed live 2026-08-14 via
        # runtime/logs/messages.log, NOT "AUTHENTICATION SUCCESSFUL as".
        # This is the actual root cause of the live report ("its logged
        # in" but undernetxstatus said identified=False): the
        # __init__-triggered reload-relogin fix made this response
        # reachable for the first time (previously only do376, firing
        # once per connection on a never-yet-authenticated bot, ever
        # triggered a login at all).
        from supybot import ircmsgs
        xhostmask = conf.supybot.plugins.UndernetX.auth.xserviceHostmask()
        self.assertFalse(self._plugin.identified)
        notice = ircmsgs.notice(self.nick, "Sorry, You are already authenticated as ExampleAccount",
                                 prefix=xhostmask)
        self.irc.feedMsg(notice)
        self.assertTrue(self._plugin.identified)

    def test_authentication_failed_notice_does_not_set_identified(self):
        from supybot import ircmsgs
        xhostmask = conf.supybot.plugins.UndernetX.auth.xserviceHostmask()
        notice = ircmsgs.notice(
            self.nick,
            "AUTHENTICATION FAILED as ExampleAccount (Maximum concurrent logins exceeded).",
            prefix=xhostmask,
        )
        self.irc.feedMsg(notice)
        self.assertFalse(self._plugin.identified)

    def test_impersonator_claiming_already_authenticated_is_detected(self):
        from supybot import ircmsgs
        notice = ircmsgs.notice(self.nick, "Sorry, You are already authenticated as ExampleAccount",
                                 prefix="X!nobody@evil.example")
        self.irc.feedMsg(notice)  # must not raise, must not set identified
        self.assertFalse(self._plugin.identified)

    # ---- reply correlation ----

    def test_x_notice_reply_is_relayed_to_the_original_caller(self):
        self.getMsg("xban #test *!*@1.2.3.4")  # the outbound BAN PRIVMSG to X
        self.irc.takeMsg()  # the "sent to X..." acknowledgement, don't care here
        self.assertEqual(self._plugin._pending.pending_count("test"), 1)

        from supybot import ircmsgs
        xhostmask = conf.supybot.plugins.UndernetX.auth.xserviceHostmask()
        reply = ircmsgs.notice(self.nick, "*** Ban set on #test",
                                prefix=xhostmask)
        self.irc.feedMsg(reply)

        relayed = self.irc.takeMsg()
        self.assertIsNotNone(relayed)
        self.assertIn("*** Ban set on #test", relayed.args[1])
        self.assertEqual(self._plugin._pending.pending_count("test"), 0)

    def test_notice_from_a_non_x_sender_does_not_satisfy_a_pending_request(self):
        from supybot import ircmsgs
        self.getMsg("xban #test *!*@1.2.3.4")
        self.irc.takeMsg()  # outbound BAN command

        impostor = ircmsgs.notice(self.nick, "AUTHENTICATION SUCCESSFUL as csurlee",
                                   prefix="X!nobody@evil.example")
        self.irc.feedMsg(impostor)

        # Still pending -- an impostor notice must not satisfy it.
        self.assertEqual(self._plugin._pending.pending_count("test"), 1)

    def test_notice_with_no_pending_request_is_just_logged(self):
        from supybot import ircmsgs
        xhostmask = conf.supybot.plugins.UndernetX.auth.xserviceHostmask()
        unsolicited = ircmsgs.notice(self.nick, "unsolicited message", prefix=xhostmask)
        # Must not raise.
        self.irc.feedMsg(unsolicited)
        self.assertIsNone(self.irc.takeMsg())

    def test_malformed_single_arg_notice_does_not_raise(self):
        from supybot import ircmsgs
        xhostmask = conf.supybot.plugins.UndernetX.auth.xserviceHostmask()
        # A NOTICE with only a target and no text -- must not IndexError.
        malformed = ircmsgs.IrcMsg(command="NOTICE", args=(self.nick,), prefix=xhostmask)
        self.irc.feedMsg(malformed)  # must not raise

    # ---- prefers_x_commands seam ----

    def test_prefers_x_commands_defaults_false(self):
        self.assertFalse(self._plugin.prefers_x_commands(self.irc, self.channel))

    def test_prefers_x_commands_reads_the_channel_value(self):
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(True)
        self.assertTrue(self._plugin.prefers_x_commands(self.irc, self.channel))

    def test_prefers_x_commands_false_off_undernet_even_if_set(self):
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(True)
        self.irc.state.supported["NETWORK"] = "Libera.Chat"
        self.assertFalse(self._plugin.prefers_x_commands(self.irc, self.channel))

    def test_prefers_x_commands_reads_a_network_scoped_only_value(self):
        # Regression test (2026-08-16): a value set via ONLY the
        # network-scoped form -- e.g. Limnoria's own "config channel
        # <network> <channel> ..." command -- must be read correctly.
        # Before the network=irc.network fix, registryValue()'s own
        # getSpecific() silently ignored this entirely and only ever
        # consulted the bare per-channel value, so a channel armed this
        # way (and ONLY this way) would have wrongly read as opted out.
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            ":test").get(self.channel).setValue(True)
        # The bare (non-network-scoped) value is untouched/still False --
        # this proves the network-scoped value is actually what's being
        # read, not a coincidental bare-value match.
        self.assertFalse(
            conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(self.channel)())
        self.assertTrue(self._plugin.prefers_x_commands(self.irc, self.channel))

    # ---- undernetxstatus ----

    def test_undernetxstatus_off_undernet(self):
        self.irc.state.supported["NETWORK"] = "Libera.Chat"
        m = self.getMsg("undernetxstatus")
        self.assertIn("not connected to UnderNet", m.args[1])

    def test_undernetxstatus_never_prints_the_password(self):
        conf.supybot.plugins.UndernetX.auth.username.setValue("myuser")
        conf.supybot.plugins.UndernetX.auth.password.setValue("s3cr3t-password")
        m = self.getMsg("undernetxstatus")
        self.assertNotIn("s3cr3t-password", m.args[1])

    def test_undernetxstatus_reports_pending_count(self):
        self.getMsg("xban #test *!*@1.2.3.4")
        self.irc.takeMsg()  # the BAN PRIVMSG
        m = self.getMsg("undernetxstatus")
        self.assertIn("pending X replies=1", m.args[1])

    def test_login_produces_exactly_one_success_reply(self):
        # Regression coverage for a live report (2026-08-14) of TWO
        # "The operation succeeded." lines from one "undernetx login" --
        # confirmed via this exact test that the plugin itself only ever
        # queues one login PRIVMSG + one reply; the live duplicate was
        # not reproducible here, so it isn't this code (see CLAUDE.md).
        conf.supybot.plugins.UndernetX.auth.username.setValue("myuser")
        conf.supybot.plugins.UndernetX.auth.password.setValue("mypass")
        self.getMsg("undernetx login")  # the login PRIVMSG to X
        reply = self.irc.takeMsg()
        self.assertIsNotNone(reply)
        self.assertIn("operation succeeded", reply.args[1])
        self.assertIsNone(self.irc.takeMsg())  # nothing more queued

    # ---- X-capability probe / enforcement fallback (2026-08-16) ----

    def _arm(self, *, prefer=True, fallback=True, identified=True, username="shild"):
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(prefer)
        conf.supybot.plugins.UndernetX.enforcement.xFallbackEnabled.setValue(fallback)
        conf.supybot.plugins.UndernetX.auth.username.setValue(username)
        self._plugin.identified = identified

    def _feed_x_notice(self, text):
        from supybot import ircmsgs
        xhostmask = conf.supybot.plugins.UndernetX.auth.xserviceHostmask()
        self.irc.feedMsg(ircmsgs.notice(self.nick, text, prefix=xhostmask))

    def test_xprobe_sends_the_right_access_query_with_no_premature_ack(self):
        self._arm()
        sent = self.getMsg(f"xprobe {self.channel}")
        self.assertEqual(sent.command, "PRIVMSG")
        self.assertEqual(sent.args[1], f"ACCESS {self.channel} ={self.nick}")
        reply = self.irc.takeMsg()
        self.assertIn("probing X capability", reply.args[1])

    def test_xprobe_reports_the_resolved_verdict_once_the_reply_lands(self):
        # Real bug found live 2026-08-16: "xprobe #channel" sent the
        # immediate ack and then NEVER reported the actual result -- the
        # probe's own resolution path only ever logged internally
        # (correct for the SILENT background triggers, wrong for a
        # command a human is actively watching). Fixed via
        # _maybe_probe_channel's new on_verdict callback.
        self._arm()
        self.getMsg(f"xprobe {self.channel}")  # the ACCESS PRIVMSG
        self.irc.takeMsg()  # the "probing..." ack

        self._feed_x_notice(f"shild (shild) has access 500 in {self.channel}.")

        report = self.irc.takeMsg()
        self.assertIsNotNone(report, "xprobe must report a result once the reply lands")
        self.assertIn("usable", report.args[1])
        self.assertIn("500", report.args[1])

    def test_xprobe_reports_unusable_after_a_denial_reply(self):
        self._arm()
        self.getMsg(f"xprobe {self.channel}")
        self.irc.takeMsg()

        self._feed_x_notice("No Match!")

        report = self.irc.takeMsg()
        self.assertIsNotNone(report)
        self.assertIn("unusable", report.args[1])

    def test_xprobe_requires_admin_capability(self):
        self._arm()
        self._assert_denied_admin_capability(f"xprobe {self.channel}")

    def test_xprobe_errors_off_undernet(self):
        self._arm()
        self.irc.state.supported["NETWORK"] = "Libera.Chat"
        m = self.getMsg(f"xprobe {self.channel}")
        self.assertIn("only works on UnderNet", m.args[1])

    def test_xprobe_errors_when_not_identified(self):
        self._arm(identified=False)
        m = self.getMsg(f"xprobe {self.channel}")
        self.assertIn("Not identified", m.args[1])

    def test_multiline_access_reply_stays_pending_across_first_lines(self):
        # The core regression test for the new multi-line mechanic:
        # header + a data row + a terminator, as three SEPARATE NOTICEs.
        # The request must stay correlated (pending_count == 1) across
        # the first two, and only resolve on the terminator.
        self._arm()
        self.assertTrue(self._plugin._maybe_probe_channel(self.irc, self.channel, force=True))
        self.assertEqual(self._plugin._pending.pending_count("test"), 1)

        self._feed_x_notice(f"-- {self.channel} access list --")
        self.assertEqual(self._plugin._pending.pending_count("test"), 1)

        self._feed_x_notice(f"shild (shild) has access 500 in {self.channel}.")
        # A definitive line (username+level match) finishes the probe
        # immediately -- it doesn't need to wait for a terminator too.
        self.assertEqual(self._plugin._pending.pending_count("test"), 0)

        from plugins.UndernetX import xprobe
        entry = self._plugin._capabilities.get("test", ircutils.toLower(self.channel))
        self.assertEqual(entry.state, xprobe.USABLE)
        self.assertEqual(entry.access_level, 500)

    def test_multiline_access_reply_resolves_on_terminator_with_no_definitive_row(self):
        self._arm()
        self._plugin._maybe_probe_channel(self.irc, self.channel, force=True)
        self._feed_x_notice(f"-- {self.channel} access list --")
        self._feed_x_notice("someoneelse (someoneelse) has access 500 in here.")
        self.assertEqual(self._plugin._pending.pending_count("test"), 1)
        self._feed_x_notice("End of access list.")
        self.assertEqual(self._plugin._pending.pending_count("test"), 0)

        from plugins.UndernetX import xprobe
        entry = self._plugin._capabilities.get("test", ircutils.toLower(self.channel))
        self.assertEqual(entry.state, xprobe.UNUSABLE)

    def test_probe_denial_reply_resolves_unusable_immediately(self):
        self._arm()
        self._plugin._maybe_probe_channel(self.irc, self.channel, force=True)
        self._feed_x_notice("No Match!")
        self.assertEqual(self._plugin._pending.pending_count("test"), 0)

        from plugins.UndernetX import xprobe
        entry = self._plugin._capabilities.get("test", ircutils.toLower(self.channel))
        self.assertEqual(entry.state, xprobe.UNUSABLE)

    def test_impostor_notice_mid_probe_is_ignored(self):
        from supybot import ircmsgs
        self._arm()
        self._plugin._maybe_probe_channel(self.irc, self.channel, force=True)
        impostor = ircmsgs.notice(self.nick, "shild (shild) has access 500 in here.",
                                   prefix="X!nobody@evil.example")
        self.irc.feedMsg(impostor)  # must not raise, must not satisfy the probe
        self.assertEqual(self._plugin._pending.pending_count("test"), 1)

    # ---- x_enforcement_available -- fail-closed on every missing precondition ----

    def test_x_enforcement_available_false_off_undernet(self):
        self._arm()
        self._seed_usable()
        self.irc.state.supported["NETWORK"] = "Libera.Chat"
        self.assertFalse(self._plugin.x_enforcement_available(self.irc, self.channel))

    def test_x_enforcement_available_false_when_not_identified(self):
        self._arm(identified=False)
        self._seed_usable()
        self.assertFalse(self._plugin.x_enforcement_available(self.irc, self.channel))

    def test_x_enforcement_available_false_when_arm_switch_off(self):
        self._arm(fallback=False)
        self._seed_usable()
        self.assertFalse(self._plugin.x_enforcement_available(self.irc, self.channel))

    def test_x_enforcement_available_false_when_channel_not_opted_in(self):
        self._arm(prefer=False)
        self._seed_usable()
        self.assertFalse(self._plugin.x_enforcement_available(self.irc, self.channel))

    def test_x_enforcement_available_false_with_no_cache_entry(self):
        self._arm()
        self.assertFalse(self._plugin.x_enforcement_available(self.irc, self.channel))

    def test_x_enforcement_available_true_with_seeded_usable_cache(self):
        self._arm()
        self._seed_usable()
        self.assertTrue(self._plugin.x_enforcement_available(self.irc, self.channel))

    def test_x_enforcement_available_true_with_network_scoped_only_prefer(self):
        # Same regression as test_prefers_x_commands_reads_a_network_
        # scoped_only_value, but through the actual enforcement gate
        # (x_enforcement_available), which is what Shild/SpamGuard's
        # enforcement.py really calls.
        self._arm(prefer=False)  # bare form explicitly False
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            ":test").get(self.channel).setValue(True)
        self._seed_usable()
        self.assertTrue(self._plugin.x_enforcement_available(self.irc, self.channel))

    def _seed_usable(self):
        from plugins.UndernetX.xprobe import ProbeVerdict
        self._plugin._capabilities.record(
            "test", ircutils.toLower(self.channel),
            ProbeVerdict(state="usable", access_level=500), [],
        )

    # ---- enforce_ban_via_x / unban_via_x ----

    def test_enforce_ban_via_x_queues_ban_then_kick(self):
        self._arm()
        self._seed_usable()
        result = self._plugin.enforce_ban_via_x(
            self.irc, self.channel, "spammer", "*!*@1.2.3.4", "spamming", duration_secs=3600)
        self.assertTrue(result)
        ban = self.irc.takeMsg()
        kick = self.irc.takeMsg()
        self.assertEqual(ban.args[1], f"BAN {self.channel} *!*@1.2.3.4 60m 0 spamming")
        self.assertEqual(kick.args[1], f"KICK {self.channel} spammer spamming")

    def test_enforce_ban_via_x_with_no_cache_entry_queues_no_ban_or_kick(self):
        # The gate cannot be bypassed -- a caller holding a stale
        # reference or skipping x_enforcement_available itself still
        # gets re-checked inside enforce_ban_via_x, which returns False.
        # That recheck legitimately queues a lazy availability PROBE as
        # an honest side effect (same as x_enforcement_available called
        # directly would) -- what must NEVER happen is an actual BAN/
        # KICK being sent without a confirmed-usable cache entry.
        self._arm()
        result = self._plugin.enforce_ban_via_x(
            self.irc, self.channel, "spammer", "*!*@1.2.3.4", "spamming")
        self.assertFalse(result)
        queued = [self.irc.takeMsg()]
        while queued[-1] is not None:
            queued.append(self.irc.takeMsg())
        queued = [m for m in queued if m is not None]
        self.assertEqual(
            [m for m in queued if m.args[1].startswith(("BAN ", "KICK "))], [])

    def test_denial_reply_after_enforcement_demotes_the_cache(self):
        from plugins.UndernetX import xprobe
        self._arm()
        self._seed_usable()
        self._plugin.enforce_ban_via_x(
            self.irc, self.channel, "spammer", "*!*@1.2.3.4", "spamming", duration_secs=3600)
        self.irc.takeMsg()  # BAN
        self.irc.takeMsg()  # KICK
        self._feed_x_notice("You lack enough access.")  # answers the BAN's own correlation
        entry = self._plugin._capabilities.get("test", ircutils.toLower(self.channel))
        self.assertEqual(entry.state, xprobe.UNUSABLE)

    def test_unban_via_x_works_even_after_cache_demotion(self):
        self._arm()
        self._seed_usable()
        self._plugin._capabilities.invalidate("test", ircutils.toLower(self.channel))
        result = self._plugin.unban_via_x(self.irc, self.channel, "*!*@1.2.3.4")
        self.assertTrue(result)
        sent = self.irc.takeMsg()
        self.assertEqual(sent.args[1], f"UNBAN {self.channel} *!*@1.2.3.4")

    # ---- doJoin-triggered probing ----

    def _feed_join(self, nick):
        from supybot import ircmsgs
        # feedMsg (not calling doJoin directly) matters here: IrcMsg's
        # own `.channel` attribute is only ever set by irclib.py's real
        # dispatch path (irclib.py:1642, msg.channel = channel) -- a
        # bare IrcMsg's __getattr__ returns None for anything not
        # explicitly set, so a direct doJoin(irc, msg) call would see
        # msg.channel is None and silently no-op every gate that reads
        # it. Every other plugin's own JOIN-simulating test helper in
        # this repo (Shild's _make_join, SpamGuard's _join) already goes
        # through feedMsg for exactly this reason.
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=(self.channel,),
            prefix=ircutils.joinHostmask(nick, "shild", "bot.example"),
        ))

    def test_own_join_to_opted_in_channel_schedules_a_probe(self):
        self._arm()
        before = len(self._plugin._scheduled_probe_events)
        self._feed_join(self.nick)
        self.assertGreater(len(self._plugin._scheduled_probe_events), before)

    def test_own_join_to_non_opted_in_channel_schedules_nothing(self):
        self._arm(prefer=False)
        before = len(self._plugin._scheduled_probe_events)
        self._feed_join(self.nick)
        self.assertEqual(len(self._plugin._scheduled_probe_events), before)

    def test_other_nicks_join_is_ignored(self):
        self._arm()
        before = len(self._plugin._scheduled_probe_events)
        self._feed_join("someoneelse")
        self.assertEqual(len(self._plugin._scheduled_probe_events), before)

    # ---- login success clears the capability cache ----

    def test_fresh_login_success_clears_the_capability_cache(self):
        self._arm()
        self._seed_usable()
        self.assertTrue(self._plugin._capabilities.is_usable(
            "test", ircutils.toLower(self.channel), ttl=3600))
        self._plugin.identified = False  # simulate "not yet identified this session"
        self._feed_x_notice("AUTHENTICATION SUCCESSFUL as shild")
        # A fresh identification clears every cached verdict on this
        # network -- old verdicts from a prior/no session are meaningless.
        self.assertIsNone(self._plugin._capabilities.get("test", ircutils.toLower(self.channel)))

    def test_relogin_while_already_identified_does_not_clear_the_cache(self):
        # was_identified True -> True is NOT a fresh identification, so
        # an already-logged-in bot's cached verdicts survive an
        # "already authenticated" reply (e.g. a stray duplicate login
        # attempt) rather than being wiped for no reason.
        self._arm()
        self._seed_usable()
        self._plugin.identified = True
        self._feed_x_notice("Sorry, You are already authenticated as shild")
        self.assertIsNotNone(self._plugin._capabilities.get("test", ircutils.toLower(self.channel)))
