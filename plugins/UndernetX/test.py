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
