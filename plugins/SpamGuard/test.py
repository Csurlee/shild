"""Limnoria PluginTestCase tests for SpamGuard.

Covers the full gate chain (match -> join window (content only) ->
exemption -> killSwitch -> op) end to end via feedMsg, for all four
matchable fields (content, ident, nick, realname), the id-keyed term
store (add/remove/search, all five categories including "pattern"), and
the owner-only command gate. Pure matcher/term-store logic is tested
separately and without the plugin harness at all in
tests/test_spamguard_matcher.py and tests/test_spamguard_terms.py;
enforcement.py's IRC-mechanics functions have their own
tests/test_spamguard_enforcement.py, mirroring tests/test_enforcement.py's
approach for Shild's equivalent module.
"""
import json
import tempfile
from pathlib import Path

import supybot.conf as conf
import supybot.ircdb as ircdb
import supybot.ircmsgs as ircmsgs
import supybot.ircutils as ircutils
from supybot.test import ChannelPluginTestCase


class SpamGuardTestCase(ChannelPluginTestCase):
    plugins = ("SpamGuard",)

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._log_path = str(Path(self._tmpdir) / "spamguard_actions.jsonl")
        self._terms_path = str(Path(self._tmpdir) / "spamguard_terms.json")
        conf.supybot.plugins.SpamGuard.logPath.setValue(self._log_path)
        # A fresh, empty, per-test terms file -- never the real
        # runtime/data/spamguard_terms.json -- so tests never read or
        # write real live term data, and each test starts from zero
        # terms regardless of what earlier tests added.
        conf.supybot.plugins.SpamGuard.termsPath.setValue(self._terms_path)
        conf.supybot.plugins.SpamGuard.enabled.get(self.channel).setValue(True)
        # Cross-test state-leak gotcha (same class already documented
        # elsewhere for Shild's ignoreList/UndernetX's auth.username --
        # any value set directly via .setValue() in a test body, channel-
        # scoped or not, is NOT covered by PluginTestCase's automatic
        # config-dict restore): a heuristic left "on" by one test would
        # otherwise leak into every later test in the same process. Reset
        # explicitly here; each heuristic test enables only what it needs.
        for name in ("floodEnabled", "hilightEnabled", "capsEnabled", "mojibakeEnabled",
                     "raidEnabled"):
            getattr(conf.supybot.plugins.SpamGuard, name).get(self.channel).setValue(False)
        # hostBanAutoRebanEnabled (2026-08-22) is global, not channel-
        # scoped -- same cross-test state-leak risk as everything else
        # in this list. Off by default; each host-ban test flips it
        # explicitly.
        conf.supybot.plugins.SpamGuard.hostBanAutoRebanEnabled.setValue(False)
        self._host_bans_path = str(Path(self._tmpdir) / "spamguard_host_bans.json")
        conf.supybot.plugins.SpamGuard.hostBansPath.setValue(self._host_bans_path)
        # Protection defaults to safe (killSwitch=True) -- each
        # enforcement test below flips it explicitly, same convention as
        # Shild's own test.py, so the test itself documents the state it
        # needs rather than relying on a shared setUp default.
        super().setUp()

        u = ircdb.users.newUser()
        u.name = "test-owner"
        u.addCapability("owner")
        u.addHostmask(self.prefix)
        ircdb.users.setUser(u)

        # The running plugin instance's TermStore was constructed
        # against termsPath at __init__ time (super().setUp() above),
        # empty at that point -- seed the one term most of the gate-chain
        # tests below rely on directly through the store, then rebuild
        # the matchers the same way `spamguard word add` does live.
        self._plugin = self.irc.getCallback("SpamGuard")
        self._czura_term = self._plugin._terms.add("word", "Czura")
        self._plugin._rebuild_matchers()

    # __no_testcap__ is required in the host part of any identity that a
    # test expects to be treated as a REAL non-exempt spammer: ircdb's own
    # checkCapability() short-circuits to True for every capability under
    # world.testing unless the hostmask's host part contains this literal
    # marker (confirmed in ircdb.py, same convention plugins/Shild/test.py
    # uses) -- without it, _is_exempt()'s channel-op-capability check
    # would treat every simulated user as exempt regardless of the
    # scenario under test.
    _DEFAULT_HOST = "203.0.113.99__no_testcap__"

    def _spam_msg(self, nick="primaryocelo", ident="~ocelo", host=_DEFAULT_HOST):
        return ircmsgs.privmsg(
            self.channel,
            "Hi Guys! It's Madeleine Czura! Just thought I'd leave my number here.",
            prefix=f"{nick}!{ident}@{host}",
        )

    def _join(self, nick="primaryocelo", ident="~ocelo", host=_DEFAULT_HOST, realname=None):
        """realname=<str> simulates a server that negotiated IRCv3
        extended-join (JOIN args become (channel, account, realname));
        realname=None simulates a plain JOIN (bare (channel,) args) --
        i.e. a server WITHOUT extended-join, the realistic Undernet case.
        """
        args = (self.channel,) if realname is None else (self.channel, "*", realname)
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=args, prefix=f"{nick}!{ident}@{host}",
        ))

    def _grant_op(self, channel):
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="MODE", args=(channel, "+o", self.irc.nick),
            prefix="ChanServ!ChanServ@services.",
        ))

    def _queued(self):
        q = self.irc.queue
        return list(q.highpriority) + list(q.normal) + list(q.lowpriority)

    def _log_records(self):
        if not Path(self._log_path).exists():
            return []
        return [json.loads(line) for line in Path(self._log_path).read_text().strip().splitlines()]

    # ---- migration (2026-08-11) ----

    def test_migration_skips_whitespace_only_legacy_entries(self):
        """Real, confirmed-live corruption: a legacy registry list whose
        raw stored value was a single space parses (via
        CommaSeparatedListOfStrings.splitter) into [" "] -- one
        non-empty-but-blank entry. `if text:` alone doesn't catch this
        (a single space is truthy); must never become a real term --
        re.escape(" ") or a raw " " regex both match almost any real
        chat message once compiled."""
        from plugins.SpamGuard.plugin import SpamGuard as SpamGuardClass

        conf.supybot.plugins.SpamGuard.phrases.setValue([" ", "real phrase"])
        conf.supybot.plugins.SpamGuard.patterns.setValue([" "])
        conf.supybot.plugins.SpamGuard.termsPath.setValue(
            str(Path(self._tmpdir) / "fresh_terms.json"))
        try:
            fresh = SpamGuardClass(self.irc)
            texts = [t.text for t in fresh._terms.all()]
            self.assertIn("real phrase", texts)
            self.assertNotIn(" ", texts)
        finally:
            conf.supybot.plugins.SpamGuard.phrases.setValue([])
            conf.supybot.plugins.SpamGuard.patterns.setValue([])
            conf.supybot.plugins.SpamGuard.termsPath.setValue(self._terms_path)

    # ---- full gate chain: content ----

    def test_enforces_when_matched_within_window_not_exempt_opped_killswitch_off(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 1, "expected a real KICK")
        self.assertEqual(len(bans), 1, "expected a real MODE +b")
        self.assertEqual(kicks[0].args[1], "primaryocelo")
        # Default test ident "~ocelo" is unverified, so the host fallback
        # is narrowed to *!~*@host, not the old unconditional *!*@host
        # (2026-08-22) -- see test_content_match_with_verified_ident_gets_full_host_mask
        # below for the verified-ident case.
        self.assertEqual(bans[0].args[2], f"*!~*@{self._DEFAULT_HOST}")

        records = self._log_records()
        self.assertEqual(records[-1]["outcome"], "enforced")
        self.assertEqual(records[-1]["field"], "content")
        self.assertEqual(records[-1]["term"].lower(), "czura")
        self.assertEqual(records[-1]["term_id"], self._czura_term.id)

    def test_kick_reason_includes_term_hostmask_reason_and_permanent_id(self):
        """2026-08-10/2026-08-13: the kick message must show the quoted
        term, the actual connecting hostmask (nick!ident@host -- NOT the
        ban mask, which can now differ from it for an ident-field match),
        a reason, and the term's permanent id, mirroring Armour/idefix's
        own "(reason: ...) [id: N]" convention."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.protection.kickReason.setValue("You are not welcome here!")
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        kicks = [m for m in self._queued() if m.command == "KICK"]
        reason = kicks[0].args[2]
        self.assertIn('"Czura"', reason)
        self.assertIn(f"primaryocelo!~ocelo@{self._DEFAULT_HOST}", reason)
        self.assertIn("reason: You are not welcome here!", reason)
        self.assertIn(f"[id: {self._czura_term.id}]", reason)

    def test_kick_reason_substitutes_term_placeholder(self):
        """{term} in a configured kickReason is substituted with the
        matched term's text, not shown literally -- the exact bug found
        live 2026-08-13 (a configured value of "SpamGuard: {term}"
        rendered the literal, unsubstituted string)."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.protection.kickReason.setValue("Blacklisted: {term}")
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        reason = [m for m in self._queued() if m.command == "KICK"][0].args[2]
        self.assertIn("reason: Blacklisted: Czura", reason)
        self.assertNotIn("{term}", reason)

    def test_kick_reason_falls_back_to_raw_value_on_malformed_placeholder(self):
        """A stray '{' that isn't the real {term} placeholder must never
        crash enforcement -- falls back to the raw configured string."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.protection.kickReason.setValue("Bad { config")
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "a malformed kickReason must not block enforcement")
        self.assertIn("reason: Bad { config", kicks[0].args[2])

    def test_matched_but_killswitch_on_does_not_enforce(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)  # explicit, matches default
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "killswitch")

    def test_matched_but_not_opped_does_not_enforce(self):
        # This class (SpamGuardTestCase, plugins=("SpamGuard",)) doubles
        # as the "UndernetX not loaded at all" proof for the 2026-08-16
        # X-routed enforcement fallback -- irc.getCallback("UndernetX")
        # returns None here unconditionally, so _x_fallback() always
        # returns None too, and behavior is exactly what it was before
        # that feature existed. See SpamGuardXFallbackTestCase (below,
        # plugins=("SpamGuard", "UndernetX")) for the cases where
        # UndernetX IS loaded.
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        # Deliberately NOT granting op.
        self._join()
        self.irc.feedMsg(self._spam_msg())

        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "not-opped")

    def test_matched_outside_join_window_does_not_enforce(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.joinWindowSecs.setValue(60)
        self._grant_op(self.channel)
        # No join tracked at all for this nick -- equivalent to a join
        # that happened long before the window.
        self.irc.feedMsg(self._spam_msg())

        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "outside-window")

    def test_matched_but_registered_user_is_exempt(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        # Marker included so the ONLY reason this is exempt is genuine
        # ircdb registration (exemptRegistered), not the world.testing
        # checkCapability short-circuit -- see _DEFAULT_HOST's docstring.
        nick, ident, host = "regular", "~reg", "203.0.113.20__no_testcap__"
        prefix = f"{nick}!{ident}@{host}"
        u = ircdb.users.newUser()
        u.name = "a-regular"
        u.addHostmask(prefix)
        ircdb.users.setUser(u)

        self._join(nick, ident, host)
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "lol did you see that Czura spam earlier", prefix=prefix,
        ))

        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "exempt")

    def test_matched_but_halfop_plus_is_exempt(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        # A DIFFERENT nick from self.nick/self.prefix -- the test bot's own
        # nick is "test" (PluginTestCase's default), same as self.nick, so
        # using self.prefix here would collide with doPrivmsg's own
        # `msg.nick == irc.nick` guard and never even reach the matcher.
        nick, ident, host = "vipuser", "~vip", "203.0.113.21__no_testcap__"
        self._join(nick, ident, host)
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="MODE", args=(self.channel, "+o", nick),
            prefix="ChanServ!ChanServ@services.",
        ))
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "Czura", prefix=f"{nick}!{ident}@{host}",
        ))

        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "exempt")

    def test_non_matching_message_is_ignored_entirely(self):
        self._join()
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "hey everyone, nice weather today",
            prefix="primaryocelo!~ocelo@192.0.2.1",
        ))
        self.assertEqual(self._log_records(), [])

    def test_disabled_channel_ignores_everything(self):
        conf.supybot.plugins.SpamGuard.enabled.get(self.channel).setValue(False)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        self.assertEqual(self._log_records(), [])

    def test_content_match_with_verified_ident_gets_full_host_mask(self):
        """2026-08-22: a REAL ident server response (no leading '~') means
        a person actually spammed right now with a real ident -- ban them
        normally, full host wildcard, same as before the ident-aware mask
        feature existed."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join("primaryocelo", "ocelo", self._DEFAULT_HOST)  # no leading '~'
        self.irc.feedMsg(self._spam_msg(ident="ocelo"))

        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(bans[0].args[2], f"*!*@{self._DEFAULT_HOST}")

    # ---- persisted host-ban history (2026-08-22) ----

    def test_host_based_enforcement_records_a_host_ban(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        records = self._plugin._host_bans.all()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.host, self._DEFAULT_HOST)
        self.assertEqual(record.field, "content")
        self.assertEqual(record.term_text.lower(), "czura")
        self.assertIn('"Czura"', record.kick_reason)
        self.assertEqual(record.hit_count, 1)

    def test_ident_field_match_never_records_a_host_ban(self):
        """Scope check: only host-fallback-masked enforcement records --
        ident/nick matches already target something narrower and more
        durable than a host."""
        self._plugin._terms.add("ident", "badident")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join("spammer", "badident", self._DEFAULT_HOST)

        self.assertEqual(len(self._plugin._host_bans), 0)

    def test_rejoin_with_unverified_ident_auto_rebans_with_original_message(self):
        """The core feature: a rejoin from a previously-convicted host,
        under an entirely different nick, with unverified ident, is
        auto-rebanned using the EXACT original kick message -- no fresh
        term match involved at all."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.hostBanAutoRebanEnabled.setValue(True)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        original_reason = [m for m in self._queued() if m.command == "KICK"][0].args[2]

        # A totally different identity, same host, still unverified ident.
        self._join("brandnewnick", "~different", self._DEFAULT_HOST)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 2, "the rejoin must trigger a second real kick")
        self.assertEqual(kicks[1].args[1], "brandnewnick")
        self.assertEqual(kicks[1].args[2], original_reason, "must reuse the FIRST kick message verbatim")
        self.assertEqual(bans[1].args[2], f"*!~*@{self._DEFAULT_HOST}")
        self.assertEqual(self._log_records()[-1]["field"], "host_history")

    def test_rejoin_with_verified_ident_is_not_auto_rebanned(self):
        """A rejoin from a known-bad host with a REAL ident server is left
        alone entirely -- no evidence they're the same actor."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.hostBanAutoRebanEnabled.setValue(True)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        self._join("legituser", "realident", self._DEFAULT_HOST)  # no leading '~'

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "only the original offender was kicked, not the rejoin")

    def test_auto_reban_toggle_off_by_default_does_not_reban(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        # hostBanAutoRebanEnabled deliberately left at its default (False).
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        self._join("brandnewnick", "~different", self._DEFAULT_HOST)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "recording happens, but no auto-reban without the toggle")

    def test_reban_does_not_overwrite_stored_kick_reason(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.hostBanAutoRebanEnabled.setValue(True)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        self._join("second", "~x", self._DEFAULT_HOST)
        self._join("third", "~y", self._DEFAULT_HOST)

        records = self._plugin._host_bans.all()
        self.assertEqual(len(records), 1)
        self.assertIn('"Czura"', records[0].kick_reason)
        self.assertEqual(records[0].hit_count, 3)

    def test_reban_still_respects_killswitch(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.hostBanAutoRebanEnabled.setValue(True)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)
        self._join("brandnewnick", "~different", self._DEFAULT_HOST)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "the reban itself must still honor the kill switch")
        self.assertEqual(self._log_records()[-1]["outcome"], "killswitch")

    def test_reban_still_respects_exemption(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        conf.supybot.plugins.SpamGuard.hostBanAutoRebanEnabled.setValue(True)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())

        nick, ident, host = "regular", "~different", self._DEFAULT_HOST
        prefix = f"{nick}!{ident}@{host}"
        u = ircdb.users.newUser()
        u.name = "a-regular-on-the-same-host"
        u.addHostmask(prefix)
        ircdb.users.setUser(u)

        self._join(nick, ident, host)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "a registered user on the same host is still exempt")

    def test_spamguardhostbans_lists_records(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        # Drain the enforcement's own queued KICK/MODE +b first -- getMsg's
        # internal takeMsg() would otherwise return one of THOSE instead
        # of the command's actual reply (same gotcha already documented
        # in CLAUDE.md for a similar mixed enforcement+command test).
        while self.irc.takeMsg():
            pass

        reply = self.getMsg("spamguardhostbans").args[1]
        self.assertIn(self._DEFAULT_HOST, reply)
        self.assertIn("content", reply)

    def test_spamguardhostbans_requires_owner_capability(self):
        self._assert_denied_owner_capability("spamguardhostbans")

    def test_spamguardhostbansremove_removes_and_replies(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        while self.irc.takeMsg():  # drain the enforcement's own queued KICK/MODE +b
            pass

        reply = self.getMsg(f"spamguardhostbansremove {self._DEFAULT_HOST}")
        self.assertIn("removed", reply.args[1].lower())
        self.assertEqual(len(self._plugin._host_bans), 0)

    def test_spamguardhostbansremove_unknown_host_errors(self):
        reply = self.getMsg("spamguardhostbansremove 9.9.9.9__not_real__")
        self.assertIn("no host-ban", reply.args[1].lower())

    # ---- full gate chain: ident (checked at JOIN, no join-window concept) ----

    def test_bad_ident_enforces_at_join_with_killswitch_off_and_opped(self):
        self._plugin._terms.add("ident", "badident")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("spammer", "~badident", self._DEFAULT_HOST)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 1, "bad ident must enforce immediately at join")
        self.assertEqual(len(bans), 1)
        # 2026-08-13: an ident match bans by IDENT, not host -- the whole
        # point is to catch this same ident reconnecting from a different
        # IP. A host-based mask here would have let it right back in.
        self.assertEqual(bans[0].args[2], "*!~badident@*")
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "ident")
        self.assertEqual(records[-1]["outcome"], "enforced")

    def test_bad_ident_not_enforced_when_killswitch_on(self):
        self._plugin._terms.add("ident", "badident")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)
        self._grant_op(self.channel)

        self._join("spammer", "~badident", self._DEFAULT_HOST)

        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "killswitch")

    def test_clean_ident_at_join_is_ignored(self):
        self._plugin._terms.add("ident", "badident")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("regular", "~normal", self._DEFAULT_HOST)

        self.assertEqual(self._log_records(), [])

    # ---- full gate chain: nick (checked at JOIN, before ident/realname) ----

    def test_bad_nick_enforces_at_join_with_killswitch_off_and_opped(self):
        self._plugin._terms.add("nick", "badbot")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("badbot", "~x", self._DEFAULT_HOST)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 1, "bad nick must enforce immediately at join")
        self.assertEqual(len(bans), 1)
        # 2026-08-13: a nick match bans by NICK, not host -- mirrors the
        # ident-field fix the same day.
        self.assertEqual(bans[0].args[2], "badbot!*@*")
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "nick")
        self.assertEqual(records[-1]["outcome"], "enforced")

    def test_bad_nick_not_enforced_when_killswitch_on(self):
        self._plugin._terms.add("nick", "badbot")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)
        self._grant_op(self.channel)

        self._join("badbot", "~x", self._DEFAULT_HOST)

        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "killswitch")

    def test_clean_nick_at_join_is_ignored(self):
        self._plugin._terms.add("nick", "badbot")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("regular", "~normal", self._DEFAULT_HOST)

        self.assertEqual(self._log_records(), [])

    def test_nick_match_checked_before_ident_one_match_is_enough(self):
        """If a nick AND an ident term would both match the same join,
        only nick is checked/acted on/logged -- one enforcement action
        per join, not two (mirrors the existing ident-before-realname
        precedent)."""
        self._plugin._terms.add("nick", "badbot")
        self._plugin._terms.add("ident", "badbot")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("badbot", "~badbot", self._DEFAULT_HOST)

        self.assertEqual(len(self._log_records()), 1)
        self.assertEqual(self._log_records()[0]["field"], "nick")

    # ---- full gate chain: realname (extended-join only) ----

    def test_bad_realname_enforces_at_join_when_extended_join_active(self):
        self._plugin._terms.add("realname_word", "spammer")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("newuser", "~x", self._DEFAULT_HOST, realname="Definitely A Spammer")

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 1, "bad realname must enforce immediately at join")
        # realname has no mask field of its own (IRC masks are strictly
        # nick!ident@host) -- falls back to host, unlike an ident match.
        # "~x" is unverified, so the host fallback is narrowed (2026-08-22).
        self.assertEqual(bans[0].args[2], f"*!~*@{self._DEFAULT_HOST}")
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "realname")
        self.assertEqual(records[-1]["term"].lower(), "spammer")

    def test_realname_never_checked_without_extended_join(self):
        """A plain JOIN (no extended-join negotiated -- realistic for a
        server like Undernet that may not support it) has only ONE arg
        (channel). realname must silently never be checked, not error."""
        self._plugin._terms.add("realname_word", "spammer")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("newuser", "~x", self._DEFAULT_HOST, realname=None)

        self.assertEqual(self._log_records(), [])

    def test_bad_ident_checked_before_realname_one_match_is_enough(self):
        """If ident already matched, realname isn't also separately
        checked/logged -- one enforcement action per join, not two."""
        self._plugin._terms.add("ident", "badident")
        self._plugin._terms.add("realname_word", "alsospam")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self._join("spammer", "~badident", self._DEFAULT_HOST, realname="alsospam here too")

        self.assertEqual(len(self._log_records()), 1)
        self.assertEqual(self._log_records()[0]["field"], "ident")

    # ---- content patterns (raw regex category) ----

    def test_pattern_matches_and_enforces(self):
        self._plugin._terms.add("pattern", r"It's [A-Z][a-z]+ [A-Z][a-z]+!")
        self._plugin._rebuild_matchers()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        host = "198.51.100.9__no_testcap__"
        self._join("otherspammer", "~x", host)
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "It's Random Person! check me out",
            prefix=f"otherspammer!~x@{host}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)
        self.assertEqual(self._log_records()[-1]["field"], "content")

    # ---- spamguard <category> add/remove ----

    def test_add_word_assigns_id_and_takes_effect_immediately(self):
        m = self.getMsg("spamguard word add lonelyheart")
        self.assertIn("added [id:", m.args[1])
        entry = self._plugin._terms.find_by_text("word", "lonelyheart")
        self.assertIsNotNone(entry)

        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        host = "198.51.100.5__no_testcap__"
        self._join("newspammer", "~x", host)
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "ask me about lonelyheart deals",
            prefix=f"newspammer!~x@{host}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "newly-added word must take effect immediately")

        # Not asserting on getMsg's return value here -- the enforcement
        # above already left an unconsumed KICK/MODE pair in the queue,
        # so the very next takeMsg() (which getMsg uses internally)
        # would surface one of those instead of this command's own
        # reply. Check the term store's actual state directly instead,
        # same as the other add/remove tests below that don't have this
        # leftover-queue complication.
        self.getMsg("spamguard word remove lonelyheart")
        self.assertIsNone(self._plugin._terms.find_by_text("word", "lonelyheart"))

    def test_add_phrase_with_space_stored_as_phrase_category(self):
        self.getMsg('spamguard word add "lonely tonight"')
        self.assertIsNotNone(self._plugin._terms.find_by_text("phrase", "lonely tonight"))
        self.assertIsNone(self._plugin._terms.find_by_text("word", "lonely tonight"))

    def test_add_ident_takes_effect_immediately(self):
        self.getMsg("spamguard ident add scriptbot")
        self.assertIsNotNone(self._plugin._terms.find_by_text("ident", "scriptbot"))

        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join("newuser", "~scriptbot", self._DEFAULT_HOST)
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "newly-added ident term must take effect immediately")

    def test_add_realname_phrase_takes_effect_immediately(self):
        self.getMsg('spamguard realname add "totally a bot"')
        self.assertIsNotNone(self._plugin._terms.find_by_text("realname_phrase", "totally a bot"))

        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join("newuser", "~x", self._DEFAULT_HOST, realname="totally a bot, honest")
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "newly-added realname phrase must take effect immediately")

    def test_add_valid_pattern_is_accepted(self):
        m = self.getMsg('spamguard pattern add "Hi [A-Z][a-z]+!"')
        self.assertIn("added [id:", m.args[1])
        entries = self._plugin._terms.by_category("pattern")
        self.assertEqual(len(entries), 1)

    def test_add_invalid_pattern_is_rejected_not_stored(self):
        # No square brackets in the invalid regex -- supybot's own
        # command parser treats unescaped "[...]" as nested-command
        # syntax and errors out before this ever reaches the plugin.
        m = self.getMsg("spamguard pattern add (unclosed")
        self.assertIn("invalid regex", m.args[1])
        self.assertEqual(self._plugin._terms.by_category("pattern"), [])

    def test_add_duplicate_term_does_not_create_a_second_id(self):
        self.getMsg("spamguard word add lonelyheart")
        m2 = self.getMsg("spamguard word add lonelyheart")
        self.assertIn("already present", m2.args[1])
        self.assertEqual(
            len([t for t in self._plugin._terms.by_category("word") if t.text == "lonelyheart"]),
            1,
        )

    def test_remove_unknown_term_reports_not_found(self):
        m = self.getMsg("spamguard word remove neverexisted")
        self.assertIn("not found", m.args[1])

    def test_spamguard_add_requires_a_term(self):
        m = self.getMsg("spamguard word add")
        self.assertIn("Error", m.args[1])

    # ---- spamguardlist ----

    def test_spamguardlist_shows_ids_across_all_categories(self):
        self.getMsg("spamguard ident add scriptbot")
        self.getMsg('spamguard realname add "totally a bot"')

        m = self.getMsg("spamguardlist")
        self.assertIn(f"[id:{self._czura_term.id}]", m.args[1])
        self.assertIn("Czura", m.args[1])  # content words, seeded in setUp
        m2 = self.irc.takeMsg()  # content phrases
        self.assertIsNotNone(m2)
        m3 = self.irc.takeMsg()  # content patterns
        self.assertIsNotNone(m3)
        m4 = self.irc.takeMsg()
        self.assertIn("scriptbot", m4.args[1])  # idents
        m5 = self.irc.takeMsg()  # nicks
        self.assertIsNotNone(m5)
        m6 = self.irc.takeMsg()  # realname words
        self.assertIsNotNone(m6)
        m7 = self.irc.takeMsg()
        self.assertIn("totally a bot", m7.args[1])  # realname phrases

    # ---- spamguardsearch / spamguardremove ----

    def test_spamguardsearch_by_exact_id(self):
        m = self.getMsg(f"spamguardsearch {self._czura_term.id}")
        self.assertIn("Czura", m.args[1])
        self.assertIn(f"[id:{self._czura_term.id}]", m.args[1])

    def test_spamguardsearch_by_text_substring(self):
        m = self.getMsg("spamguardsearch czu")
        self.assertIn("Czura", m.args[1])

    def test_spamguardsearch_no_match_says_so(self):
        m = self.getMsg("spamguardsearch nothing-like-this-exists")
        self.assertIn("No terms matching", m.args[1])

    def test_spamguardremove_by_id_works_and_takes_effect(self):
        m = self.getMsg(f"spamguardremove {self._czura_term.id}")
        self.assertIn(f"[id:{self._czura_term.id}]", m.args[1])
        self.assertIsNone(self._plugin._terms.get(self._czura_term.id))

        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [],
                          "removed term must stop matching immediately")

    def test_spamguardremove_unknown_id_errors(self):
        m = self.getMsg("spamguardremove 999999")
        self.assertIn("Error", m.args[1])

    # ---- message heuristics (2026-08-14): flood, hilight, caps, mojibake ----

    def test_flood_enforces_after_limit_reached(self):
        conf.supybot.plugins.SpamGuard.floodEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        limit = conf.supybot.plugins.SpamGuard.floodMessageLimit()
        for i in range(limit):
            self.irc.feedMsg(ircmsgs.privmsg(
                self.channel, f"just chatting {i}",
                prefix=f"flooder!~flood@{self._DEFAULT_HOST}",
            ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "expected exactly one enforcement at the limit")
        records = self._log_records()
        self.assertEqual(records[-1]["outcome"], "enforced")
        self.assertEqual(records[-1]["field"], "flood")
        self.assertEqual(records[-1]["term_id"], -1)

    def test_flood_below_limit_does_not_enforce(self):
        conf.supybot.plugins.SpamGuard.floodEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        limit = conf.supybot.plugins.SpamGuard.floodMessageLimit()
        for i in range(limit - 1):
            self.irc.feedMsg(ircmsgs.privmsg(
                self.channel, f"just chatting {i}",
                prefix=f"flooder!~flood@{self._DEFAULT_HOST}",
            ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_flood_disabled_by_default_never_enforces(self):
        """floodEnabled defaults False -- opt-in per channel, same safety
        posture as every other heuristic here."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        for i in range(20):
            self.irc.feedMsg(ircmsgs.privmsg(
                self.channel, f"just chatting {i}",
                prefix=f"flooder!~flood@{self._DEFAULT_HOST}",
            ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_flood_enforces_without_any_prior_tracked_join(self):
        """Unlike content matching, none of the four heuristics require
        the join window -- no self._join() call here at all."""
        conf.supybot.plugins.SpamGuard.floodEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        limit = conf.supybot.plugins.SpamGuard.floodMessageLimit()
        for i in range(limit):
            self.irc.feedMsg(ircmsgs.privmsg(
                self.channel, f"chat {i}",
                prefix=f"neverjoined!~x@{self._DEFAULT_HOST}",
            ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)

    def test_hilight_enforces_on_mass_nick_highlight(self):
        conf.supybot.plugins.SpamGuard.hilightEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        for nick in ("Alice", "Bob", "Carol", "Dave"):
            self._join(nick=nick, ident="~u", host=f"{nick.lower()}.example.net")
        text = "hey Alice Bob Carol Dave check this out!!!"
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, text, prefix=f"raider!~r@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "hilight")
        self.assertEqual(records[-1]["term_id"], -2)

    def test_hilight_below_limit_does_not_enforce(self):
        conf.supybot.plugins.SpamGuard.hilightEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        for nick in ("Alice", "Bob", "Carol"):
            self._join(nick=nick, ident="~u", host=f"{nick.lower()}.example.net")
        text = "hey Alice Bob Carol, how's it going"
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, text, prefix=f"chatter!~c@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [], "only 3 nicks named, below the default limit of 4")

    def test_hilight_excludes_the_sender_from_the_count(self):
        conf.supybot.plugins.SpamGuard.hilightEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        for nick in ("Alice", "Bob", "Carol"):
            self._join(nick=nick, ident="~u", host=f"{nick.lower()}.example.net")
        self._join(nick="Raider", ident="~r", host=self._DEFAULT_HOST)
        text = "Raider here with Alice Bob Carol"
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, text, prefix=f"Raider!~r@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [], "only 3 OTHER nicks named, below the default limit of 4")

    def test_caps_enforces_on_excessive_uppercase(self):
        conf.supybot.plugins.SpamGuard.capsEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "THIS IS A VERY LOUD MESSAGE INDEED",
            prefix=f"shouter!~s@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "caps")
        self.assertEqual(records[-1]["term_id"], -3)

    def test_caps_below_min_length_never_triggers(self):
        conf.supybot.plugins.SpamGuard.capsEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "OK", prefix=f"shouter!~s@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_caps_mixed_case_below_threshold_does_not_enforce(self):
        conf.supybot.plugins.SpamGuard.capsEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "This is a Normal sentence with some Caps here and there",
            prefix=f"chatter!~c@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_mojibake_enforces_on_garbled_text(self):
        conf.supybot.plugins.SpamGuard.mojibakeEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        garbled = "This is â€œgarbledâ€� text right here for real"
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, garbled, prefix=f"spammer!~s@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "mojibake")
        self.assertEqual(records[-1]["term_id"], -4)

    def test_mojibake_clean_text_never_enforces(self):
        conf.supybot.plugins.SpamGuard.mojibakeEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "This is a perfectly normal message with no issues at all",
            prefix=f"chatter!~c@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_content_match_takes_priority_over_heuristics(self):
        """A message matching BOTH a content term AND a heuristic (all
        caps here) must be logged/enforced as "content", never a
        heuristic field -- content matching is checked first in
        doPrivmsg, before _check_heuristics is ever called."""
        conf.supybot.plugins.SpamGuard.capsEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join()
        self.irc.feedMsg(ircmsgs.privmsg(
            self.channel, "IT'S MADELEINE CZURA CALLING YOU RIGHT NOW",
            prefix=f"primaryocelo!~ocelo@{self._DEFAULT_HOST}",
        ))
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "content")

    def test_spamguardstatus_shows_heuristic_state_in_channel(self):
        conf.supybot.plugins.SpamGuard.floodEnabled.get(self.channel).setValue(True)
        self.getMsg("spamguardstatus")
        m2 = self.irc.takeMsg()
        self.assertIsNotNone(m2, "expected a second line with per-heuristic state")
        self.assertIn("flood=on", m2.args[1])
        self.assertIn("hilight=off", m2.args[1])
        self.assertIn("caps=off", m2.args[1])
        self.assertIn("mojibake=off", m2.args[1])
        self.assertIn("raid=off", m2.args[1])

    # ---- raid (2026-08-16): distinct-nick join-burst detection ----

    def test_raid_enforces_after_distinct_join_limit_reached(self):
        conf.supybot.plugins.SpamGuard.raidEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        limit = conf.supybot.plugins.SpamGuard.raidJoinLimit()
        for i in range(limit - 1):
            self._join(nick=f"raider{i}", ident="~r", host=f"raider{i}.example.net")
        self._join(nick="tipper", ident="~r", host=self._DEFAULT_HOST)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "expected exactly one enforcement at the limit")
        self.assertEqual(kicks[0].args[1], "tipper",
                          "must act on the tipping-point joiner, not an earlier one")
        records = self._log_records()
        self.assertEqual(records[-1]["outcome"], "enforced")
        self.assertEqual(records[-1]["field"], "raid")
        self.assertEqual(records[-1]["term_id"], -5)

    def test_raid_below_limit_does_not_enforce(self):
        conf.supybot.plugins.SpamGuard.raidEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        limit = conf.supybot.plugins.SpamGuard.raidJoinLimit()
        for i in range(limit - 1):
            self._join(nick=f"raider{i}", ident="~r", host=f"raider{i}.example.net")

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_raid_disabled_by_default_never_enforces(self):
        """raidEnabled defaults False -- opt-in per channel, same safety
        posture as every other heuristic here."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        for i in range(20):
            self._join(nick=f"raider{i}", ident="~r", host=f"raider{i}.example.net")

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_raid_same_nick_rejoining_does_not_count_as_distinct(self):
        """A single nick joining/parting/rejoining repeatedly (a reconnect
        flap) must never look like a raid on its own -- only DISTINCT
        nicks count toward raidJoinLimit."""
        conf.supybot.plugins.SpamGuard.raidEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        limit = conf.supybot.plugins.SpamGuard.raidJoinLimit()
        for _ in range(limit + 5):
            self._join(nick="flapper", ident="~f", host=self._DEFAULT_HOST)

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_raid_resets_after_triggering_not_immediately_retriggered(self):
        """Same convention as the flood heuristic: once raidJoinLimit is
        reached and acted on, tracked state is cleared -- the very next
        join must not immediately trigger a second enforcement before a
        fresh window has genuinely built back up."""
        conf.supybot.plugins.SpamGuard.raidEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        limit = conf.supybot.plugins.SpamGuard.raidJoinLimit()
        for i in range(limit - 1):
            self._join(nick=f"raider{i}", ident="~r", host=f"raider{i}.example.net")
        self._join(nick="tipper", ident="~r", host=self._DEFAULT_HOST)
        self._join(nick="onemore", ident="~r", host=f"onemore.example.net{'__no_testcap__'}")

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1, "the join right after a trigger must not re-trigger")
        self.assertEqual(kicks[0].args[1], "tipper")

    # ---- black (2026-08-14): matches nick OR host, acts on future joins
    # AND immediately sweeps anyone already present ----

    def test_black_add_enforces_on_a_future_join_by_nick(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self.getMsg("spamguard black add badbot")

        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=(self.channel,),
            prefix=f"badbot!~x@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "black")
        self.assertEqual(records[-1]["term"], "badbot")

    def test_black_add_enforces_on_a_future_join_by_host(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self.getMsg(f"spamguard black add {self._DEFAULT_HOST}")

        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=(self.channel,),
            prefix=f"anynick!~x@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "black")

    def test_black_add_immediately_kicks_someone_already_in_the_channel(self):
        """The real point of "black" over "nick"/"ident": it acts on
        someone ALREADY present, not just future events.

        Note: the command's own reply is NOT necessarily the first
        message off the queue -- the sweep's real MODE+KICK get queued
        DURING the command handler, ahead of its own irc.reply() call at
        the end (same queue-ordering gotcha already documented for
        UndernetX's xsetpass tests) -- so check _queued() directly rather
        than assuming getMsg()'s return value is the command's reply."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join(nick="alreadyhere", ident="~x", host=self._DEFAULT_HOST)

        self.getMsg("spamguard black add alreadyhere")

        queued = self._queued()
        kicks = [m for m in queued if m.command == "KICK"]
        self.assertEqual(len(kicks), 1)
        self.assertEqual(kicks[0].args[1], "alreadyhere")

        replies = [m for m in queued if m.command in ("PRIVMSG", "NOTICE")
                   and len(m.args) > 1 and "kbanned" in m.args[1]]
        self.assertEqual(len(replies), 1, "expected the command's own reply to mention the sweep")
        self.assertIn("kbanned 1 already-present", replies[0].args[1])

        records = self._log_records()
        self.assertEqual(records[-1]["field"], "black")
        self.assertEqual(records[-1]["outcome"], "enforced")

    def test_black_add_sweep_respects_exemption(self):
        """An already-present halfop+ must not be swept, same exemption
        as any live match."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join(nick="halfopuser", ident="~x", host=self._DEFAULT_HOST)
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="MODE", args=(self.channel, "+h", "halfopuser"),
            prefix="ChanServ!ChanServ@services.",
        ))

        m = self.getMsg("spamguard black add halfopuser")
        self.assertNotIn("kbanned", m.args[1])
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_black_add_sweep_respects_killswitch(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)
        self._grant_op(self.channel)
        self._join(nick="willbeblack", ident="~x", host=self._DEFAULT_HOST)

        self.getMsg("spamguard black add willbeblack")
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [], "killSwitch on -- must never enforce, even on the sweep")
        records = self._log_records()
        self.assertEqual(records[-1]["outcome"], "killswitch")

    def test_black_add_sweep_skips_disabled_channel(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._join(nick="notwatched", ident="~x", host=self._DEFAULT_HOST)
        conf.supybot.plugins.SpamGuard.enabled.get(self.channel).setValue(False)

        self.getMsg("spamguard black add notwatched")
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [], "channel isn't enabled -- sweep must skip it entirely")

    def test_black_never_enforces_without_killswitch_off_even_after_add(self):
        """Sanity check that adding a black term alone (no killSwitch
        flip, no op) never enforces on a subsequent join either."""
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)
        self.getMsg("spamguard black add futurebot")
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=(self.channel,),
            prefix=f"futurebot!~x@{self._DEFAULT_HOST}",
        ))
        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])
        records = self._log_records()
        self.assertEqual(records[-1]["outcome"], "killswitch")

    def test_black_is_checked_before_nick_ident_realname(self):
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self._plugin._terms.add("nick", "dualmatch")
        self._plugin._terms.add("black", "dualmatch")
        self._plugin._rebuild_matchers()

        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=(self.channel,),
            prefix=f"dualmatch!~x@{self._DEFAULT_HOST}",
        ))
        records = self._log_records()
        self.assertEqual(records[-1]["field"], "black")

    def test_black_and_search_and_remove_work_generically(self):
        self.getMsg("spamguard black add somehost.example.net")
        m = self.getMsg("spamguardsearch somehost")
        self.assertIn("black:", m.args[1])

        found = self._plugin._terms.find_by_text("black", "somehost.example.net")
        self.assertIsNotNone(found)
        self.getMsg(f"spamguardremove {found.id}")
        self.assertIsNone(self._plugin._terms.get(found.id))

    # ---- owner-only gate ----

    def _unprivileged_prefix(self):
        """See plugins/Shild/test.py's identical helper docstring: the
        literal '__no_testcap__' suffix is required, or ircdb's own
        checkCapability short-circuits to True for every capability
        during supybot-test runs (world.testing), silently passing this
        test even with no capability gate in place at all."""
        return ircutils.joinHostmask("rando", "user", "unregistered.example__no_testcap__")

    def _assert_denied_owner_capability(self, command):
        m = self.getMsg(command, frm=self._unprivileged_prefix())
        self.assertIn("Error:", m.args[1])
        self.assertIn("owner capability", m.args[1])

    def test_spamguardstatus_requires_owner_capability(self):
        self._assert_denied_owner_capability("spamguardstatus")

    def test_spamguardlist_requires_owner_capability(self):
        self._assert_denied_owner_capability("spamguardlist")

    def test_spamguardsearch_requires_owner_capability(self):
        self._assert_denied_owner_capability("spamguardsearch Czura")

    def test_spamguardremove_requires_owner_capability(self):
        self._assert_denied_owner_capability(f"spamguardremove {self._czura_term.id}")

    def test_spamguard_add_requires_owner_capability(self):
        self._assert_denied_owner_capability("spamguard word add foo")
        self.assertIsNone(self._plugin._terms.find_by_text("word", "foo"))


class SpamGuardXFallbackTestCase(ChannelPluginTestCase):
    """The 2026-08-16 X-routed enforcement fallback -- mirrors
    ShildXFallbackTestCase (plugins/Shild/test.py) exactly, same "seed
    the real UndernetX capability cache, don't mock" approach.
    """
    plugins = ("SpamGuard", "UndernetX")

    _DEFAULT_HOST = SpamGuardTestCase._DEFAULT_HOST

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._log_path = str(Path(self._tmpdir) / "spamguard_actions.jsonl")
        self._terms_path = str(Path(self._tmpdir) / "spamguard_terms.json")
        conf.supybot.plugins.SpamGuard.logPath.setValue(self._log_path)
        conf.supybot.plugins.SpamGuard.termsPath.setValue(self._terms_path)
        conf.supybot.plugins.SpamGuard.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(False)

        super().setUp()

        self._plugin = self.irc.getCallback("SpamGuard")
        self._czura_term = self._plugin._terms.add("word", "Czura")
        self._plugin._rebuild_matchers()

        self.irc.state.supported["NETWORK"] = "UnderNet"
        self._x = self.irc.getCallback("UndernetX")
        self._x.identified = True
        conf.supybot.plugins.UndernetX.auth.username.setValue("shild")
        conf.supybot.plugins.UndernetX.auth.password.setValue("")
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(True)
        # A network+channel-qualified override, once set by ANY test
        # anywhere in this process, permanently takes precedence over the
        # bare-channel value above -- see plugins/UndernetX/test.py's own
        # setUp for the canonical fix/explanation (2026-08-16). Reset
        # (not just re-assert) so this class is correct regardless of
        # what ran before it, without itself becoming a source of the
        # same leak for whatever runs after it.
        net_specific = conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            ":" + self.irc.network).get(self.channel)
        net_specific.setValue(False)
        net_specific._wasSet = False
        conf.supybot.plugins.UndernetX.enforcement.xFallbackEnabled.setValue(True)
        conf.supybot.plugins.UndernetX.enforcement.minAccessLevel.setValue(100)
        conf.supybot.plugins.UndernetX.enforcement.probeTtlSecs.setValue(3600)
        conf.supybot.plugins.UndernetX.enforcement.probeMinIntervalSecs.setValue(60)

    def _seed_x_usable(self):
        from plugins.UndernetX.xprobe import ProbeVerdict
        self._x._capabilities.record(
            "test", ircutils.toLower(self.channel),
            ProbeVerdict(state="usable", access_level=500), [],
        )

    def _spam_msg(self, nick="primaryocelo", ident="~ocelo", host=None):
        host = host or self._DEFAULT_HOST
        return ircmsgs.privmsg(
            self.channel,
            "Hi Guys! It's Madeleine Czura! Just thought I'd leave my number here.",
            prefix=f"{nick}!{ident}@{host}",
        )

    def _join(self, nick="primaryocelo", ident="~ocelo", host=None):
        host = host or self._DEFAULT_HOST
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=(self.channel,), prefix=f"{nick}!{ident}@{host}",
        ))

    def _queued(self):
        q = self.irc.queue
        return list(q.highpriority) + list(q.normal) + list(q.lowpriority)

    def _log_records(self):
        if not Path(self._log_path).exists():
            return []
        return [json.loads(line) for line in Path(self._log_path).read_text().strip().splitlines()]

    def test_not_opped_available_fires_x_ban_and_kick(self):
        self._seed_x_usable()
        self._join()
        self.irc.feedMsg(self._spam_msg())

        native = [m for m in self._queued() if m.command in ("KICK", "MODE")]
        self.assertEqual(native, [])
        x_privmsgs = [m for m in self._queued() if m.command == "PRIVMSG"
                      and m.args[0] == "X@channels.undernet.org"]
        self.assertEqual(len(x_privmsgs), 2)
        self.assertTrue(x_privmsgs[0].args[1].startswith(f"BAN {self.channel} "))
        self.assertTrue(x_privmsgs[1].args[1].startswith(f"KICK {self.channel} "))
        record = self._log_records()[-1]
        self.assertEqual(record["outcome"], "enforced")
        self.assertEqual(record["via"], "x")

    def test_not_opped_no_cache_entry_does_not_enforce(self):
        self._join()
        self.irc.feedMsg(self._spam_msg())
        self.assertEqual([m for m in self._queued() if m.command in ("KICK", "MODE")], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "not-opped")

    def test_not_opped_channel_not_opted_in_does_not_enforce(self):
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(False)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        self.assertEqual([m for m in self._queued() if m.command == "PRIVMSG"
                           and m.args[0] == "X@channels.undernet.org"], [])
        self.assertEqual(self._log_records()[-1]["outcome"], "not-opped")

    def test_not_opped_arm_switch_off_does_not_enforce_even_with_usable_cache(self):
        self._seed_x_usable()
        conf.supybot.plugins.UndernetX.enforcement.xFallbackEnabled.setValue(False)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        self.assertEqual([m for m in self._queued() if m.command == "PRIVMSG"
                           and m.args[0] == "X@channels.undernet.org"], [])

    def test_killswitch_still_gates_the_x_path(self):
        self._seed_x_usable()
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)
        self._join()
        self.irc.feedMsg(self._spam_msg())
        self.assertEqual([m for m in self._queued() if m.command == "PRIVMSG"
                           and m.args[0] == "X@channels.undernet.org"], [])

    def test_opped_always_uses_native_path_never_x(self):
        self._seed_x_usable()
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="MODE", args=(self.channel, "+o", self.irc.nick),
            prefix="ChanServ!ChanServ@services.",
        ))
        self._join()
        self.irc.feedMsg(self._spam_msg())

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 1)
        self.assertEqual(len(bans), 1)
        x_privmsgs = [m for m in self._queued() if m.command == "PRIVMSG"
                      and m.args[0] == "X@channels.undernet.org"]
        self.assertEqual(x_privmsgs, [])
        record = self._log_records()[-1]
        self.assertEqual(record["via"], "native")
