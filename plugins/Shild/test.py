"""Limnoria PluginTestCase tests for Shild.

Kept deliberately scoped to what's meaningfully testable without a live
Ollama connection (supybot-test typically runs with --no-network in CI):
plugin load, the read-only status command, channel enable/disable
gating, and the classifier-confident fast path (synchronous, no network
needed). Full live-Ollama fusion behavior is exercised by
shildml.replay against real shadow_decisions.jsonl data instead (see
that module) and by actual shadow-mode running (M5).
"""
import json
import tempfile
from pathlib import Path

import numpy as np
import supybot.conf as conf
import supybot.ircdb as ircdb
import supybot.ircutils as ircutils
from supybot.test import ChannelPluginTestCase

from shildml import artifact, features


def _write_dummy_model(path, bias_toward: str = "allow", margin: float = 10.0):
    """A tiny hand-built model that always predicts `bias_toward`,
    regardless of input -- built by setting all weights to zero and a
    fixed bias on the target class, so tests don't depend on any
    particular trained artifact. `margin=10.0` (the default) produces
    near-certain confidence; `margin=0.0` produces a deterministic,
    uniform ~1/n_actions confidence -- useful for a test that needs
    classifier_confident to reliably be False.
    """
    n_actions = len(features.ACTIONS)
    idx = features.ACTION_IDX[bias_toward]
    layer_spec = [
        {"w": np.zeros((64, features.N_FEATURES), dtype="float32"),
         "b": np.zeros(64, dtype="float32"), "act": "relu"},
        {"w": np.zeros((32, 64), dtype="float32"),
         "b": np.zeros(32, dtype="float32"), "act": "relu"},
        {"w": np.zeros((n_actions, 32), dtype="float32"),
         "b": np.array([margin if i == idx else -margin for i in range(n_actions)], dtype="float32"),
         "act": None},
    ]
    artifact.save(path, layer_spec, {
        "trained_at": "test", "train_rows": 0, "label_distribution": {},
        "split_strategy": "none", "val_metrics": {},
    })


class ShildTestCase(ChannelPluginTestCase):
    plugins = ("Shild",)

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = str(Path(self._tmpdir) / "model.npz")
        self._data_path = str(Path(self._tmpdir) / "shadow.jsonl")
        self._moderation_path = str(Path(self._tmpdir) / "observed_moderation.jsonl")
        self._enforcement_path = str(Path(self._tmpdir) / "enforcement.jsonl")
        self._ban_ids_path = str(Path(self._tmpdir) / "ban_ids.json")
        self._report_dir = Path(self._tmpdir) / "daily_analysis"
        _write_dummy_model(self._model_path, bias_toward="ban")

        conf.supybot.plugins.Shild.classifier.modelPath.setValue(self._model_path)
        conf.supybot.plugins.Shild.shadowDataPath.setValue(self._data_path)
        conf.supybot.plugins.Shild.moderationLogPath.setValue(self._moderation_path)
        conf.supybot.plugins.Shild.enforcementLogPath.setValue(self._enforcement_path)
        conf.supybot.plugins.Shild.banIdsPath.setValue(self._ban_ids_path)
        conf.supybot.plugins.Shild.report.dir.setValue(str(self._report_dir))
        conf.supybot.plugins.Shild.thresholds.classifierAct.setValue(0.5)
        # ignoreList is a global value individual tests below set directly
        # (not via the class-level `config` dict PluginTestCase restores
        # automatically) -- reset it here so no test leaks state into a
        # later one in the same process, same "conf.setValue() inside a
        # test body must be restored somewhere" discipline as CLAUDE.md's
        # documented WebPanel test-leak gotcha.
        conf.supybot.plugins.Shild.ignoreList.setValue([])
        # Same cross-test state-leak discipline as ignoreList above --
        # decisionCache.enabled/ttlSecs are global values a test can set
        # directly; reset to their real defaults here so one test's
        # tweak never leaks into a later one in the same process. The
        # cache's own CONTENTS never leak between tests regardless (a
        # fresh DecisionCache is constructed per plugin instance, i.e.
        # per test, in __init__).
        conf.supybot.plugins.Shild.decisionCache.enabled.setValue(True)
        conf.supybot.plugins.Shild.decisionCache.ttlSecs.setValue(1800.0)
        # Pre-existing latent leak, only now actually tripped: relayChannel
        # is a global (network-scoped) value a handful of tests set
        # directly via .get(":test").setValue(...) and never reset --
        # same class of gotcha as ignoreList/decisionCache above, just not
        # caught until a new test (added same session) happened to run
        # alphabetically after one of them with the leak still live.
        conf.supybot.plugins.Shild.relayChannel.get(":test").setValue("")
        # Same story, and the REAL root cause of a failure the relayChannel
        # fix above only partly masked: Shild.enabled for self.channel is
        # channel-scoped and set True by many tests, never reset. Left
        # leaked True, an unrelated test's `getMsg(cmd, frm=<some
        # hostmask>)` synthesizes a JOIN for that sender (Limnoria's own
        # test harness keeps channel state consistent), which -- with
        # `enabled` still true from an earlier test -- runs that synthetic
        # joiner through Shild's FULL evaluation pipeline, producing a
        # real [shadow] relay line and a real shadow_decisions.jsonl
        # write neither test expected. Confirmed live: this is exactly
        # what broke test_shildcheck_requires_owner_capability once a new
        # test (this session) happened to leave `enabled` True right
        # before it in alphabetical run order.
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(False)
        # Protection defaults to safe (killSwitch=True) -- each enforcement
        # test below flips it explicitly rather than relying on the default,
        # so the test itself documents which state it needs.
        # Evidence is exercised separately below (test_trusted_cloak_...),
        # using a cloak host specifically because Tier 0 (cloak trust) is
        # pure/local and resolves synchronously. A bare IP host is
        # deliberately NOT used for that -- Tier 1 evidence requires real
        # DNS/HTTP lookups on the worker thread, which this offline
        # PluginTestCase suite cannot exercise deterministically (see
        # module docstring). The other tests below disable evidence so
        # they keep testing exactly what they say they test: the
        # classifier-confident fast path, synchronous, no network needed.
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        super().setUp()

        # shildstatus/shildreport/shildcheck are owner-only (2026-08-09) --
        # they surface real people's nicks/hosts/reputation data, and
        # shildcheck spends real third-party API budget per call. Grant the
        # default test hostmask (self.prefix, set by super().setUp() above)
        # 'owner' so the functional tests below still exercise the commands'
        # actual behavior; test_*_requires_owner_capability proves the gate
        # itself, using a hostmask that deliberately does NOT get this grant.
        u = ircdb.users.newUser()
        u.name = "test-owner"
        u.addCapability("owner")
        u.addHostmask(self.prefix)
        ircdb.users.setUser(u)

    def test_status_command_replies(self):
        self.assertNotError("shildstatus")

    def test_report_command_no_reports_yet(self):
        self.assertError("shildreport")

    def test_report_command_returns_latest_excerpt(self):
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-05-report.md").write_text(
            "# Shild-py daily shadow-mode report -- 2026-08-05\n\nOlder report, should not win.\n"
        )
        (self._report_dir / "2026-08-06-report.md").write_text(
            "# Shild-py daily shadow-mode report -- 2026-08-06\n\n"
            "1,451 join events logged in the last 24h, all resolving to allow.\n"
        )
        m = self.getMsg("shildreport")
        self.assertIn("2026-08-06-report", m.args[1])
        self.assertIn("1,451 join events", m.args[1])
        # shildreport sends TWO separate irc.reply() calls (same pattern as
        # shildstatus) -- the second is already queued, no new command needed.
        m2 = self.irc.takeMsg()
        self.assertIsNotNone(m2, "expected a second reply with the report path")
        self.assertIn("2026-08-06-report.md", m2.args[1])

    def test_report_command_specific_date(self):
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-05-report.md").write_text(
            "# report\n\nOlder report content.\n"
        )
        (self._report_dir / "2026-08-06-report.md").write_text(
            "# report\n\nNewer report content.\n"
        )
        m = self.getMsg("shildreport 2026-08-05")
        self.assertIn("Older report content", m.args[1])

    def test_report_command_unknown_date_errors(self):
        self._report_dir.mkdir(parents=True)
        self.assertError("shildreport 2099-01-01")

    def test_report_command_leads_with_flagged_hosts(self):
        """2026-08-10: a report following the structured format (see
        scripts/daily_data_analysis.sh's prompt) gets its '## Flagged
        hosts' lines surfaced first, instead of whatever prose happened
        to come first in the file."""
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-10-report.md").write_text(
            "# Shild daily review -- 2026-08-10\n\n"
            "## Flagged hosts\n"
            "- FLAG: 49.36.18.228 (rhy075) -- bare IP, 11 reconnects, consistent high ban score\n"
            "- FLAG: 38.41.185.136 (qqbot) -- self-describing bot nick on a bare IP\n\n"
            "## Volume and health\n"
            "1,114 join events, all resolving to allow.\n"
        )
        m = self.getMsg("shildreport")
        self.assertIn("2 flagged", m.args[1])
        self.assertIn("49.36.18.228 (rhy075)", m.args[1])
        self.assertIn("38.41.185.136 (qqbot)", m.args[1])
        # The unflagged "Volume and health" prose must NOT be what leads.
        self.assertNotIn("1,114 join events", m.args[1])

    def test_report_command_flag_none_shows_nothing_flagged(self):
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-10-report.md").write_text(
            "# Shild daily review -- 2026-08-10\n\n"
            "## Flagged hosts\n- FLAG: none\n\n"
            "## Volume and health\nQuiet day.\n"
        )
        m = self.getMsg("shildreport")
        self.assertIn("nothing flagged today", m.args[1])

    def test_report_command_falls_back_for_older_format(self):
        """A report with no '## Flagged hosts' heading at all (the format
        that existed before 2026-08-10, or a malformed run) must fall back
        to the original whole-body excerpt rather than showing nothing."""
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-10-report.md").write_text(
            "# Shild-py daily shadow-mode report -- 2026-08-10\n\n"
            "1,451 join events logged in the last 24h, all resolving to allow.\n"
        )
        m = self.getMsg("shildreport")
        self.assertIn("1,451 join events", m.args[1])

    def test_new_report_announced_once_to_relay_channel(self):
        conf.supybot.plugins.Shild.relayChannel.get(":test").setValue(self.channel)
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-06-report.md").write_text(
            "# report\n\nSomething worth a look happened today.\n"
        )
        cb = self.irc.getCallback("Shild")
        cb._check_new_report()
        m = self.irc.takeMsg()
        self.assertIsNotNone(m, "expected an announcement on the relay channel")
        self.assertIn("Something worth a look", m.args[1])
        self.assertIn("!shildreport", m.args[1])
        # A second check with no new report must NOT announce again.
        cb._check_new_report()
        self.assertIsNone(self.irc.takeMsg())

    def test_new_report_announcement_leads_with_flagged_hosts(self):
        conf.supybot.plugins.Shild.relayChannel.get(":test").setValue(self.channel)
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-10-report.md").write_text(
            "# Shild daily review -- 2026-08-10\n\n"
            "## Flagged hosts\n"
            "- FLAG: 49.36.18.228 (rhy075) -- bare IP, 11 reconnects, consistent high ban score\n\n"
            "## Volume and health\nEverything else looks normal.\n"
        )
        cb = self.irc.getCallback("Shild")
        cb._check_new_report()
        m = self.irc.takeMsg()
        self.assertIsNotNone(m, "expected an announcement on the relay channel")
        self.assertIn("1 flagged", m.args[1])
        self.assertIn("49.36.18.228 (rhy075)", m.args[1])
        self.assertNotIn("Everything else looks normal", m.args[1])

    def test_join_ignored_when_channel_disabled(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(False)
        before = Path(self._data_path).exists()
        self.irc.feedMsg(
            self._make_join("newuser", "~ident", "203.0.113.5", self.channel)
        )
        # No decision record should appear for a disabled channel.
        self.assertEqual(Path(self._data_path).exists(), before)

    def test_join_enabled_channel_confident_classifier_writes_record(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        self.irc.feedMsg(
            self._make_join("newuser2", "~ident", "203.0.113.6", self.channel)
        )
        self.assertTrue(Path(self._data_path).exists(), "expected a shadow decision record to be written")
        lines = Path(self._data_path).read_text().strip().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[-1])
        self.assertEqual(record["fused"]["action"], "ban")
        self.assertEqual(record["fused"]["source"], "classifier")
        self.assertFalse(record["fused"].get("degraded", False))

    def test_trusted_cloak_confident_ban_downgrades_synchronously_without_network(self):
        """Phase 1.5: a registered-account cloak is Tier 0 evidence (pure,
        no I/O) that CONTRADICTS a ban -- see shildml/evidence.py -- so
        the whole thing resolves in the same feedMsg call, no worker
        thread or network access involved, exactly like the plain
        confident-classifier fast path above.
        """
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(True)
        self.irc.feedMsg(
            self._make_join("newuser3", "~ident", "user/alice", self.channel)
        )
        self.assertTrue(Path(self._data_path).exists())
        record = json.loads(Path(self._data_path).read_text().strip().splitlines()[-1])
        self.assertEqual(record["fused_raw"]["action"], "ban")
        self.assertEqual(record["fused"]["action"], "allow")
        self.assertTrue(record["gate"]["applied"])
        self.assertEqual(record["gate"]["rule"], "contradicted")
        self.assertEqual(record["evidence"]["trust_tier"], "registered")

    def test_trusted_cloak_bypasses_ollama_when_classifier_not_confident(self):
        """2026-08-06 fix: the Tier 0 trust short-circuit used to only fire
        from a CONFIDENT classifier's ban/warn -- shadow-corpus analysis
        showed the real classifier never reaches that confidence in
        practice, so a trusted cloak always fell through to a full Ollama
        round-trip regardless. Tier 0 trust alone is now conclusive
        whether or not the classifier is confident -- this must also
        resolve synchronously, no worker/network involved, same as the
        confident-classifier case above.
        """
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(True)
        # Overwrite the SAME model file the plugin already loaded --
        # ClassifierWrapper is bound to a fixed path at construction
        # (classifier.py), so changing the modelPath registry value after
        # setUp has no effect; reload_if_needed() picks up the new content
        # via the file's mtime. margin=0.0 gives a deterministic, uniform
        # ~1/3 confidence -- well below any real threshold, guaranteeing
        # classifier_confident is False regardless of what it "predicts".
        _write_dummy_model(self._model_path, bias_toward="ban", margin=0.0)
        self.irc.getCallback("Shild")._classifier.reload_if_needed()
        self.irc.feedMsg(
            self._make_join("newuser5", "~ident", "user/bob", self.channel)
        )
        self.assertTrue(Path(self._data_path).exists())
        record = json.loads(Path(self._data_path).read_text().strip().splitlines()[-1])
        self.assertLess(record["classifier"]["confidence"],
                         conf.supybot.plugins.Shild.thresholds.classifierAct())
        self.assertEqual(record["fused"]["action"], "allow")
        self.assertEqual(record["fused"]["source"], "trust")
        self.assertFalse(record["fused"].get("degraded", False))
        self.assertEqual(record["evidence"]["trust_tier"], "registered")

    def test_kick_by_another_op_is_recorded_with_reason_and_classifier_reading(self):
        """Read-only observation: shild-py has no kick capability at all,
        but a REAL op kicking a REAL user is free ground truth. This must
        be recorded with the kick reason and, since we already saw this
        nick join (so we know their ident/host), a synchronous
        classifier reading at the moment of the kick.
        """
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        # The bot must have seen this nick before (via join/message) for
        # doKick to resolve their identity -- see context.py's identity
        # cache, which exists exactly because irc.state won't have it
        # anymore by the time doKick fires.
        self.irc.feedMsg(self._make_join("baduser", "~bad", "203.0.113.7", self.channel))
        Path(self._data_path).unlink()  # clear the join's own shadow-decision record

        self.irc.feedMsg(self._make_kick(
            actor="RealOp", actor_ident="~op", actor_host="op.example.com",
            channel=self.channel, target_nick="baduser", reason="stop spamming",
        ))

        self.assertTrue(Path(self._moderation_path).exists())
        lines = Path(self._moderation_path).read_text().strip().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["event_type"], "kick")
        self.assertEqual(record["actor"]["nick"], "RealOp")
        self.assertEqual(record["target"], {"nick": "baduser", "ident": "~bad", "host": "203.0.113.7"})
        self.assertEqual(record["reason"], "stop spamming")
        # The dummy model is biased toward "ban" -- proves the classifier
        # was actually consulted at kick time, not left None.
        self.assertEqual(record["classifier_at_time"]["action"], "ban")
        # And the kick must NOT have produced a normal shadow-decision
        # record -- observation is a separate, distinct data stream.
        self.assertFalse(Path(self._data_path).exists())

    def test_ban_by_another_op_extracts_host_from_mask(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        self.irc.feedMsg(self._make_ban(
            actor="RealOp", actor_ident="~op", actor_host="op.example.com",
            channel=self.channel, mask="*!*@203.0.113.8",
        ))
        self.assertTrue(Path(self._moderation_path).exists())
        record = json.loads(Path(self._moderation_path).read_text().strip().splitlines()[-1])
        self.assertEqual(record["event_type"], "ban")
        self.assertEqual(record["ban_mask"], "*!*@203.0.113.8")
        self.assertEqual(record["target"]["host"], "203.0.113.8")
        self.assertIsNone(record["classifier_at_time"])

    def test_kick_ignored_when_channel_disabled(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(False)
        self.irc.feedMsg(self._make_kick(
            actor="RealOp", actor_ident="~op", actor_host="op.example.com",
            channel=self.channel, target_nick="baduser", reason="x",
        ))
        self.assertFalse(Path(self._moderation_path).exists())

    # ---- Phase 2: protection mode (real enforcement) ----

    def test_enforcement_fires_when_opped_and_kill_switch_off(self):
        """The one path where Shild is allowed to actually act: it holds
        real op AND the kill switch has been deliberately turned off.
        The dummy model is biased toward "ban" and evidence is disabled,
        so the raw and gated decisions are both "ban" -- confirms
        _maybe_enforce reads the same `fused` decision the shadow log did.
        """
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self.irc.feedMsg(self._make_join("baduser", "~bad", "203.0.113.7", self.channel))

        kick_or_ban = [m for m in self._queued() if m.command in ("KICK", "MODE")]
        kicks = [m for m in kick_or_ban if m.command == "KICK"]
        bans = [m for m in kick_or_ban if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 1, "expected a real KICK to be queued")
        self.assertEqual(len(bans), 1, "expected a real MODE +b to be queued")
        self.assertEqual(kicks[0].args[1], "baduser")
        self.assertEqual(bans[0].args[2], "*!*@203.0.113.7")

        self.assertTrue(Path(self._enforcement_path).exists())
        record = json.loads(Path(self._enforcement_path).read_text().strip().splitlines()[-1])
        self.assertEqual(record["target"]["host"], "203.0.113.7")
        self.assertEqual(record["fused_decision"]["action"], "ban")

        # 2026-08-11: short, adaptive kick message with a permanent id,
        # not the old verbose fused.reason dump.
        self.assertEqual(record["id"], 1)
        kick_reason = kicks[0].args[2]
        self.assertTrue(kick_reason.startswith("SHILD: 203.0.113.7 "))
        self.assertIn("(score:", kick_reason)
        self.assertIn("[ID: 1]", kick_reason)
        self.assertEqual(record["reason"], kick_reason)

    def test_enforcement_ban_ids_increment_across_separate_bans(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self.irc.feedMsg(self._make_join("baduser1", "~bad", "203.0.113.8", self.channel))
        self.irc.feedMsg(self._make_join("baduser2", "~bad", "203.0.113.9", self.channel))

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 2)
        self.assertIn("[ID: 1]", kicks[0].args[2])
        self.assertIn("[ID: 2]", kicks[1].args[2])

    def test_enforcement_suppressed_by_kill_switch_even_when_opped(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(True)  # explicit, matches default
        self._grant_op(self.channel)

        self.irc.feedMsg(self._make_join("baduser2", "~bad", "203.0.113.10", self.channel))

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [], "kill switch must suppress enforcement even when opped")
        self.assertFalse(Path(self._enforcement_path).exists())
        # Shadow logging must still have happened -- protection state never
        # affects the unconditional shadow log.
        self.assertTrue(Path(self._data_path).exists())

    def test_enforcement_suppressed_when_not_opped(self):
        # This class (ShildTestCase, plugins=("Shild",)) doubles as the
        # "UndernetX not loaded at all" proof for the 2026-08-16 X-routed
        # enforcement fallback: irc.getCallback("UndernetX") returns None
        # here unconditionally, so _x_fallback() always returns None too,
        # and behavior is exactly what it was before that feature existed
        # -- no action, no error. See ShildXFallbackTestCase (below, a
        # separate plugins=("Shild", "UndernetX") class) for the cases
        # where UndernetX IS loaded.
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        # Deliberately NOT granting op here.

        self.irc.feedMsg(self._make_join("baduser3", "~bad", "203.0.113.11", self.channel))

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [], "must never enforce without real op status")
        self.assertFalse(Path(self._enforcement_path).exists())

    def test_warn_verdict_never_enforces_even_when_opped(self):
        # The plugin's ClassifierWrapper is bound to self._model_path at
        # __init__ time (its reload() checks THIS path's mtime, not
        # whatever the registry says afterward -- see shildml/infer.py),
        # so switching bias means overwriting that same file and forcing
        # a reload, not repointing modelPath to a different file.
        _write_dummy_model(self._model_path, bias_toward="warn")
        self.irc.getCallback("Shild")._classifier.reload_if_needed()
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self.irc.feedMsg(self._make_join("borderline", "~b", "203.0.113.12", self.channel))

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [], "warn verdicts must never trigger real enforcement")
        self.assertFalse(Path(self._enforcement_path).exists())

    # ---- decision cache (2026-08-16): repeat joins from the same host ----

    def test_decision_cache_skips_second_shadow_record_for_same_host(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.70", self.channel))
        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.70", self.channel))

        records = Path(self._data_path).read_text().strip().splitlines()
        self.assertEqual(len(records), 1, "a repeat join from the same host must not re-decide")

    def test_decision_cache_scoped_by_host_not_nick(self):
        """The real incident this fixes: a reconnecting client, not
        necessarily even the same nick each time -- caching is keyed by
        host alone (see decision_cache.py's module docstring)."""
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)

        self.irc.feedMsg(self._make_join("flapper1", "~f", "203.0.113.71", self.channel))
        self.irc.feedMsg(self._make_join("flapper2", "~f", "203.0.113.71", self.channel))

        records = Path(self._data_path).read_text().strip().splitlines()
        self.assertEqual(len(records), 1)

    def test_decision_cache_does_not_relay_a_second_time(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.relayChannel.get(":test").setValue(self.channel)

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.72", self.channel))
        first_relay = self.irc.takeMsg()
        self.assertIsNotNone(first_relay, "expected the first join's [shadow] relay line")

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.72", self.channel))
        second_relay = self.irc.takeMsg()
        self.assertIsNone(second_relay, "a cache hit must not relay again")

    def test_decision_cache_different_host_still_gets_its_own_decision(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)

        self.irc.feedMsg(self._make_join("usera", "~a", "203.0.113.73", self.channel))
        self.irc.feedMsg(self._make_join("userb", "~b", "203.0.113.74", self.channel))

        records = Path(self._data_path).read_text().strip().splitlines()
        self.assertEqual(len(records), 2, "a genuinely different host must not hit the cache")

    def test_decision_cache_skips_repeat_messages_from_same_host_not_just_joins(self):
        """The real report this was built from: a host that stays JOINED
        and just keeps sending messages (never parting/rejoining) was
        getting a full fresh evaluation on every single message.
        doJoin/doPrivmsg both funnel into the same _handle_event, so the
        cache check applies identically to both event types -- proven
        directly here rather than assumed."""
        from supybot import ircmsgs
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.messageAnalysis.get(self.channel).setValue(True)

        def _msg(text):
            return ircmsgs.privmsg(self.channel, text,
                                    prefix="chatty!~c@203.0.113.77")

        self.irc.feedMsg(_msg("first message"))
        for i in range(10):
            self.irc.feedMsg(_msg(f"message number {i}"))

        records = Path(self._data_path).read_text().strip().splitlines()
        self.assertEqual(len(records), 1,
                          "repeat MESSAGES (no join at all) from the same host must "
                          "not each re-decide -- only the first one should")

    def test_decision_cache_disabled_reevaluates_every_time(self):
        conf.supybot.plugins.Shild.decisionCache.enabled.setValue(False)
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.75", self.channel))
        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.75", self.channel))

        records = Path(self._data_path).read_text().strip().splitlines()
        self.assertEqual(len(records), 2, "decisionCache.enabled=False must re-decide every time")

    def test_decision_cache_still_enforces_on_repeat_if_newly_eligible(self):
        """Being cached is about not RE-DECIDING, never about suppressing
        real protection once it becomes eligible -- op status or the
        kill switch can change between the two joins."""
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(True)  # armed OFF later

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.76", self.channel))
        self.assertEqual([m for m in self._queued() if m.command == "KICK"], [],
                          "sanity: not yet armed, must not have enforced on the first join")

        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)
        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.76", self.channel))

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(len(kicks), 1,
                          "a cache hit must still enforce once newly eligible")
        # And still only ONE shadow record overall -- the second join was
        # a cache hit, not a fresh decision.
        records = Path(self._data_path).read_text().strip().splitlines()
        self.assertEqual(len(records), 1)

    # ---- decision cache in-flight tracking (2026-08-16, real second
    # incident: a burst of near-simultaneous events for the same host,
    # arriving before the FIRST one's own worker evaluation has resolved
    # -- see decision_cache.py's module docstring for the confirmed-live
    # root cause. These tests seed the real DecisionCache's in-flight
    # state directly (same "seed the real object, don't mock" pattern
    # already used elsewhere) rather than trying to race a real worker
    # thread, matching this suite's own stated policy of never
    # exercising real Tier 1-3 network lookups. ----

    def test_event_dropped_entirely_while_host_is_in_flight(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        cb = self.irc.getCallback("Shild")
        cb._decision_cache.mark_in_flight("test", "203.0.113.80")

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.80", self.channel))

        self.assertFalse(Path(self._data_path).exists(),
                          "an event for an in-flight host must produce no shadow record at all")

    def test_event_for_a_different_host_is_unaffected_by_another_hosts_in_flight_marker(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        cb = self.irc.getCallback("Shild")
        cb._decision_cache.mark_in_flight("test", "203.0.113.81")

        self.irc.feedMsg(self._make_join("someoneelse", "~s", "203.0.113.82", self.channel))

        self.assertTrue(Path(self._data_path).exists(),
                         "a different, non-in-flight host must still be evaluated normally")

    def test_event_proceeds_normally_once_in_flight_marker_is_cleared(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        cb = self.irc.getCallback("Shild")
        cb._decision_cache.mark_in_flight("test", "203.0.113.83")
        cb._decision_cache.clear_in_flight("test", "203.0.113.83")

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.83", self.channel))

        self.assertTrue(Path(self._data_path).exists(),
                         "clearing the in-flight marker must let the next event through")

    def test_synchronous_fast_path_never_leaves_a_host_marked_in_flight(self):
        """The classifier-confident/evidence-disabled fast path used
        throughout this test class never calls mark_in_flight itself
        (only the worker-dispatch site does, in _handle_event) -- confirm
        a completely ordinary join leaves nothing behind for a later
        event to trip over."""
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        cb = self.irc.getCallback("Shild")

        self.irc.feedMsg(self._make_join("flapper", "~f", "203.0.113.84", self.channel))

        self.assertFalse(cb._decision_cache.is_in_flight("test", "203.0.113.84"))

    # ---- !shildcheck ----

    def test_shildcheck_by_host_uses_shadow_manual_tag_and_writes_nothing(self):
        # evidence.enabled=False (setUp default) + bias_toward="ban" from
        # setUp's dummy model -> classifier-confident fast path, entirely
        # synchronous, no worker/network involved.
        m = self.getMsg("shildcheck 203.0.113.50")
        self.assertIn("[shadow-manual] checking 203.0.113.50", m.args[1])
        m2 = self.irc.takeMsg()
        self.assertIsNotNone(m2, "expected a second message with the decision")
        self.assertIn("[shadow-manual] ", m2.args[1])
        self.assertIn("BAN", m2.args[1])
        self.assertIn("203.0.113.50", m2.args[1])
        self.assertIn("via classifier", m2.args[1])
        # The whole point: a manual check must never look like a real
        # decision to anything reading shadow_decisions.jsonl for training.
        self.assertFalse(Path(self._data_path).exists(),
                          "!shildcheck must never write a shadow decision record")

    def test_shildcheck_resolves_known_nick_via_context_store(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        self.irc.feedMsg(
            self._make_join("knownuser", "~kid", "203.0.113.51", self.channel)
        )
        # The join itself wrote exactly one real record -- shildcheck
        # below must not add a second one.
        self.assertEqual(
            len(Path(self._data_path).read_text().strip().splitlines()), 1)
        # Drain whatever the join itself queued (e.g. a [shadow] relay
        # line, if an earlier test in this process left relayChannel
        # set) so it can't be mistaken for shildcheck's own reply below.
        while self.irc.takeMsg() is not None:
            pass

        m = self.getMsg("shildcheck knownuser")
        self.assertIn("knownuser ~kid@203.0.113.51", m.args[1])
        m2 = self.irc.takeMsg()
        self.assertIn("BAN", m2.args[1])
        self.assertIn("knownuser (~kid@203.0.113.51)", m2.args[1])

        self.assertEqual(
            len(Path(self._data_path).read_text().strip().splitlines()), 1,
            "!shildcheck must not add a second shadow decision record")

    def test_shildcheck_shows_nick_history_for_a_host_with_prior_aliases(self):
        """2026-08-16: ban-evasion detection -- a host that's connected
        under multiple nicks shows the OTHER ones (not the one currently
        being checked) as a separate reply line."""
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        self.irc.feedMsg(self._make_join("evader1", "~e", "203.0.113.60", self.channel))
        while self.irc.takeMsg() is not None:
            pass
        self.irc.feedMsg(self._make_join("evader2", "~e", "203.0.113.60", self.channel))
        while self.irc.takeMsg() is not None:
            pass

        m = self.getMsg("shildcheck evader2")
        self.assertIn("evader2 ~e@203.0.113.60", m.args[1])
        m2 = self.irc.takeMsg()
        self.assertIn("also seen as: evader1", m2.args[1])

    def test_shildcheck_no_history_line_when_host_has_no_prior_aliases(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        self.irc.feedMsg(self._make_join("onlyme", "~o", "203.0.113.61", self.channel))
        while self.irc.takeMsg() is not None:
            pass

        m = self.getMsg("shildcheck onlyme")
        self.assertIn("onlyme ~o@203.0.113.61", m.args[1])
        m2 = self.irc.takeMsg()
        self.assertNotIn("also seen as", m2.args[1])

    def test_shildcheck_resolves_connected_nick_via_irc_state_when_unanalyzed(self):
        # Channel disabled -- doJoin never reaches _handle_event, so
        # ContextStore's identity cache never learns about this nick.
        # Limnoria's own IrcState still tracks the join regardless (state
        # updates are independent of any plugin's enable/disable), which
        # is the fallback path being exercised here.
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(False)
        self.irc.feedMsg(
            self._make_join("unanalyzed", "~u", "203.0.113.52", self.channel)
        )
        self.assertFalse(Path(self._data_path).exists(),
                          "sanity: analysis really was off for this join")

        m = self.getMsg("shildcheck unanalyzed")
        self.assertIn("unanalyzed ~u@203.0.113.52", m.args[1])
        m2 = self.irc.takeMsg()
        self.assertIn("BAN", m2.args[1])
        self.assertIn("unanalyzed (~u@203.0.113.52)", m2.args[1])

    def test_shildcheck_unknown_nick_not_host_shaped_errors(self):
        self.assertError("shildcheck totallyUnknownNick")

    def test_shildcheck_shows_evidence_line_for_trusted_cloak(self):
        """2026-08-14 fix: a real user asked "where is the rest" after a
        !shildcheck on a bare IP replied with just a bare ALLOW/reason and
        no evidence detail at all, even though a real lookup had run. The
        decision line's own reason text only ever embeds evidence when the
        gate/escalation changes the action -- a plain, un-escalated allow
        (e.g. a contradicted ban, like here) never did. This must now
        always show a separate evidence line, since evidence really was
        gathered (the trusted cloak, Tier 0)."""
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(True)
        self.irc.feedMsg(
            self._make_join("trustednick", "~kid", "user/carol", self.channel)
        )
        while self.irc.takeMsg() is not None:
            pass

        m = self.getMsg("shildcheck trustednick")
        self.assertIn("[shadow-manual] checking", m.args[1])
        m2 = self.irc.takeMsg()
        self.assertIn("ALLOW", m2.args[1])
        m3 = self.irc.takeMsg()
        self.assertIsNotNone(
            m3, "expected a third message with the gathered evidence")
        self.assertIn("[shadow-manual] evidence:", m3.args[1])
        self.assertIn("user/carol", m3.args[1])

    def test_shildcheck_decision_line_colors_ban_bold_red(self):
        # bias_toward="ban" from setUp's dummy model -> classifier-confident
        # ban, entirely synchronous. The action word must be both bold and
        # mIRC-red (a plain "warn" is green -- see the next test) so BAN
        # visually stands out as the more severe verdict on IRC.
        self.getMsg("shildcheck 203.0.113.60")
        m2 = self.irc.takeMsg()
        expected = ircutils.bold(ircutils.mircColor("BAN", "red"))
        self.assertIn(expected, m2.args[1])

    def test_shildcheck_decision_line_colors_warn_plain_green(self):
        # See test_warn_verdict_never_enforces_even_when_opped above for why
        # this overwrites self._model_path + reload_if_needed() rather than
        # just repointing the modelPath registry value.
        _write_dummy_model(self._model_path, bias_toward="warn")
        self.irc.getCallback("Shild")._classifier.reload_if_needed()
        self.getMsg("shildcheck 203.0.113.61")
        m2 = self.irc.takeMsg()
        expected = ircutils.mircColor("WARN", "green")
        self.assertIn(expected, m2.args[1])
        self.assertNotIn(ircutils.bold(expected), m2.args[1])

    def test_shildcheck_never_enforces_even_with_op_and_kill_switch_off(self):
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self.getMsg("shildcheck 203.0.113.53")
        self.irc.takeMsg()  # the decision line

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE"]
        self.assertEqual(kicks, [], "!shildcheck must never enforce, regardless of op/kill switch")
        self.assertEqual(bans, [], "!shildcheck must never enforce, regardless of op/kill switch")
        self.assertFalse(Path(self._enforcement_path).exists())

    # ---- ignore list (2026-08-10) ----

    def test_ignored_host_join_resolves_to_allow_with_ignored_label_quality(self):
        # bias_toward="ban" from setUp's dummy model -- without the
        # ignore list this join would confidently resolve to BAN (see
        # test_join_enabled_channel_confident_classifier_writes_record
        # above). Proves the ignore list overrides that entirely.
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.ignoreList.setValue(["203.0.113.70"])

        self.irc.feedMsg(self._make_join("myotherbot", "~bot", "203.0.113.70", self.channel))

        record = json.loads(Path(self._data_path).read_text().strip().splitlines()[-1])
        self.assertEqual(record["fused"]["action"], "allow")
        self.assertEqual(record["fused"]["source"], "ignore")
        self.assertEqual(record["label_quality"], "ignored")
        # classifier_result is still recorded (informational), just not used.
        self.assertEqual(record["classifier"]["action"], "ban")

    def test_ignored_host_never_enforces_even_when_opped_and_kill_switch_off(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.ignoreList.setValue(["203.0.113.71"])
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        self._grant_op(self.channel)

        self.irc.feedMsg(self._make_join("myotherbot2", "~bot", "203.0.113.71", self.channel))

        kicks = [m for m in self._queued() if m.command == "KICK"]
        self.assertEqual(kicks, [])

    def test_shildcheck_on_ignored_host_shows_ignore_not_the_full_pipeline(self):
        conf.supybot.plugins.Shild.ignoreList.setValue(["203.0.113.72"])
        m = self.getMsg("shildcheck 203.0.113.72")
        self.assertIn("[shadow-manual] checking 203.0.113.72", m.args[1])
        m2 = self.irc.takeMsg()
        self.assertIn("ALLOW", m2.args[1])
        self.assertIn("via ignore", m2.args[1])
        # Read-only invariant still holds -- this never writes a real record.
        self.assertFalse(Path(self._data_path).exists())

    def test_shildignore_resolves_nick_to_current_host(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        self.irc.feedMsg(self._make_join("knownfriend", "~kid", "203.0.113.73", self.channel))
        while self.irc.takeMsg() is not None:
            pass

        self.getMsg("shildignore knownfriend")
        self.assertIn("203.0.113.73", conf.supybot.plugins.Shild.ignoreList())

    def test_shildignore_bare_host_stored_directly(self):
        self.getMsg("shildignore 203.0.113.74")
        self.assertIn("203.0.113.74", conf.supybot.plugins.Shild.ignoreList())

    def test_shildignore_unknown_nick_not_host_shaped_errors(self):
        m = self.getMsg("shildignore totallyUnknownNick")
        self.assertIn("Error", m.args[1])
        self.assertEqual(list(conf.supybot.plugins.Shild.ignoreList()), [])

    def test_shildignore_twice_does_not_duplicate(self):
        self.getMsg("shildignore 203.0.113.75")
        self.getMsg("shildignore 203.0.113.75")
        self.assertEqual(list(conf.supybot.plugins.Shild.ignoreList()).count("203.0.113.75"), 1)

    def test_shildunignore_exact_match(self):
        conf.supybot.plugins.Shild.ignoreList.setValue(["203.0.113.76"])
        self.getMsg("shildunignore 203.0.113.76")
        self.assertNotIn("203.0.113.76", conf.supybot.plugins.Shild.ignoreList())

    def test_shildunignore_via_nick_resolution(self):
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        self.irc.feedMsg(self._make_join("friend2", "~f2", "203.0.113.77", self.channel))
        while self.irc.takeMsg() is not None:
            pass
        conf.supybot.plugins.Shild.ignoreList.setValue(["203.0.113.77"])

        self.getMsg("shildunignore friend2")
        self.assertNotIn("203.0.113.77", conf.supybot.plugins.Shild.ignoreList())

    def test_shildunignore_not_on_list_errors(self):
        m = self.getMsg("shildunignore 203.0.113.78")
        self.assertIn("Error", m.args[1])

    def test_shildlistignore_shows_configured_hosts(self):
        conf.supybot.plugins.Shild.ignoreList.setValue(["203.0.113.79", "203.0.113.80"])
        m = self.getMsg("shildlistignore")
        self.assertIn("203.0.113.79", m.args[1])
        self.assertIn("203.0.113.80", m.args[1])

    def test_shildlistignore_empty_shows_none(self):
        m = self.getMsg("shildlistignore")
        self.assertIn("(none)", m.args[1])

    # ---- owner-only gate (2026-08-09) ----

    def _unprivileged_prefix(self):
        """A hostmask with no ircdb user behind it -- distinct from
        self.prefix, which setUp() grants 'owner' to. The literal
        '__no_testcap__' suffix is required: supybot's own checkCapability
        (ircdb.py) short-circuits to True for EVERY capability during
        `supybot-test` runs (world.testing) unless the hostmask's host part
        contains this exact marker -- confirmed against ircdb.py and the
        same convention used by supybot's own bundled Config/Misc/User
        plugin tests. Without it, this test would pass even with no
        capability gate at all.
        """
        return ircutils.joinHostmask("rando", "user", "unregistered.example__no_testcap__")

    def _assert_denied_owner_capability(self, command):
        # Not assertError(): a capability denial raised from the channel
        # context gets a "nick: " prefix ahead of "Error:" (standard
        # Limnoria channel-reply convention), which fails assertError's
        # hardcoded m.args[1].startswith('Error:') check even though the
        # denial itself is correct. Check the content instead of the exact
        # prefix.
        m = self.getMsg(command, frm=self._unprivileged_prefix())
        self.assertIn("Error:", m.args[1])
        self.assertIn("owner capability", m.args[1])

    def test_shildstatus_requires_owner_capability(self):
        self._assert_denied_owner_capability("shildstatus")

    def test_shildreport_requires_owner_capability(self):
        self._assert_denied_owner_capability("shildreport")

    def test_shildcheck_requires_owner_capability(self):
        self._assert_denied_owner_capability("shildcheck 203.0.113.54")
        # And confirms it's really the capability check, not resolution
        # failing first: no decision line, no shadow record either.
        self.assertIsNone(self.irc.takeMsg())
        self.assertFalse(Path(self._data_path).exists())

    def test_shildignore_requires_owner_capability(self):
        self._assert_denied_owner_capability("shildignore 203.0.113.90")
        self.assertEqual(list(conf.supybot.plugins.Shild.ignoreList()), [])

    def test_shildunignore_requires_owner_capability(self):
        conf.supybot.plugins.Shild.ignoreList.setValue(["203.0.113.91"])
        self._assert_denied_owner_capability("shildunignore 203.0.113.91")
        self.assertIn("203.0.113.91", conf.supybot.plugins.Shild.ignoreList())

    def test_shildlistignore_requires_owner_capability(self):
        self._assert_denied_owner_capability("shildlistignore")

    # ---- shildconfig (2026-08-22) ----

    def test_shildconfig_requires_owner_capability(self):
        self._assert_denied_owner_capability(f"shildconfig {self.channel}")

    def test_shildconfig_must_be_sent_privately(self):
        # Sent to the channel, not a query -- the 'private' wrap
        # converter should reject this before ever reading the registry.
        m = self.getMsg(f"shildconfig {self.channel}")
        self.assertIn("Error", m.args[1])

    def test_shildconfig_shows_shild_values_and_others_not_loaded(self):
        # This class (ShildTestCase, plugins=("Shild",)) doubles as the
        # "SpamGuard/UndernetX not loaded" proof, same convention as
        # ShildXFallbackTestCase's own docstring for UndernetX.
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.messageAnalysis.get(self.channel).setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(True)
        conf.supybot.plugins.Shild.ollama.enabled.setValue(False)

        # getMsg() itself consumes the FIRST queued reply internally
        # (returns it) -- must be captured, or every later line in the
        # manual drain loop shifts up by one and the first is lost.
        first = self.getMsg(f"shildconfig {self.channel}", private=True)
        lines = [first.args[1]]
        while True:
            m = self.irc.takeMsg()
            if m is None:
                break
            lines.append(m.args[1])

        self.assertIn("Shild.enabled: enabled", lines)
        self.assertIn("Shild.messageAnalysis: disabled", lines)
        self.assertIn("Shild.protection.killSwitch: enabled", lines)
        self.assertIn("Shild.ollama.enabled: disabled", lines)
        self.assertIn("SpamGuard: not loaded", lines)
        self.assertIn("UndernetX: not loaded", lines)

    def _queued(self):
        """All messages currently queued to be sent, without dequeuing
        them (avoids the outgoing-queue's real-time throttling, which
        would make a plain takeMsg() loop flaky in a fast-running test).
        IrcMsgQueue's three priority buckets are plain lists (smallqueue
        subclasses list) -- safe to read directly.
        """
        q = self.irc.queue
        return list(q.highpriority) + list(q.normal) + list(q.lowpriority)

    def _grant_op(self, channel):
        """Simulates the server granting the bot real op -- e.g. via
        ChanServ/X once Phase 2's auth plugins are configured with real
        credentials. Feeding this through the normal IrcState update path
        (rather than poking irc.state directly) is what makes this test
        prove the real is_opped() check, not a mocked one.
        """
        from supybot import ircmsgs
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="MODE", args=(channel, "+o", self.irc.nick),
            prefix="ChanServ!ChanServ@services.",
        ))

    def _make_join(self, nick, ident, host, channel):
        from supybot import ircmsgs
        return ircmsgs.IrcMsg(command="JOIN", args=(channel,),
                               prefix=f"{nick}!{ident}@{host}")

    def _make_kick(self, actor, actor_ident, actor_host, channel, target_nick, reason):
        from supybot import ircmsgs
        return ircmsgs.IrcMsg(command="KICK", args=(channel, target_nick, reason),
                               prefix=f"{actor}!{actor_ident}@{actor_host}")

    def _make_ban(self, actor, actor_ident, actor_host, channel, mask):
        from supybot import ircmsgs
        return ircmsgs.IrcMsg(command="MODE", args=(channel, "+b", mask),
                               prefix=f"{actor}!{actor_ident}@{actor_host}")


class ShildXFallbackTestCase(ChannelPluginTestCase):
    """The 2026-08-16 X-routed enforcement fallback: a real UndernetX
    instance is loaded (unlike ShildTestCase above, which proves the
    "UndernetX not loaded" degradation path), and its X-capability cache
    is seeded directly -- same "seed the real object, don't mock"
    pattern SpamGuard's own tests already use for its TermStore -- so
    these tests exercise the ACTUAL x_enforcement_available()/
    enforce_ban_via_x() gate, not a stand-in for it.
    """
    plugins = ("Shild", "UndernetX")

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = str(Path(self._tmpdir) / "model.npz")
        self._data_path = str(Path(self._tmpdir) / "shadow.jsonl")
        self._enforcement_path = str(Path(self._tmpdir) / "enforcement.jsonl")
        self._ban_ids_path = str(Path(self._tmpdir) / "ban_ids.json")
        _write_dummy_model(self._model_path, bias_toward="ban")

        conf.supybot.plugins.Shild.classifier.modelPath.setValue(self._model_path)
        conf.supybot.plugins.Shild.shadowDataPath.setValue(self._data_path)
        conf.supybot.plugins.Shild.enforcementLogPath.setValue(self._enforcement_path)
        conf.supybot.plugins.Shild.banIdsPath.setValue(self._ban_ids_path)
        conf.supybot.plugins.Shild.thresholds.classifierAct.setValue(0.5)
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        conf.supybot.plugins.Shild.ignoreList.setValue([])
        conf.supybot.plugins.Shild.decisionCache.enabled.setValue(True)
        conf.supybot.plugins.Shild.decisionCache.ttlSecs.setValue(1800.0)

        super().setUp()

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

    def _queued(self):
        q = self.irc.queue
        return list(q.highpriority) + list(q.normal) + list(q.lowpriority)

    def _make_join(self, nick, ident, host):
        from supybot import ircmsgs
        return ircmsgs.IrcMsg(command="JOIN", args=(self.channel,),
                               prefix=f"{nick}!{ident}@{host}")

    def test_not_opped_available_fires_x_ban_and_kick_not_native(self):
        self._seed_x_usable()
        self.irc.feedMsg(self._make_join("baduser", "~bad", "203.0.113.20"))

        native = [m for m in self._queued()
                  if m.command in ("KICK", "MODE") and m.args[0] == self.channel]
        self.assertEqual(native, [], "must not use the native path when X is available")
        x_privmsgs = [m for m in self._queued()
                      if m.command == "PRIVMSG" and m.args[0] == "X@channels.undernet.org"]
        self.assertEqual(len(x_privmsgs), 2, "expected a BAN then a KICK sent to X")
        self.assertTrue(x_privmsgs[0].args[1].startswith(f"BAN {self.channel} "))
        self.assertTrue(x_privmsgs[1].args[1].startswith(f"KICK {self.channel} "))
        self.assertTrue(Path(self._enforcement_path).exists())
        record = json.loads(Path(self._enforcement_path).read_text().strip().splitlines()[-1])
        self.assertEqual(record["via"], "x")

    def test_not_opped_no_cache_entry_enforces_nothing_but_triggers_a_probe(self):
        # No _seed_x_usable() -- the cache is empty.
        self.irc.feedMsg(self._make_join("baduser2", "~bad", "203.0.113.21"))

        acted = [m for m in self._queued() if m.command in ("KICK", "MODE")]
        self.assertEqual(acted, [], "must not use the native path")
        x_privmsgs = [m for m in self._queued() if m.command == "PRIVMSG"
                      and m.args[0] == "X@channels.undernet.org"]
        self.assertEqual(len(x_privmsgs), 1, "expected exactly one lazy ACCESS probe")
        self.assertTrue(x_privmsgs[0].args[1].startswith("ACCESS "))
        self.assertFalse(Path(self._enforcement_path).exists())

    def test_not_opped_channel_not_opted_in_does_nothing_not_even_a_probe(self):
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(False)
        self.irc.feedMsg(self._make_join("baduser3", "~bad", "203.0.113.22"))
        self.assertEqual(self._queued(), [])
        self.assertFalse(Path(self._enforcement_path).exists())

    def test_not_opped_arm_switch_off_does_nothing_even_with_usable_cache(self):
        self._seed_x_usable()
        conf.supybot.plugins.UndernetX.enforcement.xFallbackEnabled.setValue(False)
        self.irc.feedMsg(self._make_join("baduser4", "~bad", "203.0.113.23"))
        self.assertEqual(self._queued(), [])
        self.assertFalse(Path(self._enforcement_path).exists())

    def test_not_opped_not_identified_does_nothing(self):
        self._seed_x_usable()
        self._x.identified = False
        self.irc.feedMsg(self._make_join("baduser5", "~bad", "203.0.113.24"))
        self.assertEqual(self._queued(), [])

    def test_killswitch_still_gates_the_x_path(self):
        self._seed_x_usable()
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(True)
        self.irc.feedMsg(self._make_join("baduser6", "~bad", "203.0.113.25"))
        x_privmsgs = [m for m in self._queued() if m.command == "PRIVMSG"
                      and m.args[0] == "X@channels.undernet.org"]
        self.assertEqual(x_privmsgs, [], "killSwitch must block the X path too")

    def test_opped_always_uses_native_path_never_x_even_with_usable_cache(self):
        # The single most important guarantee: X is a FALLBACK, never a
        # substitute for real op.
        self._seed_x_usable()
        from supybot import ircmsgs
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="MODE", args=(self.channel, "+o", self.irc.nick),
            prefix="ChanServ!ChanServ@services.",
        ))
        self.irc.feedMsg(self._make_join("baduser7", "~bad", "203.0.113.26"))

        kicks = [m for m in self._queued() if m.command == "KICK"]
        bans = [m for m in self._queued() if m.command == "MODE" and m.args[1] == "+b"]
        self.assertEqual(len(kicks), 1)
        self.assertEqual(len(bans), 1)
        x_privmsgs = [m for m in self._queued() if m.command == "PRIVMSG"
                      and m.args[0] == "X@channels.undernet.org"]
        self.assertEqual(x_privmsgs, [], "opped enforcement must never touch X")
        record = json.loads(Path(self._enforcement_path).read_text().strip().splitlines()[-1])
        self.assertEqual(record["via"], "native")

    def test_unavailable_x_fallback_does_not_consume_a_ban_id(self):
        # No _seed_x_usable() -- unavailable, so the join resolves to
        # "not opped, no X fallback" (a probe fires, but nothing enforces).
        self.irc.feedMsg(self._make_join("baduser8", "~bad", "203.0.113.27"))
        self.assertFalse(Path(self._enforcement_path).exists())

        # A SUBSEQUENT, genuinely available enforcement must still get
        # ban id 1 -- the unavailable miss above must not have consumed one.
        self._seed_x_usable()
        self.irc.feedMsg(self._make_join("baduser9", "~bad", "203.0.113.28"))
        record = json.loads(Path(self._enforcement_path).read_text().strip().splitlines()[-1])
        self.assertIn("[ID: 1]", record["reason"])


class ShildConfigTestCase(ChannelPluginTestCase):
    """shildconfig (2026-08-22) with real SpamGuard and UndernetX
    instances loaded -- unlike ShildTestCase above (neither loaded,
    proves both "not loaded" fallback lines), these tests exercise the
    actual cross-plugin registry reads.
    """
    plugins = ("Shild", "SpamGuard", "UndernetX")

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = str(Path(self._tmpdir) / "model.npz")
        self._data_path = str(Path(self._tmpdir) / "shadow.jsonl")
        _write_dummy_model(self._model_path, bias_toward="allow")

        conf.supybot.plugins.Shild.classifier.modelPath.setValue(self._model_path)
        conf.supybot.plugins.Shild.shadowDataPath.setValue(self._data_path)
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.messageAnalysis.get(self.channel).setValue(True)
        conf.supybot.plugins.Shild.protection.killSwitch.setValue(False)
        conf.supybot.plugins.Shild.ollama.enabled.setValue(True)

        self._sg_terms_path = str(Path(self._tmpdir) / "spamguard_terms.json")
        self._sg_host_bans_path = str(Path(self._tmpdir) / "spamguard_host_bans.json")
        conf.supybot.plugins.SpamGuard.termsPath.setValue(self._sg_terms_path)
        conf.supybot.plugins.SpamGuard.hostBansPath.setValue(self._sg_host_bans_path)
        conf.supybot.plugins.SpamGuard.enabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.floodEnabled.get(self.channel).setValue(True)
        conf.supybot.plugins.SpamGuard.hilightEnabled.get(self.channel).setValue(False)
        conf.supybot.plugins.SpamGuard.capsEnabled.get(self.channel).setValue(False)
        conf.supybot.plugins.SpamGuard.mojibakeEnabled.get(self.channel).setValue(False)
        conf.supybot.plugins.SpamGuard.raidEnabled.get(self.channel).setValue(False)
        conf.supybot.plugins.SpamGuard.protection.killSwitch.setValue(True)
        conf.supybot.plugins.SpamGuard.hostBanAutoRebanEnabled.setValue(False)

        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            self.channel).setValue(True)
        conf.supybot.plugins.UndernetX.enforcement.xFallbackEnabled.setValue(False)

        super().setUp()

        # preferXCommands is a real, already-documented cross-test leak
        # risk -- see plugins/UndernetX/test.py's own setUp for the
        # original, canonical fix and full explanation (2026-08-16): a
        # network+channel-qualified override, once explicitly .setValue()'d
        # by ANY test anywhere in this process, permanently takes
        # precedence over the bare-channel value from then on
        # (getSpecific()'s own resolution order), and merely setting it to
        # a "safe" value doesn't help -- .setValue() always flips _wasSet,
        # so it still wins over the bare form. Must clear ._wasSet directly
        # to genuinely restore "never touched", exactly like UndernetX's
        # own test.py already does. Confirmed live (2026-08-22): a first
        # attempt here that instead tried to defensively re-assert a value
        # in setUp (rather than truly resetting) fixed THIS class but
        # broke ShildXFallbackTestCase/SpamGuardXFallbackTestCase, which
        # only defended the bare-channel form -- this reset avoids the
        # whack-a-mole entirely by never leaving a precedence-winning node
        # behind for any other class to trip over.
        net_specific = conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(
            ":" + self.irc.network).get(self.channel)
        net_specific.setValue(False)
        net_specific._wasSet = False

    def _lines(self, command):
        # getMsg() itself calls irc.takeMsg() once internally to fetch
        # its return value -- the FIRST queued reply -- so it must be
        # captured here too, or it's silently dropped and every
        # subsequent line in the manual drain loop below shifts up by
        # one (same class of gotcha already documented repeatedly in
        # this codebase for a command issued right after real
        # enforcement queued its own messages first).
        first = self.getMsg(command, private=True)
        lines = [first.args[1]] if first is not None else []
        while True:
            m = self.irc.takeMsg()
            if m is None:
                break
            lines.append(m.args[1])
        return lines

    def test_shows_every_shild_and_spamguard_value_for_the_channel(self):
        lines = self._lines(f"shildconfig {self.channel}")

        self.assertIn("Shild.enabled: enabled", lines)
        self.assertIn("Shild.messageAnalysis: enabled", lines)
        self.assertIn("Shild.protection.killSwitch: disabled", lines)
        self.assertIn("Shild.ollama.enabled: enabled", lines)
        self.assertIn("SpamGuard.enabled: enabled", lines)
        self.assertIn("SpamGuard.floodEnabled: enabled", lines)
        self.assertIn("SpamGuard.hilightEnabled: disabled", lines)
        self.assertIn("SpamGuard.capsEnabled: disabled", lines)
        self.assertIn("SpamGuard.mojibakeEnabled: disabled", lines)
        self.assertIn("SpamGuard.raidEnabled: disabled", lines)
        self.assertIn("SpamGuard.protection.killSwitch: enabled", lines)
        self.assertIn("SpamGuard.hostBanAutoRebanEnabled: disabled", lines)
        self.assertIn("UndernetX.enforcement.preferXCommands: enabled", lines)
        self.assertIn("UndernetX.enforcement.xFallbackEnabled: disabled", lines)

    def test_reflects_a_different_channel_toggle_state_independently(self):
        # Per-channel values are genuinely per-channel -- a second
        # channel with different settings must show its OWN state, not
        # leak self.channel's.
        other = "#otherchannel"
        conf.supybot.plugins.Shild.enabled.get(other).setValue(False)
        conf.supybot.plugins.SpamGuard.floodEnabled.get(other).setValue(False)
        conf.supybot.plugins.UndernetX.enforcement.preferXCommands.get(other).setValue(False)

        lines = self._lines(f"shildconfig {other}")
        self.assertIn("Shild.enabled: disabled", lines)
        self.assertIn("SpamGuard.floodEnabled: disabled", lines)
        self.assertIn("UndernetX.enforcement.preferXCommands: disabled", lines)

    def test_channel_value_resolves_network_specific_override(self):
        # 2026-08-22 fix: a bare .get(channel)() would miss a
        # network-qualified override entirely -- must use the same
        # getSpecific(network=, channel=) resolution self.registryValue()
        # itself uses. Sets the network-specific override with the exact
        # same construction callbacks.py's own setRegistryValue() uses
        # internally (group.get(':' + network).get(channel)) -- confirmed
        # by reading that method's source, not guessed; a naive
        # .get(channel).get(':' + network) ordering does NOT work
        # (getSpecific looks for the network segment first).
        val = conf.supybot.plugins.UndernetX.enforcement.preferXCommands
        val.get(self.channel).setValue(True)
        val.get(":" + self.irc.network).get(self.channel).setValue(False)

        lines = self._lines(f"shildconfig {self.channel}")
        self.assertIn("UndernetX.enforcement.preferXCommands: disabled", lines)

    def test_global_switches_unaffected_by_which_channel_is_queried(self):
        # protection.killSwitch/hostBanAutoRebanEnabled/ollama.enabled
        # are global, not channel-scoped -- must read identically
        # regardless of which channel argument is passed.
        lines_a = self._lines(f"shildconfig {self.channel}")
        lines_b = self._lines("shildconfig #some-other-channel-entirely")
        for line in ("Shild.protection.killSwitch: disabled",
                     "SpamGuard.protection.killSwitch: enabled",
                     "SpamGuard.hostBanAutoRebanEnabled: disabled",
                     "UndernetX.enforcement.xFallbackEnabled: disabled"):
            self.assertIn(line, lines_a)
            self.assertIn(line, lines_b)
