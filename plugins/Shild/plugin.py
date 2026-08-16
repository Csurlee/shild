"""Shild — AI + ML classifier analysis, with op-gated real enforcement,
for Limnoria.

Every event in an enabled channel is always analyzed and logged to
data/shadow_decisions.jsonl, regardless of anything below -- shadow-mode
logging/relay is unconditional and never gated by op status or the kill
switch (see _finish()).

**Phase 2 (Protection Mode)**: on top of that unconditional shadow log, a
`ban` verdict additionally becomes a REAL kick+ban when, and only when,
BOTH hold: the bot currently has op in that channel (checked live via
`enforcement.is_opped()`, never cached) AND the global
`protection.killSwitch` is off (it defaults to True -- a fresh deploy is
always safe even if the bot already has op somewhere at startup). `warn`
verdicts take no enforcement action, same as before this phase.
`plugins/Shild/enforcement.py` is the ONLY module allowed to construct a
real KICK/MODE(+b)/UNBAN message -- verify with:

    grep -rEn "ircmsgs\\.(kick|ban|mode)\\(" plugins/Shild/

which is expected to return exactly the lines in enforcement.py, nowhere
else (see that module's docstring).

doKick/doMode ALSO exist here, for a completely different reason: they
REACT to KICK/MODE messages the server sends us about what OTHER people
did (real ops, other bots) -- they never construct one, and are unrelated
to _maybe_enforce()'s real actions. This is free ground truth (a real
op's real decision on a real host) recorded to
data/observed_moderation.jsonl (see collector.py's build_moderation_record).
Both bail immediately if the actor is us (defensive -- the only way that
could happen is via _maybe_enforce's own kick/ban, which is filtered out
explicitly, see doKick/doMode below).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import aiohttp
from supybot import callbacks, ircmsgs, ircutils, log, schedule, world
from supybot.commands import additional, wrap

from shildml import evidence as evidence_mod
from shildml import fusion

from . import enforcement
from . import ollama as ollama_client
from . import prompts
from . import proxyscan
from .ban_ids import BanIdStore
from .budget import BudgetManager, ProviderLimits
from .classifier import ClassifierWrapper
from .collector import Collector, build_enforcement_record, build_moderation_record, build_record
from .context import ContextSnapshot, ContextStore
from .decision_cache import DecisionCache
from .reputation import ReputationConfig, ReputationGatherer, load_secrets
from .worker import Worker

# IRC-display-only abbreviations for the phrases evidence.HostEvidence.summary()
# and fusion.py's reason templates produce. Deliberately NOT applied to
# fused.reason/evidence.summary() themselves -- those stay verbatim (they're
# what's written to shadow_decisions.jsonl and, if Ollama is ever re-enabled,
# what's injected into its prompt), so this only shortens what's actually
# rendered on IRC. Order doesn't matter: every phrase is a distinct substring.
_IRC_REASON_ABBREVIATIONS = [
    (" -- only ", " - "),
    ("AbuseIPDB abuse confidence: ", "AbuseIPDB: "),
    ("Scamalytics fraud score: ", "Scamalytics: "),
    ("IPQS fraud score: ", "IPQS: "),
    ("flagged as proxy/VPN", "Flag: proxy/VPN"),
    ("country: ", "Country: "),
    ("proxy port scan: clean", "proxy scan: clean"),
    ("clean on all blocklists checked", "clean on all blocklists"),
]

_IRC_SOURCE_ABBREVIATIONS = {
    "classifier+evidence": "clas.+evi.",
    "ollama+evidence": "ollama+evi.",
}

_IRC_ACTION_COLOR = {"ban": "red", "warn": "green", "allow": "green"}


def _irc_compact_reason(reason: str) -> str:
    for old, new in _IRC_REASON_ABBREVIATIONS:
        reason = reason.replace(old, new)
    return reason


def _irc_colorize_action(action: str) -> str:
    label = action.upper()
    colored = ircutils.mircColor(label, _IRC_ACTION_COLOR.get(action))
    return ircutils.bold(colored) if action == "ban" else colored


def _top_reputation_score(ev: Optional["evidence_mod.HostEvidence"]) -> Optional[int]:
    """Highest of AbuseIPDB/Scamalytics/IPQS -- all three are already
    0-100 fraud/abuse scales, so "highest" is directly comparable across
    providers without any normalization. None if none of them ran."""
    if ev is None:
        return None
    candidates = [
        s for s in (ev.abuseipdb_score, ev.scamalytics_score, ev.ipqs_fraud_score)
        if s is not None
    ]
    return max(candidates) if candidates else None


def _short_ban_cause(ev: Optional["evidence_mod.HostEvidence"]) -> str:
    """A short, adaptive phrase for the real kick message (2026-08-11
    request) -- picks the single most specific/severe signal available
    rather than concatenating everything the way ev.summary() does.
    Priority order: a hard/independent hit (DNSBL, bogon) is a stronger
    fact than an infrastructure classification, so those come first;
    geo_proxy+a fraud score is the exact case this format was requested
    from; progressively weaker fallbacks after that."""
    if ev is None:
        return "matches known abuse patterns"
    if ev.dronebl_type or ev.dnsbl_hits:
        return "appears to be a listed botnet/proxy host"
    if ev.is_bogon:
        return "is on an unallocated (bogon) IP range"
    has_score = _top_reputation_score(ev) is not None
    if ev.geo_proxy and has_score:
        return "appears to be on a proxy and be fraudulent"
    if ev.open_proxy_ports:
        return "has an open proxy port"
    if ev.geo_proxy:
        return "appears to be on a proxy/VPN"
    if ev.scamalytics_blacklisted:
        return "is on an external fraud blacklist"
    if has_score:
        return "appears to be fraudulent"
    return "matches known abuse patterns"


def _short_ban_score(ev: Optional["evidence_mod.HostEvidence"], classifier_confidence: float) -> int:
    """The highest reputation score if any provider ran, else the
    classifier's own confidence as a 0-100 integer (e.g. a pure
    classifier+evidence escalation with no fraud-score provider
    configured still shows SOMETHING under "score")."""
    top = _top_reputation_score(ev)
    return top if top is not None else round(classifier_confidence * 100)


class Shild(callbacks.Plugin):
    """SHILD AI + ML classifier -- always logs (shadow mode); additionally
    enforces (real kick+ban) a `ban` verdict only where the bot holds op
    and the protection kill switch is off (Phase 2)."""

    # doJoin/doPrivmsg must return fast; all blocking work goes through
    # self._worker (see worker.py). `threaded` only affects command
    # methods, not event hooks, but is set False explicitly for clarity.
    threaded = False

    def __init__(self, irc):
        self.__parent = super(Shild, self)
        self.__parent.__init__(irc)

        self._classifier = ClassifierWrapper(self.registryValue("classifier.modelPath"))
        self._context = ContextStore()
        self._decision_cache = DecisionCache(
            ttl_secs=self.registryValue("decisionCache.ttlSecs"))
        self._worker = Worker(
            max_queue=self.registryValue("worker.maxQueue"),
            max_concurrency=self.registryValue("worker.maxConcurrency"),
        )
        self._worker.start()
        self._collector = Collector(self.registryValue("shadowDataPath"))
        self._moderation_log = Collector(self.registryValue("moderationLogPath"))
        self._enforcement_log = Collector(self.registryValue("enforcementLogPath"))
        self._ban_ids = BanIdStore(self.registryValue("banIdsPath"))
        # Names of scheduled auto-unban events this instance created, so
        # die() can clean them up rather than leaking a callback bound to
        # a dead plugin instance across a reload (same pattern as
        # _reload_event_name below, just plural/dynamic).
        self._pending_unbans: dict[str, None] = {}
        self._session: Optional[aiohttp.ClientSession] = None  # created inside the worker loop
        self._stats = {"joins": 0, "messages": 0, "decisions": 0, "degraded": 0, "gated": 0, "enforced": 0}
        self._ollama_latencies_ms: list[float] = []  # bounded ring for p50/p99 in !shildstatus
        self._started_at = time.time()

        # Phase 1.5: host evidence (DNSBL/IP reputation/cloak trust) and
        # the evidence gate (downgrade gate on ban/warn, plus a narrow
        # evidence-corroborated escalation path added 2026-08-09) -- see
        # shildml/evidence.py and shildml/fusion.py for the design.
        secrets = load_secrets(self.registryValue("secretsPath"))
        self._budget = BudgetManager(
            self.registryValue("budgetPath"),
            limits={
                "ipapi": ProviderLimits(rate_per_min=self.registryValue("ipapi.rateLimitPerMinute")),
                "abuseipdb": ProviderLimits(daily_limit=self.registryValue("abuseipdb.dailyLimit")),
                "ipqs": ProviderLimits(lifetime_limit=self.registryValue("ipqs.lifetimeLimit")),
                "scamalytics": ProviderLimits(daily_limit=self.registryValue("scamalytics.dailyLimit")),
                "scamalytics2": ProviderLimits(daily_limit=self.registryValue("scamalytics.dailyLimit2")),
            },
        )
        self._reputation = ReputationGatherer(
            ReputationConfig(
                dns_timeout=self.registryValue("dnsbl.timeout"),
                http_timeout=self.registryValue("ipapi.timeout"),
                dnsbl_ttl=self.registryValue("dnsbl.cacheTtl"),
                geo_ttl=self.registryValue("ipapi.cacheTtl"),
                tier2_ttl=self.registryValue("dnsbl.cacheTtl"),
                abuseipdb_enabled=self.registryValue("abuseipdb.enabled"),
                abuseipdb_key=secrets["abuseipdb_key"],
                ipqs_enabled=self.registryValue("ipqs.enabled"),
                ipqs_key=secrets["ipqs_key"],
                scamalytics_enabled=self.registryValue("scamalytics.enabled"),
                scamalytics_username=secrets["scamalytics_username"],
                scamalytics_key=secrets["scamalytics_key"],
                scamalytics_username2=secrets["scamalytics_username2"],
                scamalytics_key2=secrets["scamalytics_key2"],
                scamalytics_tiering_enabled=self.registryValue("scamalytics.tieringEnabled"),
                scamalytics_tier_min_abuseipdb=self.registryValue(
                    "scamalytics.tierMinAbuseipdbScore"),
                scamalytics_tier_max_abuseipdb=self.registryValue(
                    "scamalytics.tierMaxAbuseipdbScore"),
                geoip_enabled=self.registryValue("geoip.enabled"),
                geoip_db_path=self.registryValue("geoip.dbPath"),
                blocklist_enabled=self.registryValue("blocklist.enabled"),
                blocklist_dir=self.registryValue("blocklist.dir"),
                blocklist_names=tuple(self.registryValue("blocklist.lists")),
            ),
            self._budget,
        )
        self._proxyscan_cfg = proxyscan.ProxyScanConfig(
            enabled=self.registryValue("proxyscan.enabled"),
            connect_timeout=self.registryValue("proxyscan.connectTimeout"),
            overall_timeout=self.registryValue("proxyscan.overallTimeout"),
        )
        self._evidence_thresholds = evidence_mod.EvidenceThresholds(
            abuseipdb_bad=self.registryValue("evidence.abuseipdbThreshold"),
            ipqs_bad=self.registryValue("evidence.ipqsThreshold"),
            scamalytics_bad=self.registryValue("evidence.scamalyticsThreshold"),
            require_hard_evidence_for_ban=self.registryValue(
                "evidence.requireHardEvidenceForBan"),
            scamalytics_extreme=self.registryValue("evidence.scamalyticsExtreme"),
            abuseipdb_extreme=self.registryValue("evidence.abuseipdbExtreme"),
            ipqs_extreme=self.registryValue("evidence.ipqsExtreme"),
            enable_secondary_ban_escalation=self.registryValue(
                "evidence.enableSecondaryBanEscalation"),
        )

        # Scheduler events are global and survive plugin reload, so use a
        # name unique to this instance and always clear it first.
        self._reload_event_name = f"shildClassifierReload-{id(self)}"
        try:
            schedule.removeEvent(self._reload_event_name)
        except KeyError:
            pass
        schedule.addPeriodicEvent(
            self._classifier.reload_if_needed,
            self.registryValue("classifier.reloadCheckSecs"),
            self._reload_event_name, now=False,
        )

        # 2026-08-06: announce a new daily shadow-data review report (see
        # scripts/daily_data_analysis.sh) to each network's relayChannel
        # once, the first time this instance notices it -- persisted to a
        # marker file in report.dir so a restart mid-day doesn't re-announce
        # the same report. Cheap directory listing, no worker thread needed
        # (unlike Ollama/GitHubWatch's polling, nothing here blocks on I/O
        # slow enough to matter on Limnoria's main loop).
        self._last_announced_report = self._load_last_announced_report()
        self._report_event_name = f"shildReportCheck-{id(self)}"
        try:
            schedule.removeEvent(self._report_event_name)
        except KeyError:
            pass
        schedule.addPeriodicEvent(
            self._check_new_report,
            self.registryValue("report.checkIntervalSecs"),
            self._report_event_name, now=False,
        )

    def die(self):
        try:
            schedule.removeEvent(self._reload_event_name)
        except KeyError:
            pass
        try:
            schedule.removeEvent(self._report_event_name)
        except KeyError:
            pass
        for event_name in list(self._pending_unbans):
            try:
                schedule.removeEvent(event_name)
            except KeyError:
                pass
        self._worker.stop()
        self.__parent.die()

    # ---- helpers ----

    def _enabled(self, irc, channel: str) -> bool:
        return self.registryValue("enabled", channel, irc.network)

    def _is_ignored(self, host: str) -> bool:
        return host.lower() in {h.lower() for h in self.registryValue("ignoreList")}

    def _thresholds(self) -> fusion.Thresholds:
        return fusion.Thresholds(
            classifier_act=self.registryValue("thresholds.classifierAct"),
            ollama_act=self.registryValue("thresholds.ollamaAct"),
            classifier_act_with_evidence=self.registryValue(
                "thresholds.classifierActWithEvidence"),
            classifier_ban_secondary_floor=self.registryValue(
                "thresholds.classifierBanSecondaryFloor"),
        )

    def _format_decision(self, tag: str, nick: str, ident: str, host: str,
                          location: str, fused: fusion.FusedDecision) -> str:
        """The exact text of a decision line -- the one place this format
        is built, so a live [shadow] relay and !shildcheck's [shadow-manual]
        reply can never drift apart. `tag` is "shadow" for a real event,
        "shadow-manual" for an operator-triggered lookup. The action word
        is mIRC-colored and the evidence/reason text is abbreviated for
        IRC display only -- see _irc_compact_reason()'s docstring-level
        comment above the constants for why fused.reason itself is never
        touched.
        """
        action_label = _irc_colorize_action(fused.action)
        source_label = _IRC_SOURCE_ABBREVIATIONS.get(fused.source, fused.source)
        reason = _irc_compact_reason(fused.reason)
        return (
            f"[{tag}] {action_label} {nick} ({ident}@{host}) in "
            f"{location} via {source_label} ({fused.confidence:.0%}): {reason}"
        )

    @staticmethod
    def _queue_wrapped(irc, target: str, text: str) -> None:
        """Queues `text` as one or more PRIVMSGs to `target`, splitting on
        a safe IRC line-length boundary. irc.queueMsg() with a raw
        ircmsgs.privmsg() (unlike irc.reply()'s own more-system) does no
        length checking at all -- a long decision line (a verbose evidence
        summary can easily run past 512 bytes) was getting silently
        truncated mid-word by the server with no indication anything was
        cut off. 400 is a conservative budget under the 512-byte IRC line
        limit, leaving room for the server-added ":nick!user@host PRIVMSG
        target :" framing this side can't know exactly in advance."""
        for chunk in ircutils.wrap(text, 400):
            irc.queueMsg(ircmsgs.privmsg(target, chunk))

    def _relay(self, irc, text: str) -> None:
        relay_chan = self.registryValue("relayChannel", network=irc.network)
        if not relay_chan:
            return
        try:
            self._queue_wrapped(irc, relay_chan, text)
        except Exception:
            log.exception("Shild: failed to relay shadow decision")

    # ---- daily report (scripts/daily_data_analysis.sh) ----

    def _report_dir(self) -> Path:
        return Path(self.registryValue("report.dir"))

    def _report_state_path(self) -> Path:
        return self._report_dir() / ".last_announced"

    def _load_last_announced_report(self) -> str:
        try:
            return self._report_state_path().read_text().strip()
        except OSError:
            return ""

    def _save_last_announced_report(self, name: str) -> None:
        try:
            self._report_dir().mkdir(parents=True, exist_ok=True)
            self._report_state_path().write_text(name)
        except OSError:
            log.exception("Shild: failed to persist last-announced report marker")

    def _latest_report_path(self) -> Optional[Path]:
        try:
            candidates = sorted(self._report_dir().glob("*-report.md"))
        except OSError:
            return None
        return candidates[-1] if candidates else None

    @staticmethod
    def _parse_flagged_hosts(text: str) -> Optional[list[str]]:
        """Extract '- FLAG: ...' lines from a report's '## Flagged hosts'
        section -- see scripts/daily_data_analysis.sh's prompt, which
        requires the daily review agent to lead every report with this
        exact, machine-parseable section (added 2026-08-10 so the most
        actionable part of the report -- specific hosts worth a human's
        attention -- drives the IRC excerpt/!shildreport reply instead of
        whatever prose happened to come first).

        Returns None when no '## Flagged hosts' heading is found at all
        -- an older report written before this format existed, or the
        agent didn't follow instructions -- so callers can fall back to
        the previous whole-body excerpt instead of silently showing
        nothing. Returns [] (not None) for an explicit '- FLAG: none'
        line: that is a real, structured "nothing today" answer, distinct
        from "the format wasn't found at all".
        """
        flag_prefix = "- flag:"
        in_section = False
        found_section = False
        flags: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("## flagged hosts"):
                in_section = True
                found_section = True
                continue
            if in_section and stripped.startswith("##"):
                break  # next section -- stop collecting
            if in_section and stripped.lower().startswith(flag_prefix):
                value = stripped[len(flag_prefix):].strip()
                if value and value.lower() != "none":
                    flags.append(value)
        return flags if found_section else None

    @classmethod
    def _report_excerpt(cls, path: Path, limit: int = 350) -> str:
        text = path.read_text().strip()

        flags = cls._parse_flagged_hosts(text)
        if flags is not None:
            if not flags:
                return "nothing flagged today"
            prefix = f"{len(flags)} flagged: "
            joined = "; ".join(flags)
            budget = max(limit - len(prefix), 0)
            if len(joined) > budget:
                joined = joined[:budget].rsplit(" ", 1)[0] + "..."
            return prefix + joined

        # Fallback for a report with no '## Flagged hosts' section (older
        # format, or the agent didn't follow instructions) -- reproduces
        # the original whole-body-truncated behavior so nothing breaks.
        lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        body = " ".join(" ".join(lines).split())  # collapse to one line, normalize whitespace
        if len(body) <= limit:
            return body
        return body[:limit].rsplit(" ", 1)[0] + "..."

    def _check_new_report(self) -> None:
        if not self.registryValue("report.announce"):
            return
        latest = self._latest_report_path()
        if latest is None or latest.name == self._last_announced_report:
            return
        self._last_announced_report = latest.name
        self._save_last_announced_report(latest.name)
        try:
            excerpt = self._report_excerpt(latest)
        except OSError:
            log.exception("Shild: failed to read new daily report %s", latest)
            return
        text = f"[daily report] {excerpt} -- !shildreport for more"
        for irc in world.ircs:
            self._relay(irc, text)

    # ---- event hooks ----

    def doJoin(self, irc, msg):
        channel = msg.channel
        if channel is None or msg.nick == irc.nick:
            return
        if not self._enabled(irc, channel) or not msg.host:
            return
        self._stats["joins"] += 1
        self._handle_event(irc, msg, event_type="join")

    def doPrivmsg(self, irc, msg):
        channel = msg.channel
        if channel is None or msg.nick == irc.nick:
            return  # ignore private messages and our own output
        if not self._enabled(irc, channel) or ircmsgs.isCtcp(msg):
            return
        if not self.registryValue("messageAnalysis", channel, irc.network):
            return  # joins still analyzed -- see config.py's messageAnalysis docstring
        self._stats["messages"] += 1
        self._handle_event(irc, msg, event_type="message")

    def doKick(self, irc, msg):
        """Observes a kick made by SOMEONE ELSE -- never by us (see module
        docstring). This is the free ground truth an op's real decision
        gives us: no Ollama call, no evidence lookup, just a synchronous
        classifier read (if we know enough about the target) and a JSONL
        record, purely for later analysis.
        """
        channel = msg.channel
        if channel is None or not self._enabled(irc, channel):
            return
        if msg.nick == irc.nick:
            return  # can't currently happen -- we have no kick capability
        network = irc.network
        reason = msg.args[2] if len(msg.args) > 2 else ""
        for target_nick in msg.args[1].split(','):
            identity = self._context.identity_for_nick(network, target_nick)
            target_ident, target_host = identity if identity else (None, None)
            classifier_result = None
            if target_ident and target_host:
                classifier_result = self._classifier.predict(target_nick, target_ident, target_host)
            record = build_moderation_record(
                network=network, channel=channel, event_type="kick",
                actor_nick=msg.nick, actor_ident=msg.user, actor_host=msg.host,
                target_nick=target_nick, target_ident=target_ident, target_host=target_host,
                reason=reason, classifier=classifier_result,
            )
            try:
                self._moderation_log.write(record)
            except Exception:
                log.exception("Shild: failed to write observed kick record")

    def doMode(self, irc, msg):
        """Observes a ban/quiet (+b/+q) set by SOMEONE ELSE -- see doKick
        above and the module docstring. A ban mask in the standard
        nick!ident@host form carries the host directly; we extract it
        best-effort for later evidence cross-referencing, but never run
        the classifier here (a mask's nick/ident portion is usually a
        wildcard, not a real identity, so a prediction from it would be
        meaningless).
        """
        channel = msg.channel
        if channel is None or not self._enabled(irc, channel):
            return
        if msg.nick == irc.nick:
            return  # can't currently happen -- we have no mode capability
        network = irc.network
        for mode, value in ircutils.separateModes(msg.args[1:]):
            if mode not in ('+b', '+q') or not value:
                continue
            target_host = value.rsplit('@', 1)[-1] if '@' in value else None
            record = build_moderation_record(
                network=network, channel=channel, event_type="ban",
                actor_nick=msg.nick, actor_ident=msg.user, actor_host=msg.host,
                target_nick=None, target_ident=None, target_host=target_host,
                ban_mask=value,
            )
            try:
                self._moderation_log.write(record)
            except Exception:
                log.exception("Shild: failed to write observed ban record")

    # ---- decision pipeline ----

    def _handle_event(self, irc, msg, event_type: str) -> None:
        network = irc.network
        channel = msg.channel
        nick, ident, host = msg.nick, msg.user, msg.host
        account = msg.server_tags.get("account") if msg.server_tags else None
        text = msg.args[1] if event_type == "message" and len(msg.args) > 1 else ""

        # Snapshot BEFORE any evaluation -- see context.py docstring for
        # why this ordering is the structural fix for the old system's
        # in_global_bad label-leakage bug.
        ctx = self._context.snapshot(network, channel, nick, ident, host, account=account)
        self._context.record_event(network, channel, event_type, nick, host=host, detail=text)

        classifier_result = self._classifier.predict(
            nick, ident, host, join_rate=ctx.join_rate,
            account_present=ctx.account_present, cross_chan_count=ctx.cross_chan_count,
        )

        if self._is_ignored(host):
            # Admin override (shildignore) is conclusive on its own --
            # skip evidence/Ollama entirely, same as Tier 0 trust below,
            # but classifier_result is still recorded (informational
            # only, not used) for later analysis. See
            # shildml.fusion.ignored_bypass's docstring for why this is
            # NOT the same training-label trustworthiness as trust
            # bypass (source="trust", label_quality="ok").
            fused = fusion.ignored_bypass(host)
            self._finish(irc, network, channel, event_type, nick, ident, host, account,
                         ctx, classifier_result, None, fused, fused, None, None)
            return

        if self.registryValue("decisionCache.enabled"):
            cached = self._decision_cache.get(network, host)
            if cached is not None:
                # Same host, already decided recently -- see
                # decision_cache.py's module docstring for the real
                # incident this fixes (a flapping client re-triggering
                # the full evidence pipeline every 15-90s) and why this
                # is keyed by host, not (nick, host). Skips the shadow-log
                # write and relay (neither carries anything new) but
                # still runs real enforcement if newly eligible -- op
                # status or the kill switch could have changed since the
                # cached decision was made.
                cached_fused, cached_evidence = cached
                self._maybe_enforce(irc, network, channel, nick, ident, host,
                                     cached_fused, cached_evidence)
                return
            if self._decision_cache.is_in_flight(network, host):
                # A burst of near-simultaneous events for this same
                # host, arriving before the FIRST one's own evaluation
                # has resolved (real incident, 2026-08-16 -- see
                # decision_cache.py's module docstring). Nothing to
                # enforce with yet, and the in-flight evaluation's own
                # _finish() already covers this host once it resolves --
                # drop this event outright rather than dispatching a
                # redundant worker task.
                return

        thresholds = self._thresholds()
        classifier_confident = (
            classifier_result is not None
            and classifier_result.confidence >= thresholds.classifier_act
        )

        evidence_enabled = self.registryValue("evidence.enabled")
        ollama_enabled = self.registryValue("ollama.enabled")

        # Tier 0 evidence (cloak trust, account presence) is pure/local --
        # no I/O -- so it's always cheap to check up front, regardless of
        # whether the classifier was confident. Computed once, reused by
        # both branches below.
        tier0_ev = None
        if evidence_enabled:
            cloak, trust_tier, is_tor_gateway = evidence_mod.classify_cloak(host)
            if trust_tier != evidence_mod.TRUST_NONE or account:
                tier0_ev = evidence_mod.HostEvidence(
                    cloak=cloak, trust_tier=trust_tier,
                    account_present=bool(account), is_tor_exit=is_tor_gateway,
                )

        if classifier_confident:
            raw = fusion.decide_raw(classifier_result, None, thresholds)
            if raw.action == "allow":
                # Nothing to gate -- no evidence needed at all.
                self._finish(irc, network, channel, event_type, nick, ident, host, account,
                             ctx, classifier_result, None, raw, raw, None, None)
                return

            # A ban/warn is on the table. If Tier 0 is already conclusive
            # (trusted cloak or a services account), the whole decision
            # resolves synchronously with no network access at all. Only
            # an inconclusive Tier 0 (a bare IP/hostname with no cloak)
            # needs the worker, and even then only for evidence lookups --
            # Ollama is skipped entirely since the classifier was already
            # confident.
            if not evidence_enabled or tier0_ev is not None:
                fused = (
                    fusion.decide(classifier_result, None, thresholds, evidence=tier0_ev,
                                   evidence_thresholds=self._evidence_thresholds)
                    if evidence_enabled else raw
                )
                self._finish(irc, network, channel, event_type, nick, ident, host, account,
                             ctx, classifier_result, None, fused, raw, None, tier0_ev)
                return
            # else: fall through to the worker for Tier 1+ (network) evidence.

        elif tier0_ev is not None:
            # Classifier wasn't confident -- previously this always fell
            # through to a full Ollama round-trip regardless of trust.
            # Analysis of the shadow corpus (2026-08-06) showed the
            # classifier has never once reached its confident-enough
            # threshold, so this was the ONLY path any event ever took --
            # meaning a trusted, cloaked, NickServ-registered user was
            # always sent through Ollama anyway, where a small model
            # doesn't reliably honor its own "trusted hosts, always allow"
            # system-prompt instruction (it stayed harmless only because
            # its confidence never cleared the acting threshold either).
            # Tier 0 trust alone is conclusive here too -- skip Ollama.
            fused = fusion.trusted_bypass(tier0_ev)
            self._finish(irc, network, channel, event_type, nick, ident, host, account,
                         ctx, classifier_result, None, fused, fused, None, tier0_ev)
            return

        config = ollama_client.OllamaConfig(
            url=self.registryValue("ollama.url"),
            model=self.registryValue("ollama.model"),
            timeout=self.registryValue("ollama.timeout"),
        )

        include_ircbl = self.registryValue("dnsbl.ircblEnabled")

        def coro_factory():
            return self._evaluate(
                classifier_confident, ollama_enabled, event_type, nick, ident, host, channel,
                account, text, ctx, config, evidence_enabled, include_ircbl,
            )

        def on_result(outcome):
            if isinstance(outcome, BaseException):
                ollama_result = None if (classifier_confident or not ollama_enabled) else \
                    fusion.OllamaResult(ok=False, degraded_reason=type(outcome).__name__)
                latency_ms = None
                ev = None
            else:
                ollama_result, latency_ms, ev = outcome
                if latency_ms is not None:
                    self._ollama_latencies_ms.append(latency_ms)
                    if len(self._ollama_latencies_ms) > 500:
                        self._ollama_latencies_ms.pop(0)
            fused_raw = fusion.decide_raw(classifier_result, ollama_result, thresholds,
                                           ollama_disabled=not ollama_enabled)
            fused = (
                fusion.decide(classifier_result, ollama_result, thresholds,
                               evidence=ev, evidence_thresholds=self._evidence_thresholds,
                               ollama_disabled=not ollama_enabled)
                if evidence_enabled and ev is not None else fused_raw
            )
            self._finish(irc, network, channel, event_type, nick, ident, host, account,
                         ctx, classifier_result, ollama_result, fused, fused_raw, latency_ms, ev)

        if self.registryValue("decisionCache.enabled"):
            self._decision_cache.mark_in_flight(network, host)
        self._worker.submit(coro_factory, on_result)

    async def _evaluate(self, classifier_confident, ollama_enabled, event_type, nick, ident,
                         host, channel, account, text, ctx, ollama_config, evidence_enabled,
                         include_ircbl=True):
        """Runs on the worker thread. Gathers host evidence first (Tier
        0-3, see reputation.py/proxyscan.py) -- always, regardless of
        ollama_enabled, since evidence still enriches the record and feeds
        the gate for a confident classifier's ban/warn -- then either: (a)
        returns immediately if the classifier was already confident, or
        Ollama is disabled by config (2026-08-06), or (b) builds the
        Ollama prompt WITH the evidence summary embedded and calls Ollama.
        Returns (ollama_result, latency_ms, evidence) so the caller's
        on_result can fuse+record.

        include_ircbl (2026-08-16): False on the live join/message path by
        default (dnsbl.ircblEnabled), True always for !shildcheck -- see
        that config value's docstring and reputation.gather()'s own
        comment for why IRCBL is live-disabled but still manually
        queryable.
        """
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

        ev = None
        if evidence_enabled:
            # proxyscan now runs concurrently with Tier 1/2 inside
            # gather() itself (2026-08-13, see reputation.py's gather()
            # docstring comment) rather than as a separate sequential
            # step here -- gather() already knows resolved_ip/trust_tier
            # by the time it decides whether to launch it, so the
            # enabled/resolved/trust-tier gate lives there now too.
            ev = await self._reputation.gather(
                self._session, host, account, allow_tier2=True,
                proxyscan_cfg=self._proxyscan_cfg, include_ircbl=include_ircbl,
            )

        if classifier_confident or not ollama_enabled:
            return None, None, ev

        evidence_summary = ev.summary() if ev is not None else ""
        if event_type == "join":
            user_prompt = prompts.build_join_prompt(
                nick, ident, host, channel,
                channel_context=ctx.channel_context, host_context=ctx.host_context,
                evidence_summary=evidence_summary,
            )
        else:
            user_prompt = prompts.build_message_prompt(
                nick, channel, text, channel_context=ctx.channel_context,
                evidence_summary=evidence_summary,
            )

        ollama_result, latency_ms = await ollama_client.analyze(
            self._session, ollama_config, prompts.SYSTEM_PROMPT, user_prompt,
        )
        return ollama_result, latency_ms, ev

    def _finish(self, irc, network, channel, event_type, nick, ident, host, account,
                ctx, classifier_result, ollama_result, fused, fused_raw, ollama_latency_ms,
                evidence) -> None:
        # Unconditional (not gated on decisionCache.enabled) so a stuck
        # in-flight marker can never survive a live toggle of that
        # setting mid-evaluation -- discard() is a harmless no-op if
        # this host was never marked in the first place (every
        # synchronous _finish() call site, which never marks in-flight
        # at all, hits exactly that no-op path).
        self._decision_cache.clear_in_flight(network, host)
        if self.registryValue("decisionCache.enabled"):
            self._decision_cache.set(network, host, fused, evidence)
        self._stats["decisions"] += 1
        if fused.degraded:
            self._stats["degraded"] += 1
        if fused.gate_applied:
            self._stats["gated"] += 1

        record = build_record(
            network=network, channel=channel, event_type=event_type,
            nick=nick, ident=ident, host=host, account=account, ctx=ctx,
            classifier=classifier_result, ollama=ollama_result, fused=fused,
            fused_raw=fused_raw, evidence=evidence, ollama_latency_ms=ollama_latency_ms,
        )
        try:
            self._collector.write(record)
        except Exception:
            log.exception("Shild: failed to write shadow decision record")

        if fused.action != "allow" and not fused.degraded:
            self._relay(
                irc,
                self._format_decision("shadow", nick, ident, host,
                                       f"{network}/{channel}", fused),
            )

        self._maybe_enforce(irc, network, channel, nick, ident, host, fused, evidence)

    def _x_fallback(self, irc, channel):
        """The live UndernetX plugin instance iff X-routed enforcement
        would actually work in `channel` RIGHT NOW, else None
        (2026-08-16). Looked up fresh via irc.getCallback on every call,
        never cached -- same discipline as WebPanel's own
        shild_callback()/ChannelStats lookups (a cached reference would
        keep reading a dead instance after a `@reload UndernetX`).
        Degrades to None with zero errors if UndernetX isn't loaded at
        all, so a deployment without it behaves exactly as before this
        feature existed.
        """
        cb = irc.getCallback("UndernetX")
        if cb is None:
            return None
        try:
            return cb if cb.x_enforcement_available(irc, channel) else None
        except Exception:
            log.exception("Shild: UndernetX availability check failed")
            return None

    def _maybe_enforce(self, irc, network, channel, nick, ident, host, fused, evidence) -> None:
        """Phase 2: turns a `ban` verdict into a real kick+ban, but only
        where BOTH hold: the global kill switch is off, AND the bot can
        actually act -- either it holds real op in this channel right
        now (checked live, never cached), or (2026-08-16) it lacks op
        but UndernetX confirms a live-verified X capability there (see
        `_x_fallback` above and plugins/UndernetX/xprobe.py). `warn`
        takes no action here, same as always. This runs AFTER the
        unconditional shadow-log write/relay above -- shadow logging
        never depends on any of this.
        """
        if fused.action != "ban" or fused.degraded:
            return
        if self.registryValue("protection.killSwitch"):
            return

        xcb = None
        if not enforcement.is_opped(irc, channel):
            xcb = self._x_fallback(irc, channel)
            if xcb is None:
                return  # exactly today's behavior: not opped, no X fallback available

        duration = self.registryValue("protection.banDurationSecs")
        # Short, adaptive kick message (2026-08-11 request) -- built from
        # evidence's own structured fields, not fused.reason's full
        # verbose summary (still recorded verbatim in the enforcement
        # log below and in shadow_decisions.jsonl, unaffected by this --
        # IRC-display-only, same convention as _irc_compact_reason()
        # above). ban_id is assigned only once enforcement is actually
        # about to happen, not earlier -- a decision that never reaches
        # here (killswitch/not-opped-and-no-X-fallback) never consumes
        # an id.
        ban_id = self._ban_ids.next_id()
        cause = _short_ban_cause(evidence)
        score = _short_ban_score(evidence, fused.confidence)
        kick_reason = f"SHILD: {host} {cause} (score: {score}) [ID: {ban_id}]"

        mask = enforcement.ban_mask(host)
        via = "x" if xcb is not None else "native"
        try:
            if xcb is not None:
                if not xcb.enforce_ban_via_x(irc, channel, nick, mask, kick_reason,
                                              duration_secs=duration):
                    log.warning("Shild: X enforcement declined for %s in %s/%s",
                                mask, network, channel)
                    return
            else:
                mask = enforcement.enforce_ban(irc, channel, nick, host, kick_reason)
        except Exception:
            log.exception("Shild: failed to enforce ban")
            return

        unban_at = time.time() + duration
        event_name = f"shild-unban-{id(self)}-{network}-{channel}-{mask}-{unban_at}"

        def _do_unban():
            self._pending_unbans.pop(event_name, None)
            live_irc = world.getIrc(network)
            if live_irc is None:
                return
            try:
                if via == "x":
                    x_cb = live_irc.getCallback("UndernetX")
                    if x_cb is None:
                        log.warning("Shild: UndernetX no longer loaded; cannot lift "
                                    "X ban %s in %s/%s", mask, network, channel)
                        return
                    x_cb.unban_via_x(live_irc, channel, mask)
                else:
                    enforcement.unban(live_irc, channel, mask)
            except Exception:
                log.exception("Shild: failed to auto-unban %s in %s/%s", mask, network, channel)

        self._pending_unbans[event_name] = None
        schedule.addEvent(_do_unban, unban_at, name=event_name)

        record = build_enforcement_record(
            id=ban_id,
            network=network, channel=channel, nick=nick, ident=ident, host=host,
            ban_mask=mask, reason=kick_reason, duration_secs=duration, unban_at=unban_at,
            fused=fused, via=via,
        )
        try:
            self._enforcement_log.write(record)
        except Exception:
            log.exception("Shild: failed to write enforcement action record")
        self._stats["enforced"] += 1

    # ---- the only command ----

    def stats_snapshot(self) -> dict:
        """A shallow copy of the live event/decision counters -- safe to
        call from off the IRC thread (WebPanel's HTTP thread does; see
        plugins/WebPanel's overview page). dict() is one C-level copy, so
        no lock is needed the way ContextStore's deques/dicts require
        one -- these are simple int counters replaced by reassignment,
        never mutated in place across threads.
        """
        return dict(self._stats)

    def runtime_snapshot(self) -> dict:
        """Everything `!shildstatus` reports, as data rather than
        pre-formatted text -- both `shildstatus` below and WebPanel's
        overview page format THIS, so IRC and the web panel can never
        drift out of sync with each other. Safe to call from off the IRC
        thread (see stats_snapshot's docstring; every field read here is
        either an immutable snapshot-worthy value or, like `_stats`, a
        plain counter dict)."""
        lat = sorted(self._ollama_latencies_ms)
        p50 = lat[len(lat) // 2] if lat else None
        p99 = lat[int(len(lat) * 0.99)] if lat else None
        return {
            "uptime_secs": int(time.time() - self._started_at),
            "classifier_available": self._classifier.available,
            "classifier_schema_hash": (
                self._classifier.schema_hash if self._classifier.available else None
            ),
            "worker_running": self._worker.running,
            "worker_dropped_count": self._worker.dropped_count,
            "ollama_enabled": self.registryValue("ollama.enabled"),
            "ollama_latency_p50_ms": p50,
            "ollama_latency_p99_ms": p99,
            "stats": self.stats_snapshot(),
            "evidence_cache_size": self._reputation.cache_size(),
            "budget_stats": self._budget.stats(),
            "kill_switch": self.registryValue("protection.killSwitch"),
            "pending_unbans": len(self._pending_unbans),
            "ignore_list_size": len(self.registryValue("ignoreList")),
        }

    def context_store(self) -> ContextStore:
        """Accessor so callers (WebPanel) never reach into `self._context`
        directly -- keeps ContextStore's own locking/copy-on-read
        contract (see context.py) as the one place that matters."""
        return self._context

    def shildstatus(self, irc, msg, args):
        """takes no arguments

        Reports Shild's status: classifier/model info, Ollama reachability,
        queue health, decision counts, and protection-mode state. Read-only,
        owner-only (2026-08-09) -- this plugin's commands surface real
        people's nicks/hosts/reputation data, same reasoning as WebPanel's
        auth gate.
        """
        snap = self.runtime_snapshot()
        stats = snap["stats"]
        lat_line = "ollama: disabled (classifier-only)"
        if snap["ollama_enabled"]:
            lat_line = (
                f"ollama latency p50/p99 (ms): "
                f"{snap['ollama_latency_p50_ms']}/{snap['ollama_latency_p99_ms']}"
                if snap["ollama_latency_p50_ms"] is not None
                else "ollama latency: no samples yet"
            )

        # Sent as two DELIBERATE messages, not one long line, on purpose:
        # a single long irc.reply() gets silently truncated by Limnoria's
        # own length limit and queued behind a "(1 more message)" that
        # requires the requester to know to ask for it (via the `more`
        # command) -- easy to miss entirely, which is exactly what
        # happened here. Two explicit irc.reply() calls always both
        # arrive with no follow-up action needed.
        general = [
            f"shild-py up {snap['uptime_secs']}s (always shadow-logs; enforces only where "
            f"opped and protection.killSwitch is off)",
            f"classifier: {'loaded' if snap['classifier_available'] else 'unavailable'} "
            f"(schema_hash={snap['classifier_schema_hash'][:12] if snap['classifier_schema_hash'] else 'n/a'})",
            f"worker: {'running' if snap['worker_running'] else 'STOPPED'}, "
            f"dropped={snap['worker_dropped_count']}",
            lat_line,
            f"events since restart: joins={stats['joins']} messages={stats['messages']} "
            f"decisions={stats['decisions']} degraded={stats['degraded']} "
            f"gated={stats['gated']}",
        ]
        protection = [
            f"evidence cache: {snap['evidence_cache_size']} entries | "
            f"budget: {snap['budget_stats']}",
            f"protection: killSwitch={'ON (safe)' if snap['kill_switch'] else 'OFF (live)'} "
            f"enforced={stats['enforced']} pending_unbans={snap['pending_unbans']} "
            f"ignored_hosts={snap['ignore_list_size']}",
        ]
        irc.reply(" | ".join(general))
        irc.reply(" | ".join(protection))

    shildstatus = wrap(shildstatus, ["owner"])

    def shildreport(self, irc, msg, args, date):
        """[<YYYY-MM-DD>]

        Returns an excerpt of the daily shadow-data review report (see
        scripts/daily_data_analysis.sh) -- defaults to the most recent
        one. Full text is on disk at the path given in the reply.
        Owner-only (2026-08-09), same reasoning as shildstatus.
        """
        if date:
            path = self._report_dir() / f"{date}-report.md"
            if not path.exists():
                irc.error(f"No report found for {date}.")
                return
        else:
            path = self._latest_report_path()
            if path is None:
                irc.error("No daily reports yet -- see scripts/daily_data_analysis.sh.")
                return
        try:
            excerpt = self._report_excerpt(path, limit=400)
        except OSError:
            irc.error(f"Found {path} but couldn't read it.")
            return
        irc.reply(f"{path.stem}: {excerpt}")
        irc.reply(f"Full report: {path}")
    shildreport = wrap(shildreport, ["owner", additional("somethingWithoutSpaces")])

    # ---- !shildcheck (manual, on-demand host/nick lookup) ----

    def _resolve_check_target(self, irc, target: str):
        """Resolves a !shildcheck argument to (nick, ident, host), or
        None if it's neither a known nick nor host/IP-shaped. Tried in
        order:

        1. ContextStore's identity cache -- populated by any join/message
           Shild has already analyzed on this network, works even if the
           nick has since left.
        2. Limnoria's own live IrcState -- covers a currently-connected
           nick Shild has never evaluated (e.g. a channel with analysis
           off), independent of anything this plugin has recorded.
        3. Otherwise, `target` itself, treated as a bare host/IP -- but
           only if it's actually host-shaped (contains '.' or ':'), so a
           mistyped nick isn't silently misread as a hostname and fed to
           the classifier and third-party reputation providers.
        """
        network = irc.network
        identity = self._context.identity_for_nick(network, target)
        if identity is not None:
            ident, host = identity
            return target, ident, host

        try:
            hostmask = irc.state.nickToHostmask(target)
        except KeyError:
            hostmask = None
        if hostmask and ircutils.isUserHostmask(hostmask):
            _nick, ident, host = ircutils.splitHostmask(hostmask)
            return target, ident, host

        if "." in target or ":" in target:
            return target, "", target
        return None

    def shildcheck(self, irc, msg, args, target):
        """<nick or host/IP>

        Manually runs the same classifier + evidence pipeline a live join
        would against a nick Shild has already seen (or is currently
        connected), or a bare host/IP -- and replies with the decision in
        the same format as a live [shadow] line, tagged [shadow-manual]
        so it's clearly an operator-triggered lookup rather than a real
        event. Always read-only: never writes to shadow_decisions.jsonl
        (this isn't a real event -- recording it would pollute the
        training corpus with a synthetic sample that never actually
        happened) and never enforces, regardless of the result or the
        kill switch. Owner-only (2026-08-09): it also spends real
        third-party API budget (AbuseIPDB/IPQS) per lookup.

        Also shows any OTHER nicks this host has connected as (2026-08-16,
        see context.py's nick_history_for_host) -- real ban-evasion
        detection, e.g. "also seen as: evader1, evader2" -- when there's
        any history to show; silent otherwise.
        """
        resolved = self._resolve_check_target(irc, target)
        if resolved is None:
            irc.error(f"No known nick and doesn't look like a host/IP: {target}")
            return
        nick, ident, host = resolved
        network = irc.network
        channel = msg.channel
        reply_to = channel or msg.nick
        location = f"{network}/{channel}" if channel else network

        irc.reply(f"[shadow-manual] checking {target} ({nick} {ident}@{host} on "
                  f"{network}) ...")

        history = self._context.nick_history_for_host(network, host, exclude_nick=nick)
        if history:
            irc.reply(f"[shadow-manual] {host} also seen as: {', '.join(history)}")

        if self._is_ignored(host):
            # Reflects reality: a live event for this host would never
            # reach the classifier/evidence pipeline either (see
            # _handle_event) -- showing a real BAN/WARN read here would
            # be misleading about what actually happens for this host.
            self._queue_wrapped(
                irc, reply_to,
                self._format_decision("shadow-manual", nick, ident, host, location,
                                       fusion.ignored_bypass(host)),
            )
            return

        join_rate, cross_chan_count = self._context.observed_context(network, host)
        ctx = ContextSnapshot(join_rate=join_rate, cross_chan_count=cross_chan_count,
                               account_present=False, channel_context="", host_context="")

        classifier_result = self._classifier.predict(
            nick, ident, host, join_rate=ctx.join_rate,
            account_present=ctx.account_present, cross_chan_count=ctx.cross_chan_count,
        )
        thresholds = self._thresholds()
        classifier_confident = (
            classifier_result is not None
            and classifier_result.confidence >= thresholds.classifier_act
        )
        evidence_enabled = self.registryValue("evidence.enabled")
        ollama_enabled = self.registryValue("ollama.enabled")

        tier0_ev = None
        if evidence_enabled:
            cloak, trust_tier, is_tor_gateway = evidence_mod.classify_cloak(host)
            if trust_tier != evidence_mod.TRUST_NONE:
                tier0_ev = evidence_mod.HostEvidence(
                    cloak=cloak, trust_tier=trust_tier,
                    account_present=False, is_tor_exit=is_tor_gateway,
                )

        def _send(fused, ev=None):
            # queueMsg, not irc.reply() -- this can fire from the worker
            # thread's on_result callback, well after this command method
            # has already returned. queueMsg is documented thread-safe
            # (see worker.py); it's also what the live [shadow] relay
            # uses for the exact same reason.
            self._queue_wrapped(
                irc, reply_to,
                self._format_decision("shadow-manual", nick, ident, host, location, fused),
            )
            # 2026-08-14: unlike the live [shadow] relay (which only ever
            # posts non-allow decisions, so terseness is fine),
            # !shildcheck always replies -- including a clean "allow"
            # after a real Tier 1-3 lookup genuinely ran. fused.reason
            # only ever embeds evidence text when the gate/escalation
            # actually modified the decision, so a clean result showed
            # nothing about what was checked at all. Always show the
            # gathered evidence explicitly, regardless of outcome, so a
            # manual investigative check never looks like it did nothing.
            if ev is not None:
                self._queue_wrapped(
                    irc, reply_to, f"[shadow-manual] evidence: {ev.summary()}",
                )

        if classifier_confident:
            raw = fusion.decide_raw(classifier_result, None, thresholds)
            if raw.action == "allow" or not evidence_enabled or tier0_ev is not None:
                fused = (
                    fusion.decide(classifier_result, None, thresholds, evidence=tier0_ev,
                                   evidence_thresholds=self._evidence_thresholds)
                    if evidence_enabled and raw.action != "allow" else raw
                )
                _send(fused, tier0_ev)
                return
            # else: classifier confident on ban/warn, evidence enabled,
            # Tier 0 inconclusive -- fall through to the worker for
            # Tier 1+ evidence, same as a live event would.
        elif tier0_ev is not None:
            _send(fusion.trusted_bypass(tier0_ev), tier0_ev)
            return

        config = ollama_client.OllamaConfig(
            url=self.registryValue("ollama.url"),
            model=self.registryValue("ollama.model"),
            timeout=self.registryValue("ollama.timeout"),
        )

        def coro_factory():
            # Always True, regardless of dnsbl.ircblEnabled -- a manual
            # check carries no live-enforcement risk or latency pressure,
            # and an operator investigating a host benefits from every
            # available signal (2026-08-16, see that config value's
            # docstring).
            return self._evaluate(
                classifier_confident, ollama_enabled, "join", nick, ident, host,
                channel or "", None, "", ctx, config, evidence_enabled, True,
            )

        def on_result(outcome):
            if isinstance(outcome, BaseException):
                ollama_result = None if (classifier_confident or not ollama_enabled) else \
                    fusion.OllamaResult(ok=False, degraded_reason=type(outcome).__name__)
                ev = None
            else:
                ollama_result, _latency_ms, ev = outcome
            fused = (
                fusion.decide(classifier_result, ollama_result, thresholds,
                               evidence=ev, evidence_thresholds=self._evidence_thresholds,
                               ollama_disabled=not ollama_enabled)
                if evidence_enabled and ev is not None else
                fusion.decide_raw(classifier_result, ollama_result, thresholds,
                                   ollama_disabled=not ollama_enabled)
            )
            _send(fused, ev)

        self._worker.submit(coro_factory, on_result)

    shildcheck = wrap(shildcheck, ["owner", "somethingWithoutSpaces"])

    # ---- ignore list (2026-08-10) ----

    def shildignore(self, irc, msg, args, target):
        """<nick or host/IP>

        Adds a host to Shild's ignore list -- future joins/messages from
        it resolve straight to allow, skipping the classifier/evidence/
        Ollama pipeline entirely (see shildml.fusion.ignored_bypass).
        For a known friend, the operator's own second bot, or anything
        else that shouldn't be judged. <nick or host/IP> is resolved the
        same way !shildcheck resolves its target -- a nick is turned
        into ITS CURRENT HOST right now, a one-time snapshot (a bare
        nick is never stored, since anyone could take it later).
        Owner-only, same reasoning as every other Shild command.
        """
        resolved = self._resolve_check_target(irc, target)
        if resolved is None:
            irc.error(f"No known nick and doesn't look like a host/IP: {target}")
            return
        host = resolved[2]
        if self._is_ignored(host):
            irc.reply(f"{host} is already on the ignore list.")
            return
        hosts = self.registryValue("ignoreList")
        self.setRegistryValue("ignoreList", sorted(hosts + [host]))
        irc.replySuccess(f"{host} added to the ignore list.")
    shildignore = wrap(shildignore, ["owner", "somethingWithoutSpaces"])

    def shildunignore(self, irc, msg, args, target):
        """<nick or host/IP>

        Removes a host from Shild's ignore list. Tries an exact match
        against what's actually stored first (the common case -- copying
        a host straight out of !shildlistignore's output); if that
        doesn't match anything, falls back to resolving <target> as a
        nick the same way !shildignore/!shildcheck do, in case it no
        longer resolves to the same host it was added under.
        """
        hosts = self.registryValue("ignoreList")
        matched = [h for h in hosts if h.lower() == target.lower()]
        if not matched:
            resolved = self._resolve_check_target(irc, target)
            if resolved is not None:
                host = resolved[2]
                matched = [h for h in hosts if h.lower() == host.lower()]
        if not matched:
            irc.error(f"{target} is not on the ignore list.")
            return
        remaining = [h for h in hosts if h not in matched]
        self.setRegistryValue("ignoreList", sorted(remaining))
        irc.replySuccess()
    shildunignore = wrap(shildunignore, ["owner", "somethingWithoutSpaces"])

    def shildlistignore(self, irc, msg, args):
        """takes no arguments

        Lists every host on Shild's ignore list.
        """
        hosts = self.registryValue("ignoreList")
        irc.reply("ignored hosts: " + (" ".join(sorted(hosts)) if hosts else "(none)"))
    shildlistignore = wrap(shildlistignore, ["owner"])


Class = Shild
