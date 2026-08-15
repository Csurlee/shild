"""Config registry for the Shild plugin.

Everything network-sensitive (Ollama URL, classifier model path,
decision thresholds) is `opSettable=False` — a channel op should never
be able to repoint the bot at an arbitrary Ollama host (SSRF) or loosen
the thresholds that gate whether a decision even gets logged as
"would have acted". Only a global bot admin can change these, via
`@config` in a query/DCC, or by editing the .conf file directly.
"""
from __future__ import annotations

from supybot import conf, registry

try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization("Shild")
except ImportError:
    _ = lambda x: x  # noqa: E731


def configure(advanced):
    conf.registerPlugin("Shild", True)


Shild = conf.registerPlugin("Shild")

conf.registerGroup(Shild, "ollama")
conf.registerGlobalValue(
    Shild.ollama, "enabled",
    registry.Boolean(True, _(
        """Whether the live decision path consults Ollama at all. Set False
        to run classifier-only (microseconds per decision, no worker
        round-trip for Ollama, no timeout/RAM pressure from a resident
        CPU-only LLM). Turned off 2026-08-06 after corpus analysis showed
        Ollama never once produced an acting decision across 4,479 shadow
        rows, while being the dominant cause of unusable (TimeoutError)
        data. A classifier read that isn't confident enough to act still
        resolves cleanly to allow (shildml.fusion.decide_raw's
        ollama_disabled path) -- it does NOT get relabeled degraded/
        unusable the way an unexpected Ollama failure does. Evidence
        gathering (Tier 0-3) is unaffected by this flag; only the Ollama
        HTTP call itself is skipped.""")),
)
conf.registerGlobalValue(
    Shild.ollama, "url",
    registry.String("http://localhost:11434", _("""Ollama API base URL.""")),
)
conf.registerGlobalValue(
    Shild.ollama, "model",
    registry.String("llama3.2:1b", _("""Ollama model name.""")),
)
conf.registerGlobalValue(
    Shild.ollama, "timeout",
    registry.PositiveFloat(45.0, _(
        """Ollama request timeout, in seconds. CPU-only inference for a
        realistic analysis prompt on llama3.2:1b measured 23-46s on this
        server's hardware (46s on a cold model reload, this box has only
        ~3.4GB RAM total) -- keep meaningful headroom above the high end or
        every decision degrades to fail-open (see shildml.fusion.decide)
        instead of getting a real answer. Raised from 30.0 on 2026-08-04
        after the shadow corpus showed ~59% of recent decisions degrading
        via TimeoutError even with maxConcurrency correctly capped at 1.""")),
)

conf.registerGroup(Shild, "classifier")
conf.registerGlobalValue(
    Shild.classifier, "modelPath",
    registry.String("models/shild_v2.npz", _("""Path to the classifier .npz artifact.""")),
)
conf.registerGlobalValue(
    Shild.classifier, "reloadCheckSecs",
    registry.PositiveInteger(300, _(
        """How often (seconds) to check whether the classifier artifact
        on disk has changed and hot-reload it.""")),
)

conf.registerGroup(Shild, "thresholds")
conf.registerGlobalValue(
    Shild.thresholds, "classifierAct",
    registry.Probability(0.85, _(
        """Classifier confidence required to skip consulting Ollama.""")),
)
conf.registerGlobalValue(
    Shild.thresholds, "ollamaAct",
    registry.Probability(0.75, _(
        """Ollama confidence required to treat its answer as an actionable decision.""")),
)
conf.registerGlobalValue(
    Shild.thresholds, "classifierActWithEvidence",
    registry.Probability(0.50, _(
        """Lower classifier-confidence bar used ONLY when independently
        corroborating host evidence (DNSBL, bogon, geo proxy/hosting, an
        AbuseIPDB/IPQS/Scamalytics score over threshold, an open proxy
        port) agrees with the classifier's own top ban/warn action -- see
        shildml.fusion._apply_escalation. Added 2026-08-09 after a real
        op (idefix) banned a hosting+proxy+open-port host on Undernet
        #windrop that Shild's own classifier read as ban at only 0.60
        confidence -- well under classifierAct (0.85) -- so it resolved
        to a silent allow with the corroborating evidence sitting unused
        in the record. Originally 0.55 (chosen from a 362-row corpus scan
        spanning confidence 0.40-0.73); lowered to 0.50 on 2026-08-10
        after a real near-miss (!shildcheck 192.0.2.1: classifier ban
        at 0.538, Scamalytics 100/100 fraud, missed the old bar by 1.2
        points) and a fresh corpus scan showing a substantial 0.50-0.55
        cluster (224 rows) sitting just outside it. 0.50 is the exact
        boundary the original analysis already drew between "reliable
        enough to consider" and "the weakest, least reliable tail"
        (0.40-0.50) -- see shildml/fusion.py's Thresholds docstring for
        the full reasoning. Never used alone -- evidence with no
        classifier agreement, or classifier confidence with no
        corroborating evidence, still cannot act via this path.""")),
)
conf.registerGlobalValue(
    Shild.thresholds, "classifierBanSecondaryFloor",
    registry.Probability(0.30, _(
        """2026-08-14: floor on the classifier's OWN ban-probability (not
        its top pick) for the "secondary-rank" evidence escalation
        sub-rule -- fires only when the classifier's top action was warn
        but ban was its clear second choice (ranked above allow) at or
        above this floor, AND hard evidence corroborates. Chosen from a
        real corpus slice the same day: three hosts (Spike77777, fietanre,
        tanami_) had ban as a 34-39% second choice, backed by hard
        evidence (an open proxy port, a real DroneBL hit, a bogon
        source) -- genuine near-misses the original top-pick-only
        escalation (classifierActWithEvidence above) could never reach.
        See shildml.fusion._apply_escalation and
        evidence.enableSecondaryBanEscalation below (the gate covering
        BOTH this and the separate extreme-evidence sub-rule).""")),
)

conf.registerGroup(Shild, "worker")
conf.registerGlobalValue(
    Shild.worker, "maxQueue",
    registry.PositiveInteger(8, _(
        """Maximum pending Ollama jobs before drop-oldest shedding kicks in.
        Kept small on purpose: this server's Ollama backend only runs one
        inference at a time regardless of maxConcurrency below (confirmed
        live -- every model's llama-server process launches with a single
        parallel slot), so at ~20-40s/request a large queue just builds a
        multi-minute backlog that pins the CPU instead of shedding load,
        which is what actually made the server unresponsive under a busy
        channel's traffic (see docs/DOCUMENTATION.md).""")),
)
conf.registerGlobalValue(
    Shild.worker, "maxConcurrency",
    registry.PositiveInteger(1, _(
        """Maximum concurrent Ollama requests. Set to match this server's
        real backend capacity (one inference at a time) rather than
        pretending to parallelize requests the Ollama process would just
        serialize anyway.""")),
)

conf.registerGlobalValue(
    Shild, "shadowDataPath",
    registry.String("data/shadow_decisions.jsonl", _(
        """Path to the shadow-mode decision JSONL log.""")),
)

conf.registerGlobalValue(
    Shild, "ignoreList",
    registry.SpaceSeparatedListOfStrings([], _(
        """Hosts Shild NEVER evaluates -- resolves straight to allow,
        skipping the classifier/evidence/Ollama pipeline entirely,
        regardless of what it would otherwise read as. For a known
        friend, the operator's own second bot, or anything else that
        shouldn't be judged. Manage live via
        `shildignore`/`shildunignore`/`shildlistignore` (owner-only,
        2026-08-10). Each entry is always a HOST, never a bare nick --
        `shildignore <nick>` resolves it to that nick's CURRENT host at
        the moment the command runs (same resolution `shildcheck` uses),
        a one-time snapshot, not a standing nick-based exemption (a nick
        can be taken by anyone). An ignored host's join/message still
        gets its own shadow_decisions.jsonl record (source="ignore"),
        but tagged label_quality="ignored" so it's never mistaken for a
        genuine "allow" training example -- see
        shildml.schema.load_training_rows.""")),
)

conf.registerGlobalValue(
    Shild, "enforcementLogPath",
    registry.String("data/enforcement_actions.jsonl", _(
        """Path to the JSONL log of real enforcement actions Shild itself
        took (kick+ban). Distinct from shadowDataPath (decisions, acted
        on or not) and moderationLogPath (actions OTHERS took) -- see
        plugins/Shild/collector.py's build_enforcement_record.""")),
)

conf.registerGlobalValue(
    Shild, "moderationLogPath",
    registry.String("data/observed_moderation.jsonl", _(
        """Path to the observed-moderation JSONL log: kicks/bans taken by
        OTHERS (real ops, other bots) in enabled channels. Read-only
        observation only -- Shild has no moderation capability and never
        writes to this log as a result of its own action, only as a
        result of watching someone else's.""")),
)

conf.registerGroup(Shild, "report")
conf.registerGlobalValue(
    Shild.report, "dir",
    registry.String("runtime/daily_analysis", _(
        """Directory containing the daily shadow-data review reports
        written by scripts/daily_data_analysis.sh (2026-08-06, added when
        Ollama was turned off -- see ollama.enabled above -- as its
        replacement "second opinion" layer). Read by !shildreport and the
        new-report announcer below.""")),
)
conf.registerGlobalValue(
    Shild.report, "announce",
    registry.Boolean(True, _(
        """Whether to relay a short excerpt to each network's relayChannel
        when a new daily report appears. Same channel !shildstatus's
        "[shadow] would ..." lines already go to.""")),
)
conf.registerGlobalValue(
    Shild.report, "checkIntervalSecs",
    registry.PositiveInteger(600, _(
        """How often (seconds) to check report.dir for a new report to
        announce. The report itself only appears once a day (cron, see
        scripts/daily_data_analysis.sh) -- this just needs to be frequent
        enough to notice it same-morning, a cheap directory listing.""")),
)

# Network-specific: the relay channel differs per network (Libera uses
# ##relay, Undernet uses #relay), and a decision made on one network must
# never be announced on another.
conf.registerNetworkValue(
    Shild, "relayChannel",
    registry.String("", _(
        """Channel to relay 'would have acted' shadow decisions to. Must
        never be the monitored channel itself.""")),
)

# Per-channel, per-network opt-in — global admin only (opSettable=False).
# Shadow mode should never quietly start analyzing a channel an op
# enabled on a whim; it's a deliberate per-channel rollout decision.
conf.registerChannelValue(
    Shild, "enabled",
    registry.Boolean(False, _(
        """Whether Shild's shadow-mode analysis (observe + log only, never acts) is active in this channel.""")),
    opSettable=False,
)

# A busy channel's chat volume, not join volume, is what actually
# overloaded the Ollama worker queue (see worker.maxQueue's docstring
# above) -- joins are Phase 2's real threat surface (bans are
# join-triggered) and are naturally much lower-volume than chat, so this
# lets a channel keep join analysis while dropping the message flood.
# Default False (2026-08-02): message-level analysis is off everywhere
# the bot is enabled, not just on channels that already proved to
# overload -- newly-enabled channels (#location/#romania/#undernet, live
# via @config) inherit this default automatically, closing the same
# overload risk before it recurs rather than chasing it channel by
# channel. Opt a specific channel back into message analysis explicitly
# if it's ever actually needed.
conf.registerChannelValue(
    Shild, "messageAnalysis",
    registry.Boolean(False, _(
        """Whether Shild analyzes channel MESSAGES (in addition to joins,
        which are always analyzed when "enabled" is true). Off by default
        -- a busy channel's chat volume is what floods the Ollama worker
        queue; joins keep being analyzed regardless of this setting.""")),
    opSettable=False,
)

# ---------------------------------------------------------------------
# Phase 1.5: host evidence (DNSBL/IP reputation/cloak trust). All
# opSettable=False for the same reason as everything above -- a channel
# op should never be able to disable the evidence gate that's keeping
# ban decisions honest, or repoint a lookup at an arbitrary host (SSRF).
# ---------------------------------------------------------------------

conf.registerGroup(Shild, "evidence")
conf.registerGlobalValue(
    Shild.evidence, "enabled",
    registry.Boolean(True, _(
        """Whether to gather host evidence and apply the evidence gate to
        decisions (see shildml.evidence / shildml.fusion) -- mostly a
        downgrade gate on ban/warn, plus a narrow evidence-corroborated
        escalation path added 2026-08-09 (see CLAUDE.md). Turning this off
        reverts to raw classifier/Ollama decisions with no evidence
        corroboration -- only useful for A/B comparison via
        scripts/gate_report.py, never recommended for normal operation.""")),
)
conf.registerGlobalValue(
    Shild.evidence, "abuseipdbThreshold",
    registry.Integer(50, _(
        """AbuseIPDB confidence-of-abuse score (0-100) at or above which a
        host counts as corroborated bad.""")),
)
conf.registerGlobalValue(
    Shild.evidence, "ipqsThreshold",
    registry.Integer(85, _(
        """IPQualityScore fraud_score (0-100) at or above which a host
        counts as corroborated bad. Set above the "high risk" line (75)
        to stay clear of VPN-only hits, which are not themselves abuse.""")),
)
conf.registerGlobalValue(
    Shild.evidence, "scamalyticsThreshold",
    registry.Integer(75, _(
        """Scamalytics scamalytics_score (0-100) at or above which a host
        counts as corroborated bad -- independent of `is_blacklisted_external`,
        which always counts regardless of this threshold. 75 approximates
        Scamalytics' own "high"/"very high" risk tiers; tune once real
        corpus data exists to check against, same as abuseipdbThreshold/
        ipqsThreshold.""")),
)
conf.registerGlobalValue(
    Shild.evidence, "requireHardEvidenceForBan",
    registry.Boolean(True, _(
        """2026-08-10: when True (the default), a `ban` verdict must be
        corroborated by HARD evidence (a real DNSBL/IRCBL listing, a
        confirmed open proxy port, bogon source, or an AbuseIPDB/IPQS
        score over threshold) -- geo_proxy (ip-api's proxy/VPN/hosting
        flag) alone is capped to `warn`. A corpus review found 68% of
        evidence-corroborated escalations rested on geo_proxy alone,
        including a real ban of a legitimate ProtonVPN connection --
        geo_proxy flags a paid VPN/VPS subscriber identically to a known
        open relay, so it isn't sufficient evidence of abuse by itself.
        Safety valve only -- turning this False reverts to the pre-2026-
        08-10 behavior; not recommended. NOTE: unlike thresholds.* (which
        are re-read every event), this is captured once into
        EvidenceThresholds at plugin __init__ -- same as
        abuseipdbThreshold/ipqsThreshold above -- so a live @config change
        needs `@reload Shild` to take effect, not a full bot restart
        (this value lives in plugin.py, not shildml/).""")),
)
conf.registerGlobalValue(
    Shild.evidence, "scamalyticsExtreme",
    registry.Integer(80, _(
        """2026-08-14: higher bar than scamalyticsThreshold, used only by
        the "extreme-evidence" escalation sub-rule (see
        enableSecondaryBanEscalation below) -- lets a Scamalytics score
        this high promote a warn to ban even when the classifier's OWN
        ban-probability ranked below allow. Not confirmed against
        Scamalytics' exact tier boundaries (undocumented); chosen from a
        real case (batis610, 82/100, 2026-08-14).""")),
)
conf.registerGlobalValue(
    Shild.evidence, "abuseipdbExtreme",
    registry.Integer(90, _(
        """Same as scamalyticsExtreme but for AbuseIPDB's abuse-confidence
        score.""")),
)
conf.registerGlobalValue(
    Shild.evidence, "ipqsExtreme",
    registry.Integer(95, _(
        """Same as scamalyticsExtreme but for IPQualityScore's fraud_score.""")),
)
conf.registerGlobalValue(
    Shild.evidence, "enableSecondaryBanEscalation",
    registry.Boolean(True, _(
        """2026-08-14: safety valve for BOTH new secondary escalation
        sub-rules in shildml.fusion._apply_escalation -- the
        secondary-rank floor (thresholds.classifierBanSecondaryFloor) and
        the extreme-evidence override (scamalyticsExtreme/
        abuseipdbExtreme/ipqsExtreme, or 2+ independent hard signals
        agreeing). Independent of requireHardEvidenceForBan above, which
        only governs the older hard/soft cap. Set False to revert to the
        pre-2026-08-14 behavior where evidence can only ever confirm the
        classifier's own TOP-ranked action. Same @reload-not-restart
        caveat as requireHardEvidenceForBan -- captured once at plugin
        __init__.""")),
)

conf.registerGroup(Shild, "dnsbl")
conf.registerGlobalValue(
    Shild.dnsbl, "timeout",
    registry.PositiveFloat(5.0, _(
        """DNS lookup timeout in seconds for DNSBL/DroneBL/bogon/Tor-exit
        checks.""")),
)
conf.registerGlobalValue(
    Shild.dnsbl, "cacheTtl",
    registry.PositiveInteger(21600, _(
        """How long (seconds) to cache a DNSBL/DroneBL/bogon/Tor-exit
        result per IP. Default 6h.""")),
)

conf.registerGroup(Shild, "ipapi")
conf.registerGlobalValue(
    Shild.ipapi, "timeout",
    registry.PositiveFloat(8.0, _("""HTTP timeout in seconds for ip-api.com geo/proxy lookups.""")),
)
conf.registerGlobalValue(
    Shild.ipapi, "cacheTtl",
    registry.PositiveInteger(86400, _(
        """How long (seconds) to cache an ip-api.com result per IP. Default 24h.""")),
)
conf.registerGlobalValue(
    Shild.ipapi, "rateLimitPerMinute",
    registry.PositiveInteger(45, _(
        """ip-api.com's free-tier rate limit (requests/minute) -- verified
        2026-08-02. Do not raise this unless upgrading to a paid plan.""")),
)

conf.registerGroup(Shild, "abuseipdb")
conf.registerGlobalValue(
    Shild.abuseipdb, "enabled",
    registry.Boolean(True, _(
        """Whether to call AbuseIPDB as a Tier 2 reputation check (only
        when Tier 1 hasn't already corroborated a ban/warn). Requires an
        API key in the local secrets file -- see "secretsPath" below and
        docs/DOCUMENTATION.md. Silently skipped (not an error) if no key
        is configured.""")),
)
conf.registerGlobalValue(
    Shild.abuseipdb, "dailyLimit",
    registry.PositiveInteger(1000, _("""AbuseIPDB's free-tier daily lookup limit.""")),
)

conf.registerGroup(Shild, "ipqs")
conf.registerGlobalValue(
    Shild.ipqs, "enabled",
    registry.Boolean(False, _(
        """Whether to call IPQualityScore as a Tier 2 reputation check.
        Ships OFF: the account configured during Phase 1.5 bring-up had 0
        remaining free-tier credits (verified 2026-08-02) -- see
        docs/DOCUMENTATION.md. Flip on once credits are available AND a
        key is present in the local secrets file.""")),
)
conf.registerGlobalValue(
    Shild.ipqs, "lifetimeLimit",
    registry.PositiveInteger(1000, _(
        """IPQualityScore's free-tier lookup allowance -- lifetime, not
        daily, per their pricing model.""")),
)

conf.registerGroup(Shild, "scamalytics")
conf.registerGlobalValue(
    Shild.scamalytics, "enabled",
    registry.Boolean(True, _(
        """Whether to call Scamalytics as a second Tier 2 reputation check
        alongside IPQS. Added 2026-08-10 as a genuinely different
        provider/account, not a fallback for IPQS's dead key (see
        CLAUDE.md). Defaults True (same convention as AbuseIPDB, not
        IPQS -- real, verified-working credentials exist for this
        deployment) but needs both "scamalytics_username" and
        "scamalytics_key" in the local secrets file to actually do
        anything; silently skipped (not an error) if either is missing,
        so this is still safe on a fresh deploy with no secrets file.""")),
)
conf.registerGlobalValue(
    Shild.scamalytics, "dailyLimit",
    registry.PositiveInteger(150, _(
        """Scamalytics' free tier is 5,000 credits/MONTH, not daily, and
        unused credits do not roll over -- BudgetManager only supports
        daily/lifetime windows, so this is a deliberately conservative
        daily approximation (150/day * 30 = 4,500, leaving headroom under
        5,000 even on a 31-day month) rather than an exact monthly cap.
        Raise only alongside a paid plan.""")),
)
conf.registerGlobalValue(
    Shild.scamalytics, "dailyLimit2",
    registry.PositiveInteger(150, _(
        """Same budget shape as scamalytics.dailyLimit, but for the OPTIONAL
        second Scamalytics account (scamalytics_username2/scamalytics_key2
        in the local secrets file) ReputationGatherer falls back to once
        the primary account's own daily budget is exhausted -- see
        reputation.py's module docstring. Two independent free-tier
        accounts each get their own 5,000/month allowance, so this defaults
        to the same conservative 150/day approximation as the primary.
        Meaningless (never consulted) if no second account is configured;
        this is the counter for it, not a toggle.""")),
)

conf.registerGlobalValue(
    Shild, "secretsPath",
    registry.String("secrets.json", _(
        """Path to a local, gitignored JSON file holding API keys
        (keys: abuseipdb_key, ipqs_key, scamalytics_username,
        scamalytics_key, and the OPTIONAL fallback pair
        scamalytics_username2/scamalytics_key2 -- see reputation.py's
        module docstring for when the fallback account is used),
        resolved relative to the bot's own
        working directory (runtime/) -- NOT the repo root, so this must be
        "secrets.json", not "runtime/secrets.json" (that was a real bug,
        fixed 2026-08-02: it silently never loaded, since the wrong
        relative path resolved to a nonexistent runtime/runtime/secrets.json;
        fails open/looks like "no key configured" rather than erroring, so
        it went unnoticed -- AbuseIPDB/IPQS Tier 2 checks likely never
        actually had a key in production until this fix). Environment
        variables SHILD_ABUSEIPDB_KEY / SHILD_IPQS_KEY / SHILD_SCAMALYTICS_USERNAME /
        SHILD_SCAMALYTICS_KEY / SHILD_SCAMALYTICS_USERNAME2 / SHILD_SCAMALYTICS_KEY2
        take precedence over the file. The key VALUES
        are deliberately never a registry value: an admin's @config dump
        must never be able to leak these -- only
        this path string is.""")),
)

conf.registerGlobalValue(
    Shild, "budgetPath",
    registry.String("budget.json", _(
        """Path to the persisted daily/lifetime lookup-budget counters for
        keyed reputation providers -- survives a bot restart so a quota
        can't be silently reset by one. Resolved relative to the bot's own
        working directory (runtime/), same as secretsPath below -- found
        2026-08-10 defaulting to "runtime/budget.json" (the identical
        mistake secretsPath already had fixed), which silently wrote real
        budget counters into a nested runtime/runtime/budget.json instead.
        Fixed at the source; the live conf value still needs a one-time
        manual correction (not a full regen) plus moving the existing
        file up a level to avoid losing accumulated counters -- see
        CLAUDE.md.""")),
)

conf.registerGroup(Shild, "proxyscan")
conf.registerGlobalValue(
    Shild.proxyscan, "enabled",
    registry.Boolean(True, _(
        """Whether to actively probe a joining host's IP for open proxy
        ports (Tier 3 evidence). Enabled 2026-08-06 per user decision --
        see plugins/Shild/proxyscan.py's module docstring: this actively
        connects to a third party's machine (qualitatively different from
        every other check here) and is largely redundant on a network,
        like Libera, that already runs its own connect-time proxy scan,
        but useful on Undernet which has no equivalent.""")),
)
conf.registerGlobalValue(
    Shild.proxyscan, "connectTimeout",
    registry.PositiveFloat(2.0, _("""Per-port connect timeout in seconds.""")),
)
conf.registerGlobalValue(
    Shild.proxyscan, "overallTimeout",
    registry.PositiveFloat(6.0, _(
        """Hard deadline in seconds for the whole port scan, regardless of
        how many ports are configured -- a flood of joins must never pile
        up slow scans.""")),
)

# ---------------------------------------------------------------------
# Phase 2: Protection Mode. Real enforcement (kick+ban), gated by actually
# holding op in the channel (see plugins/Shild/enforcement.py::is_opped)
# AND this kill switch. Shadow-mode logging/relay above is completely
# unaffected by any of this -- it keeps running unconditionally in every
# enabled channel regardless of op status or the kill switch.
# ---------------------------------------------------------------------

conf.registerGroup(Shild, "protection")
conf.registerGlobalValue(
    Shild.protection, "killSwitch",
    registry.Boolean(True, _(
        """Global override: when True (the default), Shild NEVER takes a
        real enforcement action anywhere, regardless of op status. Must
        be deliberately set False before any real kick/ban can ever
        happen -- this is what keeps a fresh deploy safe even if the bot
        already holds op somewhere at startup. Shadow-mode logging/relay
        is entirely unaffected either way; this only gates
        plugins/Shild/enforcement.py.""")),
)
conf.registerGlobalValue(
    Shild.protection, "banDurationSecs",
    registry.PositiveInteger(3600, _(
        """How long (seconds) a real ban set by Shild lasts before being
        automatically lifted. Matches the old Eggdrop ban_duration
        default of 60 minutes.""")),
)
conf.registerGlobalValue(
    Shild, "banIdsPath",
    registry.String("shild_ban_ids.json", _(
        """Path to the persisted, ever-incrementing counter that assigns
        each real ban its own permanent [ID: N], shown in the kick
        message -- see plugins/Shild/ban_ids.py. Resolved relative to
        the bot's own working directory (runtime/), same as budgetPath
        -- do NOT prefix with "runtime/" (see budgetPath's own docstring
        for the double-"runtime/" bug this exact mistake caused
        there).""")),
)
