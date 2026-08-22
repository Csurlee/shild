"""Declarative catalog of every user-facing registry value shild-py's
plugins expose, used by scripts/install_wizard.py to know what to prompt
for and by tests/test_install_catalog.py to make sure this file never
falls out of date.

Why this exists: "the installer must be updated every time a new feature
or plugin is made" is easy to say and easy to forget -- this project's own
CLAUDE.md documents the same class of drift bug (a live-only @config value
silently reverted by the next regen) happening to NickServ, UndernetX,
GitHubWatch, ChannelLogger, and channel lists, on separate occasions, over
months. A written reminder didn't prevent any of those. What actually
works in this codebase is a structural check (the "purity guard"/
"timezone guard" grep commands in the Weather plan, the evidence-gate
leak test) -- so here, that's tests/test_install_catalog.py: it imports
every plugin's config.py, walks the REAL registered registry tree, and
fails loudly if any value isn't classified below. Adding a plugin or a
config value without updating this file breaks the test suite.

Every entry is one of:

  Ask(path, tier, question, kind, default=..., secret=False, url=None)
      The wizard prompts for this. `tier` is "essential" (always asked),
      "plugin" (asked when that plugin is enabled), or "advanced" (only
      in the opt-in deep pass). `kind` is "string"/"int"/"float"/"bool"/
      "list"/"channel_list". `secret` values are written to
      runtime/secrets.json, never the registry, and `url` (if given) is
      shown at the prompt as where to register for a free key.

  Skip(path, reason)
      Deliberately not asked. `reason` is a short human sentence -- this
      is the reviewable half of "is this the right call", since the test
      can only check that a reason EXISTS, not that it's a good one.

`path` is the registry path BELOW `supybot.plugins.<PluginName>.` (the
plugin prefix is added by the catalog structure, not repeated per entry).
"""
from __future__ import annotations

import dataclasses
from typing import Optional


@dataclasses.dataclass(frozen=True)
class Ask:
    path: str
    tier: str  # "essential" | "plugin" | "advanced"
    question: str
    kind: str = "string"  # "string" | "int" | "float" | "bool" | "list" | "channel_list"
    default: object = None
    secret: bool = False
    url: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class Skip:
    path: str
    reason: str


# Aliases shipped by default when install.json omits its own "aliases"
# key -- a shild-py feature decision (ship these short commands), not
# deployment-specific data. The single source of truth for this list;
# both install_wizard.py and bootstrap_runtime.py import it from here.
DEFAULT_ALIASES = {
    "spstatus": "spamguardstatus",
    "splist": "spamguardlist",
    "spsearch": "spamguardsearch $*",
    "spremove": "spamguardremove $*",
    "sp": "spamguard $*",
    "shstatus": "shildstatus",
    "shreport": "shildreport $*",
    "shcheck": "shildcheck $*",
    "shignore": "shildignore $*",
    "shunignore": "shildunignore $*",
    "shlistignore": "shildlistignore",
}

# Plugins that are always loaded, never asked about, and whose config
# this catalog does not cover -- they're Limnoria/repo baseline plugins
# with no meaningful per-install tuning (see bootstrap_runtime.py's own
# comment on why: universal hardening decisions, not deployment choices).
BASELINE_PLUGINS = (
    "Owner", "Admin", "Config", "User", "Misc", "Channel", "Anonymous",
    "Status", "ChannelStats", "Services", "Alias",
)

CATALOG: dict[str, list] = {
    "Shild": [
        Skip("enabled", "structural -- driven by install.json's plugins.Shild.channels, not a bare bool"),
        Ask("messageAnalysis", tier="plugin", kind="bool", default=False,
            question="Analyze channel MESSAGES too, not just joins? "
                     "(Starts expensive if Ollama is ever re-enabled; joins-only is the safe default.)"),
        Skip("relayChannel", "derived from each network's relay_channel in install.json"),
        Ask("protection.killSwitch", tier="plugin", kind="bool", default=True,
            question="Keep the enforcement kill switch ON (safe, shadow-mode only, no real kicks/bans)?"),
        Skip("protection.banDurationSecs", "internal tuning, change later via @config if needed"),
        Ask("ollama.enabled", tier="advanced", kind="bool", default=True,
            question="Enable the local Ollama LLM second-opinion? (Needs a running Ollama server; off is fine, the classifier+evidence pipeline works without it.)"),
        Skip("ollama.url", "only relevant if ollama.enabled above is turned on; edit via @config"),
        Skip("ollama.model", "only relevant if ollama.enabled above is turned on"),
        Skip("ollama.timeout", "internal tuning"),
        Skip("classifier.modelPath", "derived: models/shild_v2.npz under the repo root"),
        Skip("classifier.reloadCheckSecs", "internal tuning"),
        Skip("secretsPath", "derived: always runtime/secrets.json, never asked"),
        Skip("evidence.enabled", "the evidence gate is core to Shild; always on"),
        Ask("abuseipdb.enabled", tier="plugin", kind="bool", default=True,
            question="Enable AbuseIPDB reputation lookups? (free tier, 1000/day -- "
                     "you'll be asked for the key separately)",
            url="https://www.abuseipdb.com/register"),
        Skip("abuseipdb.dailyLimit", "internal tuning"),
        Ask("ipqs.enabled", tier="advanced", kind="bool", default=False,
            question="Enable IPQualityScore reputation lookups? (key asked separately)",
            url="https://www.ipqualityscore.com/create-account"),
        Skip("ipqs.lifetimeLimit", "internal tuning"),
        Ask("scamalytics.enabled", tier="plugin", kind="bool", default=True,
            question="Enable Scamalytics fraud-score lookups? (free tier, 5000/month -- "
                     "username+key asked separately)",
            url="https://scamalytics.com/ip/api/enquiry"),
        Skip("scamalytics.dailyLimit", "internal tuning, conservative approximation of the monthly quota"),
        Skip("scamalytics.dailyLimit2", "internal tuning; second-account fallback budget"),
        Skip("scamalytics.tieringEnabled", "correct default (True), not a first-install decision"),
        Skip("scamalytics.tierMinAbuseipdbScore", "internal tuning"),
        Skip("scamalytics.tierMaxAbuseipdbScore", "internal tuning"),
        Ask("proxyscan.enabled", tier="plugin", kind="bool", default=True,
            question="Enable active proxy-port scanning? This actively connects to a "
                     "joining host's IP to check for open proxy ports -- more signal, "
                     "but is real outbound traffic to strangers' hosts."),
        Skip("proxyscan.connectTimeout", "internal tuning"),
        Skip("proxyscan.overallTimeout", "internal tuning"),
        Skip("ignoreList", "managed live via the shildignore command, not at install time"),
        Skip("decisionCache.enabled", "correct default (True), not a first-install decision"),
        Skip("decisionCache.ttlSecs", "internal tuning"),
        Skip("report.dir", "derived: runtime/daily_analysis"),
        Skip("report.announce", "internal tuning"),
        Skip("report.checkIntervalSecs", "internal tuning"),
        Skip("shadowDataPath", "derived: data/shadow_decisions.jsonl"),
        Skip("enforcementLogPath", "derived path"),
        Skip("moderationLogPath", "derived path"),
        Skip("budgetPath", "derived path"),
        Skip("banIdsPath", "derived path"),
        Skip("worker.maxQueue", "internal tuning"),
        Skip("worker.maxConcurrency", "internal tuning"),
        Skip("dnsbl.timeout", "internal tuning"),
        Skip("dnsbl.staggerMs", "internal tuning"),
        Skip("dnsbl.cacheTtl", "internal tuning"),
        Ask("dnsbl.ircblEnabled", tier="advanced", kind="bool", default=False,
            question="Include rbl.ircbl.org in LIVE join/message evidence checks? "
                     "(Off by default: on this project's own deployment it was the "
                     "slowest of the 5 DNSBL zones and dragged the others down when "
                     "queried concurrently, and Undernet's own X service already "
                     "g-lines off this same list -- still always queried on a manual "
                     "!shildcheck regardless of this setting.)"),
        Skip("ipapi.timeout", "internal tuning"),
        Skip("ipapi.cacheTtl", "internal tuning"),
        Skip("ipapi.rateLimitPerMinute", "internal tuning, tied to ip-api.com's free-tier limit"),
        Ask("geoip.enabled", tier="plugin", kind="bool", default=True,
            question="Use a local, offline GeoIP database for country lookups? "
                     "Free, no API key or rate limit (run scripts/update_geoip_db.py "
                     "to download it -- falls back to the online ip-api.com check if "
                     "you skip that)."),
        Skip("geoip.dbPath", "derived path; scripts/update_geoip_db.py's default matches it"),
        Ask("blocklist.enabled", tier="plugin", kind="bool", default=True,
            question="Check joining hosts against local FireHOL open-proxy/botnet "
                     "blocklists? Free, no API key, no rate limit (run "
                     "scripts/update_blocklists.py to download them)."),
        Skip("blocklist.dir", "derived path; scripts/update_blocklists.py's default matches it"),
        Skip("blocklist.lists", "the curated default set is the intended install; "
                                 "change via @config if you want a different subset"),
        Skip("thresholds.classifierAct", "internal ML tuning, not a first-install decision"),
        Skip("thresholds.ollamaAct", "internal ML tuning"),
        Skip("thresholds.classifierActWithEvidence", "internal ML tuning"),
        Skip("thresholds.classifierBanSecondaryFloor", "internal ML tuning"),
        Skip("evidence.abuseipdbThreshold", "internal ML tuning"),
        Skip("evidence.ipqsThreshold", "internal ML tuning"),
        Skip("evidence.scamalyticsThreshold", "internal ML tuning"),
        Skip("evidence.requireHardEvidenceForBan", "safety valve, correct default, not a first-install decision"),
        Skip("evidence.scamalyticsExtreme", "internal ML tuning"),
        Skip("evidence.abuseipdbExtreme", "internal ML tuning"),
        Skip("evidence.ipqsExtreme", "internal ML tuning"),
        Skip("evidence.enableSecondaryBanEscalation", "safety valve, correct default"),
    ],
    "SpamGuard": [
        Skip("enabled", "structural -- driven by install.json's plugins.SpamGuard.channels"),
        Skip("relayChannel", "derived from each network's relay_channel in install.json"),
        Ask("protection.killSwitch", tier="plugin", kind="bool", default=True,
            question="Keep SpamGuard's enforcement kill switch ON (safe, logs matches but never kicks/bans)?"),
        Skip("protection.banDurationSecs", "internal tuning"),
        Skip("protection.kickReason", "internal default reads fine; change later via @config"),
        Skip("termsPath", "derived path: runtime/data/spamguard_terms.json"),
        Skip("hostBansPath", "derived path: runtime/data/spamguard_host_bans.json"),
        Ask("hostBanAutoRebanEnabled", tier="advanced", kind="bool", default=False,
            question="Automatically re-ban a host that's already been convicted before "
                     "(persisted host-ban history), the moment it rejoins under any "
                     "nick/ident/realname? Off by default -- recording still always happens "
                     "so you can review it via spamguardhostbans before arming this."),
        Skip("hostBanRetentionDays", "internal tuning"),
        Skip("hostBanPruneIntervalSecs", "internal tuning"),
        Skip("logPath", "derived path"),
        Skip("joinWindowSecs", "internal tuning"),
        Skip("exemptRegistered", "correct default (True), not a first-install decision"),
        Ask("floodEnabled", tier="advanced", kind="bool", default=False,
            question="Enable the flood-message heuristic globally as a default for new channels?"),
        Ask("hilightEnabled", tier="advanced", kind="bool", default=False,
            question="Enable the mass-highlight heuristic globally as a default for new channels?"),
        Ask("capsEnabled", tier="advanced", kind="bool", default=False,
            question="Enable the excess-caps heuristic globally as a default for new channels?"),
        Ask("mojibakeEnabled", tier="advanced", kind="bool", default=False,
            question="Enable the mojibake/garbled-encoding heuristic globally as a default for new channels?"),
        Ask("raidEnabled", tier="advanced", kind="bool", default=False,
            question="Enable the raid (coordinated-join) heuristic globally as a default for new "
                     "channels? Caution: a real netsplit-reconnect burst can resemble a raid."),
        Skip("floodMessageLimit", "internal tuning"),
        Skip("floodWindowSecs", "internal tuning"),
        Skip("hilightNickLimit", "internal tuning"),
        Skip("hilightMinNickLen", "internal tuning"),
        Skip("capsPercent", "internal tuning"),
        Skip("capsMinLength", "internal tuning"),
        Skip("mojibakeScore", "internal tuning"),
        Skip("raidJoinLimit", "internal tuning"),
        Skip("raidWindowSecs", "internal tuning"),
        Skip("words", "legacy migration-only field, superseded by the `spamguard word add` command"),
        Skip("phrases", "legacy migration-only field"),
        Skip("patterns", "legacy migration-only field"),
        Skip("identWords", "legacy migration-only field"),
        Skip("realnameWords", "legacy migration-only field"),
        Skip("realnamePhrases", "legacy migration-only field"),
    ],
    "WebPanel": [
        Skip("enable", "driven by the generic 'Enable <Plugin>?' toggle every plugin gets, "
                       "not asked twice -- see install_wizard.py's plugin loop"),
        Skip("allowedHosts", "derived automatically from bind4/port -- see bootstrap_runtime.py"),
        Skip("secretsPath", "derived: runtime/secrets.json"),
        Skip("livePreviewSource", "internal tuning"),
        Skip("channelLogDir", "auto-derived from directories.log"),
        Skip("reportDir", "auto-derived"),
        Skip("shadowDataPath", "auto-derived"),
        Skip("partedStatePath", "derived path"),
        Skip("authCacheSecs", "internal tuning"),
        Skip("maxAuthFailures", "internal tuning"),
        Skip("authLockoutSecs", "internal tuning"),
        Skip("logTailLines", "cosmetic tuning"),
        Skip("logTailMaxBytes", "cosmetic tuning"),
        Skip("recentScansCount", "cosmetic tuning"),
        Skip("summaryRefreshSecs", "internal tuning"),
        Skip("gateRefreshSecs", "internal tuning"),
        Skip("liveLines", "cosmetic tuning"),
        Skip("liveRefreshSecs", "cosmetic tuning"),
        Skip("liveDecisionsCount", "cosmetic tuning"),
        Skip("partedRetentionDays", "internal tuning"),
        Skip("partedCheckIntervalSecs", "internal tuning"),
    ],
    "GitHubWatch": [
        Ask("repos", tier="plugin", kind="list", default=[],
            question="GitHub repos to watch, space-separated owner/repo (leave blank to skip)"),
        Skip("channel", "derived from each network's relay_channel in install.json"),
        Skip("secretsPath", "derived: runtime/secrets.json"),
        Ask("_github_token", tier="plugin", kind="string", default="", secret=True,
            question="GitHub token (only needed for private repos, raises the rate limit 60->5000/hr)",
            url="https://github.com/settings/tokens"),
        Skip("pollIntervalSecs", "internal tuning"),
        Skip("announcePushes", "correct default"),
        Skip("announceIssues", "correct default"),
        Skip("announcePullRequests", "correct default"),
        Skip("statePath", "derived path"),
        Skip("maxCommitsShown", "cosmetic tuning"),
    ],
    "Weather": [
        Ask("_openweathermap_key", tier="plugin", kind="string", default="", secret=True,
            question="OpenWeatherMap API key (required for the weather/w command)",
            url="https://openweathermap.org/api"),
        Ask("_openaq_key", tier="plugin", kind="string", default="", secret=True,
            question="OpenAQ API key (optional, only needed for the aqi command / air-quality fragment)",
            url="https://explore.openaq.org/register"),
        Skip("enabled", "correct default (True) -- Weather answers wherever it's loaded unless disabled later"),
        Skip("showAirQuality", "correct default"),
        Ask("defaultLocation", tier="advanced", kind="string", default="",
            question="Default location per network for a bare `w` with nothing saved (leave blank for none)"),
        Skip("secretsPath", "derived: runtime/secrets.json"),
        Skip("locationsPath", "derived path"),
        Skip("geocodeCachePath", "derived path"),
        Ask("userAgent", tier="advanced", kind="string",
            default="shild-py-Weather/0.1 (+https://github.com/Csurlee/shild)",
            question="User-Agent string sent to Nominatim (their policy requires an identifying one)"),
        Ask("contactEmail", tier="advanced", kind="string", default="",
            question="Contact email appended to the Nominatim User-Agent (recommended by their policy, optional)"),
        Skip("timeoutSecs", "internal tuning"),
        Skip("forecastDays", "cosmetic tuning"),
        Skip("currentTtlSecs", "internal tuning"),
        Skip("forecastTtlSecs", "internal tuning"),
        Skip("airQualityTtlSecs", "internal tuning"),
        Skip("geocodeCacheTtlDays", "internal tuning"),
        Skip("geocodeMissTtlHours", "internal tuning"),
        Skip("cacheMaxEntries", "internal tuning"),
        Skip("nominatimRatePerMin", "tied to Nominatim's own policy, do not raise"),
        Skip("owmRatePerMin", "internal tuning"),
        Skip("openaqRatePerMin", "internal tuning"),
        Skip("airQualityRadiusMeters", "cosmetic tuning"),
        Skip("maxLineBytes", "internal tuning"),
    ],
    "UndernetX": [
        Skip("auth.username", "supplied via install.json's networks[].services credentials, not asked twice"),
        Skip("auth.password", "supplied via install.json's networks[].services credentials, not asked twice"),
        Skip("auth.noJoinsUntilAuthed", "always forced False by bootstrap_runtime.py -- see its own comment"),
        Skip("auth.xservice", "correct default, X's own service name"),
        Skip("auth.xserviceHostmask", "correct default, impersonation-detection anchor"),
        Skip("modeXonID", "correct default"),
        Skip("commands.replyTimeoutSecs", "internal tuning"),
        Skip("commands.defaultBanDuration", "internal tuning"),
        Skip("commands.defaultBanAccess", "internal tuning, verify against a live X before changing"),
        Skip("enforcement.preferXCommands",
             "per-channel opt-in for the X-routed enforcement fallback; set live per "
             "channel only after completing the live verification procedure in "
             "docs/UNDERNETX.md, not at install time"),
        Skip("enforcement.xFallbackEnabled",
             "master arm switch for X-routed enforcement -- ships off; the reply-text "
             "classifier it depends on (xprobe.py) isn't verified against a live X "
             "reply for any given deployment's account, see docs/UNDERNETX.md's "
             "rollout procedure before ever enabling"),
        Skip("enforcement.minAccessLevel",
             "internal tuning; verify against a live X ACCESS reply before changing"),
        Skip("enforcement.probeTtlSecs", "internal tuning"),
        Skip("enforcement.probeMinIntervalSecs", "internal tuning"),
    ],
}


def all_ask_entries() -> list[tuple[str, Ask]]:
    """(plugin_name, Ask) for every Ask entry across the whole catalog."""
    out = []
    for plugin_name, entries in CATALOG.items():
        for entry in entries:
            if isinstance(entry, Ask):
                out.append((plugin_name, entry))
    return out
