"""Config registry for WebPanel -- a read-only, LAN-only, authenticated
web dashboard for shild-py. See plugin.py's module docstring for the
phase-1 read-only boundary this deliberately does not cross (no settings
routes, no POST handlers that change anything).

Nothing registered here is a credential. The panel's username/password
hash live in runtime/secrets.json (see secrets.py), specifically so an
admin's `@config` dump can never leak them -- runtime/shildpy.conf is
world-readable (mode 0664) and already demonstrates why: as of
2026-08-06 it holds this project's live Libera NickServ and Undernet X
passwords in cleartext.
"""
from __future__ import annotations

from supybot import conf, registry

try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization("WebPanel")
except ImportError:
    _ = lambda x: x  # noqa: E731


def configure(advanced):
    conf.registerPlugin("WebPanel", True)


WebPanel = conf.registerPlugin("WebPanel")

conf.registerGlobalValue(
    WebPanel, "enable",
    registry.Boolean(False, _(
        """Whether the web panel's HTTP routes are hooked at all. False
        by default -- inert until deliberately turned on. Toggling this
        live via @config hooks/unhooks immediately, no reload needed
        (see plugin.py's _configCallback).""")),
)

conf.registerGlobalValue(
    WebPanel, "secretsPath",
    registry.String("secrets.json", _(
        """Path to the gitignored local secrets file holding
        web_panel_user/web_panel_password_hash, resolved relative to the
        bot's own working directory (runtime/, since it's started via
        `cd runtime && supybot shildpy.conf`) -- NOT relative to the repo
        root, so this must be "secrets.json", not "runtime/secrets.json".
        Getting this wrong silently disabled Shild's and GitHubWatch's
        own secrets loading before it was caught (see CLAUDE.md) -- here
        it fails closed instead (no credentials means the panel refuses
        every request, see secrets.py), so the failure mode is at least
        visible rather than silent.""")),
)

conf.registerGlobalValue(
    WebPanel, "allowedHosts",
    registry.SpaceSeparatedListOfStrings(
        ["127.0.0.1:8080", "localhost:8080"], _(
        """Space-separated allowlist of acceptable HTTP Host header
        values. Any request whose Host isn't in this list is rejected
        with 400 BEFORE authentication is even checked. This is the
        entire defense against DNS rebinding: without it, a website you
        merely visit could resolve its own hostname to this box's LAN IP
        and reach the panel through your own browser, which would attach
        your cached Basic-Auth credentials automatically. If the panel is
        bound to a LAN IP (see scripts/bootstrap_runtime.py's
        HTTP_BIND4), that IP:port must be added here too or every
        request will 400.""")),
)

conf.registerGlobalValue(
    WebPanel, "authCacheSecs",
    registry.NonNegativeInteger(300, _(
        """How long (seconds) a successfully verified username/password
        is remembered in memory, so the deliberately slow password hash
        (see auth.py's hash_password) doesn't get re-run on every single
        page load / live-preview refresh -- Limnoria's HTTP server
        handles requests serially, so that would let a couple of open
        browser tabs freeze the panel for everyone. 0 disables the cache
        (every request re-runs the full hash). Set to 0 temporarily
        while rotating the panel password, since a cached credential
        stays valid for up to this long after being changed. Only read
        at plugin load/reload, not live.""")),
)

conf.registerGlobalValue(
    WebPanel, "maxAuthFailures",
    registry.PositiveInteger(5, _(
        """How many failed login attempts from the same client IP within
        60 seconds trigger a lockout (see authLockoutSecs). Only read at
        plugin load/reload, not live.""")),
)

conf.registerGlobalValue(
    WebPanel, "authLockoutSecs",
    registry.PositiveInteger(300, _(
        """How long (seconds) a client IP is locked out after
        maxAuthFailures failed attempts within a 60s window.
        Deliberately a lockout window rather than a per-request sleep()
        delay -- Limnoria's HTTP server handles requests serially, so
        sleeping inside a request handler would freeze the panel for
        every other client too, not just the one being throttled. Only
        read at plugin load/reload, not live.""")),
)

conf.registerGlobalValue(
    WebPanel, "channelLogDir",
    registry.String("", _(
        """Base directory to look for ChannelLogger's <network>/<channel>
        log files under. Empty (the default) derives it from Limnoria's
        own supybot.directories.log the same way ChannelLogger itself
        does (dirize("ChannelLogger")) -- one source of truth, only
        override this if channel logs live somewhere non-standard.""")),
)

conf.registerGlobalValue(
    WebPanel, "reportDir",
    registry.String("", _(
        """Directory to look for Shild's daily *-report.md/-summary.json
        files in. Empty (the default) derives it from
        supybot.plugins.Shild.report.dir if the Shild plugin's config is
        loaded, falling back to "daily_analysis" (relative to the bot's
        runtime/ working directory) if Shild's config isn't available at
        all -- so /panel/report degrades to "no reports found" rather
        than erroring when Shild isn't loaded.""")),
)

conf.registerGlobalValue(
    WebPanel, "logTailLines",
    registry.PositiveInteger(300, _(
        """Default number of lines shown on /panel/log/<network>/
        <channel>. A request's own ?n= query parameter can ask for more,
        clamped to this value -- see logTailMaxBytes for the hard byte
        cap that applies regardless of how many lines are requested.""")),
)

conf.registerGlobalValue(
    WebPanel, "logTailMaxBytes",
    registry.PositiveInteger(1048576, _(
        """Hard cap (bytes) on how much of a log file is ever read for a
        single /panel/log/<network>/<channel> request, regardless of
        ?n=. Without this a multi-GB log file (rotateLogs=False, or just
        a very long-lived channel) could be read entirely into memory by
        one request.""")),
)

conf.registerGlobalValue(
    WebPanel, "shadowDataPath",
    registry.String("", _(
        """Path to data/shadow_decisions.jsonl for /panel/scans. Empty
        (the default) derives it from supybot.plugins.Shild.shadowDataPath
        if Shild's config is loaded, falling back to
        "data/shadow_decisions.jsonl" otherwise -- one source of truth,
        same reasoning as reportDir above.""")),
)

conf.registerGlobalValue(
    WebPanel, "recentScansCount",
    registry.PositiveInteger(10, _(
        """Default number of recently-scanned hosts shown on
        /panel/scans. A request's own ?n= can ask for more, capped at
        100 regardless (see http.py) -- this is a convenience dashboard,
        not a full export tool; scripts/gate_report.py and direct
        shadow_decisions.jsonl access remain the way to analyze the full
        corpus.""")),
)

conf.registerGlobalValue(
    WebPanel, "summaryRefreshSecs",
    registry.PositiveInteger(300, _(
        """How often (seconds) /panel/stats' near-miss/distribution
        summary is recomputed in the background. Never computed on a
        request thread -- see plugins/WebPanel/stats.py's SummaryCache
        docstring for why. An idle bot recomputes nothing regardless of
        this value, since the underlying file's (mtime, size) is checked
        first.""")),
)

conf.registerGlobalValue(
    WebPanel, "gateRefreshSecs",
    registry.PositiveInteger(900, _(
        """How often (seconds) /panel/gate's pre/post-evidence-gate A/B
        report is recomputed in the background. Longer than
        summaryRefreshSecs by default since scripts/gate_report.py scans
        the WHOLE corpus by design (not a bounded tail), making it the
        more expensive of the two -- see stats.py's gate_report()
        wrapper.""")),
)

class LivePreviewSource(registry.String):
    """Restricts plugins.WebPanel.livePreviewSource to a known set of
    values -- "logfile" (tail ChannelLogger's own file each refresh, no
    new data collection, nothing new held in memory) or "none" (disable
    the per-channel live view entirely; /panel/live/decisions, which
    doesn't depend on this, still works). A third "memory" mode (the
    plugin's own doPrivmsg/doJoin/etc. hooks feeding a small in-RAM
    ring buffer, covering channels with no ChannelLogger file too) was
    considered but not implemented in this phase -- "logfile" already
    covers the common case with strictly less new surface area; revisit
    only if a channel without logging enabled specifically needs a live
    view.
    """
    def setValue(self, v):
        if v not in ("logfile", "none"):
            raise registry.InvalidRegistryValue(
                'Value must be "logfile" or "none".')
        registry.String.setValue(self, v)

conf.registerGlobalValue(
    WebPanel, "livePreviewSource",
    LivePreviewSource("logfile", _(
        """Where /panel/live/<network>/<channel> gets its content from.
        "logfile" tails ChannelLogger's own file (see channelLogDir
        above) -- reuses the log-tailing code, adds no new data
        collection. "none" disables the per-channel live view (the
        cross-network Shild decision feed at /panel/live/decisions is
        unaffected either way).""")),
)

conf.registerGlobalValue(
    WebPanel, "liveLines",
    registry.PositiveInteger(40, _(
        """How many of the most recent lines are shown on
        /panel/live/<network>/<channel> each refresh.""")),
)

conf.registerGlobalValue(
    WebPanel, "liveRefreshSecs",
    registry.PositiveInteger(10, _(
        """How often (seconds) the live-preview pages
        (/panel/live/<network>/<channel> and /panel/live/decisions)
        auto-refresh, via a plain <meta http-equiv="refresh"> tag -- no
        JavaScript at all, which matters because the CSP set in http.py
        (default-src 'none', no script-src) means none could run anyway.
        Floored at 3 in code regardless of this value, so a
        misconfigured "0" or "1" can't turn the panel into a
        self-inflicted request flood.""")),
)

conf.registerGlobalValue(
    WebPanel, "liveDecisionsCount",
    registry.PositiveInteger(30, _(
        """How many recent events are shown on
        /panel/live/decisions (Shild's ContextStore.recent_global_events
        -- see plugins/Shild/context.py). Independent of
        recentScansCount, which reads a different data source
        (shadow_decisions.jsonl on disk, not the in-memory event
        ring).""")),
)

# ---------------------------------------------------------------------
# Parted-channel log retention (2026-08-10): a channel logged by
# ChannelLogger but no longer joined gets a "Parted -- deletes <date>"
# annotation on /panel/logs and /panel/live, and its whole log
# directory is deleted once partedRetentionDays have passed since it
# was FIRST observed parted. See plugins/WebPanel/parted.py for the
# tracking logic and http.py's run_parted_maintenance for the actual
# deletion. A channel rejoined before its retention window elapses has
# its tracking cleared -- the deletion clock only ever starts once per
# part, never accumulates across repeated parts.
# ---------------------------------------------------------------------

conf.registerGlobalValue(
    WebPanel, "partedStatePath",
    registry.String("webpanel_parted.json", _(
        """Path to the persisted record of when each parted channel was
        first observed parted (see parted.py). Resolved relative to the
        bot's own working directory (runtime/) -- do NOT prefix with
        "runtime/" (see Shild's budgetPath/secretsPath docstrings for
        the double-"runtime/" bug this exact mistake caused there).""")),
)

conf.registerGlobalValue(
    WebPanel, "partedRetentionDays",
    registry.PositiveInteger(7, _(
        """How many days after a channel is first observed parted its
        log directory is deleted. This is a real, irreversible file
        deletion -- raise this if channel logs should be kept around
        longer after parting for any reason.""")),
)

conf.registerGlobalValue(
    WebPanel, "partedCheckIntervalSecs",
    registry.PositiveInteger(3600, _(
        """How often (seconds) the parted-channel check runs: comparing
        every logged channel against each connected network's current
        join list, updating the "Parted -- deletes <date>" tracking,
        and deleting any channel's logs whose partedRetentionDays has
        elapsed. Runs on Limnoria's main thread (cheap: a directory
        listing plus small JSON read/write, not the request path), only
        while the panel itself is enabled.""")),
)
