"""WebPanel: a read-only, LAN-only, authenticated web dashboard for
shild-py -- ZNC-style overview/stats/logs/live-preview/commands pages
over data Shild/ChannelStats/ChannelLogger already produce.

Separate plugin from Shild on purpose, same reasoning as GitHubWatch's
own module docstring: this is a presentation layer over data that
already exists, not threat-analysis logic, and keeping it independent
means it can be loaded/reloaded/disabled without touching Shild's state
or its hermetic test suite at all.

**Read-only in this phase.** WebPanelCallback.doPost (http.py) returns a
bare 405 for every path -- no route accepts a form submission, changes a
setting, or writes anything. Adding bot-settings management (nick, real
name, server list, etc.) is a deliberate later phase that needs CSRF
protection, an Origin/Referer check, a capability-based allowlist of
which registry keys are settable at all, and an audit log -- all absent
today on purpose, not by oversight. See this project's WebPanel design
notes for the full reasoning.

**Fail-closed on missing credentials**, unlike every other secrets
loader in this repo -- see secrets.py's module docstring for why the
polarity is inverted here (a missing key elsewhere just disables an
optional feature; a missing key here would mean serving real users'
channel logs and shadow-decision data to the LAN with no login at all).
"""
from __future__ import annotations

from supybot import callbacks, conf, httpserver, schedule, world

from .http import WebPanelCallback

_DEFAULT_REPORT_DIR = "daily_analysis"
_DEFAULT_SHADOW_DATA_PATH = "data/shadow_decisions.jsonl"


class WebPanel(callbacks.Plugin):
    def __init__(self, irc):
        self.__parent = super(WebPanel, self)
        self.__parent.__init__(irc)
        self._http_running = False
        self._callback = None
        # Scheduler events are global and survive plugin reload, so use
        # a name unique to this instance and always clear it first --
        # same convention as Shild's own periodic events.
        self._parted_check_event_name = f"webpanelPartedCheck-{id(self)}"
        conf.supybot.plugins.WebPanel.enable.addCallback(self._configCallback)
        if self.registryValue("enable"):
            self._startHttp()

    def die(self):
        if self._http_running:
            self._stopHttp()
        conf.supybot.plugins.WebPanel.enable.removeCallback(self._configCallback)
        self.__parent.die()

    def _configCallback(self):
        # Registered against the `enable` value itself (see __init__),
        # so toggling `@config plugins.WebPanel.enable` hooks/unhooks
        # live with no reload needed -- same idiom as Aka's
        # web.enable.addCallback in the bundled Aka plugin.
        if self.registryValue("enable"):
            if not self._http_running:
                self._startHttp()
        else:
            if self._http_running:
                self._stopHttp()

    def _startHttp(self):
        # Track readiness via this flag, not registryValue('enable') --
        # the config can change between hook and die/unhook, and basing
        # the unhook decision on the flag (rather than re-reading config)
        # is what keeps die() correct regardless of what happened to the
        # setting in between.
        self._callback = WebPanelCallback(self)
        httpserver.hook("panel", self._callback)
        self._http_running = True
        try:
            schedule.removeEvent(self._parted_check_event_name)
        except KeyError:
            pass
        # now=True (unlike Shild's own periodic events, which
        # deliberately wait one full interval) -- a channel already
        # parted before this plugin ever loaded/reloaded must show its
        # "Parted" annotation on the very next page load, not up to
        # partedCheckIntervalSecs (default 1 HOUR) later.
        schedule.addPeriodicEvent(
            self._run_parted_check,
            self.registryValue("partedCheckIntervalSecs"),
            self._parted_check_event_name, now=True,
        )

    def _stopHttp(self):
        try:
            schedule.removeEvent(self._parted_check_event_name)
        except KeyError:
            pass
        httpserver.unhook("panel")
        self._callback = None
        self._http_running = False

    def _run_parted_check(self) -> None:
        if self._callback is not None:
            self._callback.run_parted_maintenance()

    # ---- path resolution shared with http.py's file-backed routes ----

    def channel_log_dir(self) -> str:
        """Base directory for ChannelLogger's <network>/<channel> log
        files. Empty config derives the SAME path ChannelLogger itself
        computes (dirize("ChannelLogger") under supybot.directories.log)
        -- this only touches Limnoria's own core config, never Shild's,
        so it works whether or not Shild/ChannelLogger happen to be
        loaded in this process."""
        configured = self.registryValue("channelLogDir")
        if configured:
            return configured
        return conf.supybot.directories.log.dirize("ChannelLogger")

    def report_dir(self) -> str:
        """Directory holding Shild's daily *-report.md/-summary.json
        files. Empty config derives it from Shild's own report.dir
        registry value IF Shild's config module has been imported in
        this process (it may not be -- e.g. plugins/WebPanel/test.py
        deliberately loads only WebPanel, to prove this page degrades
        gracefully rather than erroring when Shild isn't loaded), else
        falls back to the relative default Shild itself would use."""
        configured = self.registryValue("reportDir")
        if configured:
            return configured
        shild_group = getattr(conf.supybot.plugins, "Shild", None)
        if shild_group is not None:
            try:
                return shild_group.report.dir()
            except AttributeError:
                pass
        return _DEFAULT_REPORT_DIR

    def shadow_data_path(self) -> str:
        """Path to data/shadow_decisions.jsonl for /panel/scans. Same
        empty-means-derive-from-Shild-or-fall-back pattern as
        report_dir() above."""
        configured = self.registryValue("shadowDataPath")
        if configured:
            return configured
        shild_group = getattr(conf.supybot.plugins, "Shild", None)
        if shild_group is not None:
            try:
                return shild_group.shadowDataPath()
            except AttributeError:
                pass
        return _DEFAULT_SHADOW_DATA_PATH

    def channelstats_callback(self):
        """Same never-cache reasoning as shild_callback() above."""
        for irc in world.ircs:
            cb = irc.getCallback("ChannelStats")
            if cb is not None:
                return cb
        return None

    def shild_callback(self):
        """The live Shild plugin instance, looked up fresh each call --
        NEVER cache this. @reload Shild constructs a new instance and
        die()s the old one; a cached reference would keep reading a dead
        instance's frozen counters and a ContextStore nothing writes to
        anymore (same reasoning as GitHubWatch's own world.ircs lookups
        -- see that plugin's module docstring). Returns None if Shild
        isn't loaded on any connected network; callers must degrade
        gracefully (a "Shild not loaded" notice, still HTTP 200), never
        error.
        """
        for irc in world.ircs:
            cb = irc.getCallback("Shild")
            if cb is not None:
                return cb
        return None


Class = WebPanel
