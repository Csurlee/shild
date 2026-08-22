"""GitHubWatch: polls configured GitHub repos and announces new pushes,
opened issues, and opened/merged pull requests to a configured channel.

Separate plugin from Shild on purpose -- this has nothing to do with
join/message threat analysis, it's a notification feature, and keeping
it independent means it can be loaded/reloaded/disabled without
touching Shild's own state at all.

Posts to every connected network whose `channel` config value is
non-empty, via the live `Irc` object looked up per network at post time
(`world.getIrc`/`world.ircs`), never a reference captured earlier -- a
reconnect must not leave this posting through a stale connection (same
reasoning as Shild's auto-unban scheduling in plugins/Shild/plugin.py).
"""
from __future__ import annotations

from supybot import callbacks, conf, ircmsgs, log, schedule, world
from supybot.commands import wrap

from . import github
from .secrets import load_github_token
from .state import SeenStateStore
from .worker import PollConfig, Worker


class GitHubWatch(callbacks.Plugin):
    """Polls GitHub for new pushes/issues/pull requests and announces
    them to a configured channel. Read-only aside from that -- no
    commands that change repo/channel state, only `!githubwatchstatus`.
    """

    def __init__(self, irc):
        self.__parent = super(GitHubWatch, self)
        self.__parent.__init__(irc)
        self._state = SeenStateStore(self.registryValue("statePath"))
        self._worker = Worker(self._state, self._build_poll_config, self._on_events)
        self._worker.start()
        self._pin_network_values()
        self._pin_event_name = f"githubwatchPinNetworkValues-{id(self)}"
        try:
            schedule.removeEvent(self._pin_event_name)
        except KeyError:
            pass
        schedule.addPeriodicEvent(
            self._pin_network_values, 60, self._pin_event_name, now=False)

    def _pin_network_values(self) -> None:
        """2026-08-22: channel (registerNetworkValue) is only persisted
        through a clean shutdown's registry write-back if it was actually
        READ during this process's run -- see Shild's own matching fix
        (plugins/Shild/plugin.py) for the full explanation, including WHY
        this must also run on a periodic retry (a single __init__-time
        call isn't enough: getSpecific(network=X) silently falls back to
        the bare value whenever world.getIrc(X) isn't registered yet at
        that exact moment, and Undernet routinely hasn't finished
        connecting by the time this process-wide __init__ runs).
        Force-activates every configured network's channel by writing it
        back to its own current value, so it survives the next write-back
        regardless of whether a poll happens to announce something
        first."""
        for network in conf.supybot.networks():
            current = self.registryValue("channel", network=network)
            if current:
                self.setRegistryValue("channel", current, network=network)

    def die(self):
        self._worker.stop()
        try:
            schedule.removeEvent(self._pin_event_name)
        except KeyError:
            pass
        self.__parent.die()

    # ---- config -> worker ----

    def _build_poll_config(self) -> PollConfig:
        token = load_github_token(self.registryValue("secretsPath"))
        return PollConfig(
            repos=list(self.registryValue("repos")),
            poll_interval_secs=self.registryValue("pollIntervalSecs"),
            token=token,
            max_commits_shown=self.registryValue("maxCommitsShown"),
            announce_pushes=self.registryValue("announcePushes"),
            announce_issues=self.registryValue("announceIssues"),
            announce_pull_requests=self.registryValue("announcePullRequests"),
        )

    # ---- worker -> IRC (runs on the worker thread) ----

    def _on_events(self, repo: str, events: list[dict]) -> None:
        max_commits_shown = self.registryValue("maxCommitsShown")
        for irc in world.ircs:
            channel = self.registryValue("channel", network=irc.network)
            if not channel:
                continue
            for event in events:
                try:
                    line = github.format_event(event, max_commits_shown)
                    irc.queueMsg(ircmsgs.privmsg(channel, line))
                except Exception:
                    log.exception("GitHubWatch: failed to announce event from %s", repo)

    # ---- the only command ----

    def githubwatchstatus(self, irc, msg, args):
        """takes no arguments

        Reports which repos are being polled, the worker thread's health,
        and the last poll result per repo. Read-only.
        """
        repos = self.registryValue("repos")
        if not repos:
            irc.reply("GitHubWatch: no repos configured (plugins.GitHubWatch.repos is empty).")
            return
        results = self._worker.last_poll_ok
        per_repo = ", ".join(
            f"{r}={'ok' if results.get(r) else ('fail' if r in results else 'pending')}"
            for r in repos
        )
        irc.reply(
            f"GitHubWatch: worker={'running' if self._worker.running else 'STOPPED'} "
            f"pollInterval={self.registryValue('pollIntervalSecs')}s | repos: {per_repo}"
        )

    githubwatchstatus = wrap(githubwatchstatus)


Class = GitHubWatch
