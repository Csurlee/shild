"""One long-lived thread with its own asyncio event loop, polling
configured repos on a timer. Same reasoning as plugins/Shild/worker.py
for why this isn't just a Limnoria `schedule.addPeriodicEvent` callback:
those run ON the main IRC loop, and even a "fast" GitHub API call
blocking that thread for a few seconds would stall doJoin/doPrivmsg for
every connected network. Simpler than Shild's worker.py, though: this is
a single self-driven poll loop, not a job queue fed by IRC events, so
there's no queue/semaphore/drop-oldest machinery needed.
"""
from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Callable, Optional

import aiohttp
from supybot import log, world

from . import github
from .state import SeenStateStore


@dataclass
class PollConfig:
    repos: list[str]
    poll_interval_secs: int
    token: Optional[str]
    max_commits_shown: int
    announce_pushes: bool
    announce_issues: bool
    announce_pull_requests: bool


class Worker:
    """`on_events` runs ON THE WORKER THREAD -- if it touches Limnoria
    state (posting to IRC), it must use thread-safe calls
    (`irc.queueMsg` is; see plugin.py), same rule as Shild's worker.py.
    """

    def __init__(self, state: SeenStateStore, get_config: Callable[[], PollConfig],
                 on_events: Callable[[str, list[dict]], None]):
        self._state = state
        self._get_config = get_config
        self._on_events = on_events
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._ready = threading.Event()
        self.last_poll_ok: dict[str, bool] = {}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._ready.clear()
        self._thread = world.SupyThread(target=self._run, name="GitHubWatchWorker")
        self._thread.daemon = True
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def stop(self, timeout: float = 5.0) -> None:
        if self._loop is not None and self._stop_event is not None:
            try:
                self._loop.call_soon_threadsafe(self._stop_event.set)
            except RuntimeError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
            self._loop = None
            self._stop_event = None

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._stop_event = asyncio.Event()
        self._ready.set()
        try:
            self._loop.run_until_complete(self._poll_forever())
        finally:
            self._loop.close()

    async def _poll_forever(self) -> None:
        assert self._stop_event is not None
        async with aiohttp.ClientSession() as session:
            while not self._stop_event.is_set():
                cfg = self._get_config()
                for repo in cfg.repos:
                    if self._stop_event.is_set():
                        break
                    await self._poll_one(session, repo, cfg)
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=cfg.poll_interval_secs
                    )
                except asyncio.TimeoutError:
                    pass  # normal -- just means it's time to poll again

    async def _poll_one(self, session: aiohttp.ClientSession, repo: str, cfg: PollConfig) -> None:
        if "/" not in repo:
            log.warning("GitHubWatch: skipping malformed repo %r (want owner/repo)", repo)
            return
        owner, name = repo.split("/", 1)
        events, error = await github.fetch_events(session, owner, name, token=cfg.token)
        self.last_poll_ok[repo] = error is None
        if error is not None:
            log.info("GitHubWatch: poll of %s failed: %s", repo, error)
            return
        if not events:
            return

        since_id = self._state.last_seen(repo)
        newest_id = github.max_event_id(events)
        relevant = github.relevant_events(events, since_id=since_id)
        relevant = [
            e for e in relevant
            if (cfg.announce_pushes if e.get("type") == "PushEvent" else
                cfg.announce_issues if e.get("type") == "IssuesEvent" else
                cfg.announce_pull_requests if e.get("type") == "PullRequestEvent" else True)
        ]

        if since_id is None:
            # First time seeing this repo: don't replay its whole recent
            # history into the channel, just establish the cursor.
            if newest_id is not None:
                self._state.mark_seen(repo, newest_id)
            return

        if relevant:
            self._on_events(repo, list(reversed(relevant)))  # chronological order
        if newest_id is not None:
            self._state.mark_seen(repo, newest_id)
