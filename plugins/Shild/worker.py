"""Long-lived asyncio worker thread + bounded queue for Ollama calls.

Limnoria's main loop is strictly single-threaded (confirmed against
Limnoria's source during planning) -- doJoin/doPrivmsg must never block.
The reference Dnsbl plugin spawns one `world.SupyThread` per event, which
is fine for cheap parallel DNS lookups but wrong here: Ollama inference
is seconds, not milliseconds, and a 30-join flood must not spawn 30
threads all serializing on one Ollama instance.

Instead: exactly one worker thread runs its own asyncio event loop for
the lifetime of the plugin. Jobs are handed off from Limnoria's main
thread via `asyncio.Queue.put_nowait` wrapped in
`loop.call_soon_threadsafe` (the standard, documented way to push work
into a different thread's event loop). A bounded queue with drop-oldest
shedding and an `asyncio.Semaphore` capping concurrent Ollama calls keep
a flood from turning into a pile of stalled requests.
"""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from supybot import world


@dataclass
class Job:
    coro_factory: Callable[[], Awaitable[Any]]
    on_result: Callable[[Any], None]
    submitted_at: float


class Worker:
    """One instance per Shild plugin instance (see plugin.py __init__/die).
    `submit()` is safe to call from Limnoria's main thread. `on_result`
    callbacks run ON THE WORKER THREAD -- if they touch Limnoria state,
    they must use thread-safe calls (`irc.sendMsg`/`irc.queueMsg` are;
    see plugin.py).
    """

    def __init__(self, max_queue: int = 64, max_concurrency: int = 2):
        self.max_queue = max_queue
        self.max_concurrency = max_concurrency
        self.dropped_count = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._queue: Optional[asyncio.Queue] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._ready.clear()
        self._thread = world.SupyThread(target=self._run, name="ShildWorker")
        self._thread.daemon = True
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def stop(self, timeout: float = 5.0) -> None:
        if self._loop is not None and self._queue is not None:
            try:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
            except RuntimeError:
                pass  # loop already closed
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
            self._loop = None
            self._queue = None

    def submit(self, coro_factory: Callable[[], Awaitable[Any]],
               on_result: Callable[[Any], None]) -> None:
        """Fire-and-forget. If the worker isn't running, the job is
        silently dropped and counted -- callers (plugin.py) should check
        `running` in a status command, not on every submit.
        """
        if self._loop is None or self._queue is None:
            self.dropped_count += 1
            return
        job = Job(coro_factory, on_result, time.monotonic())

        def _enqueue():
            assert self._queue is not None
            if self._queue.full():
                try:
                    self._queue.get_nowait()  # drop-oldest shedding
                    self.dropped_count += 1
                except asyncio.QueueEmpty:
                    pass
            self._queue.put_nowait(job)

        try:
            self._loop.call_soon_threadsafe(_enqueue)
        except RuntimeError:
            self.dropped_count += 1

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._queue = asyncio.Queue(maxsize=self.max_queue)
        self._ready.set()
        try:
            self._loop.run_until_complete(self._dispatch())
        finally:
            self._loop.close()

    async def _dispatch(self) -> None:
        assert self._queue is not None
        sem = asyncio.Semaphore(self.max_concurrency)
        pending: set[asyncio.Task] = set()

        async def handle(job: Job) -> None:
            async with sem:
                try:
                    result = await job.coro_factory()
                except Exception as e:  # noqa: BLE001 -- the worker loop must never die
                    result = e
                job.on_result(result)

        while True:
            job = await self._queue.get()
            if job is None:  # shutdown sentinel from stop()
                break
            task = asyncio.ensure_future(handle(job))
            pending.add(task)
            pending = {t for t in pending if not t.done()}

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
