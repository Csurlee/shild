"""Pure/bounded readers over shild-py's JSONL data files for WebPanel.
No supybot import.

`tail_records` is what backs /panel/scans -- deliberately NOT
scripts/daily_data_summary.summarize(), which parses the ENTIRE
data/shadow_decisions.jsonl (multi-MB and only ever growing) on every
call. Limnoria's HTTP server handles requests serially (see http.py's
module docstring), so a full-file scan on the request thread would stall
every other client for as long as it takes. This reads a bounded window
from the end of the file instead -- O(max_bytes), not O(file size).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .logs import tail_lines

# scripts/ isn't a pip-installed package (unlike shildml, which
# plugins/Shild already imports freely regardless of cwd -- see
# pyproject.toml) and the live bot's cwd is runtime/, so scripts/ is
# never on sys.path by default there. Resolve the repo root relative to
# THIS file (plugins/WebPanel/stats.py -> plugins/WebPanel -> plugins ->
# repo root) so `import scripts.*` works the same in the live bot, in
# supybot-test, and in plain pytest, with no dependency on cwd.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Comfortably more lines than any real `n` this module is asked for --
# tail_lines' own `max_bytes` argument is what actually bounds the I/O,
# this just tells it "don't truncate the line count before we've had a
# chance to filter out malformed/partial lines".
_MAX_CANDIDATE_LINES = 100_000


def tail_records(path: str, n: int, max_bytes: int = 262_144) -> List[dict]:
    """Returns up to the last `n` valid JSON objects from a JSONL file,
    oldest-first (same order as the file), reading at most `max_bytes`
    from its end. Malformed or partial lines -- a concurrent writer can
    leave a torn final line, since collector.py appends and closes per
    record rather than atomically -- are skipped SILENTLY, unlike
    shildml.schema.read_jsonl (which prints skips to stderr): a
    dashboard tailing a live-growing file shouldn't be noisy about
    something this routine expects to happen occasionally. Returns []
    for a missing file or n <= 0, never raises.
    """
    if n <= 0:
        return []
    raw_lines = tail_lines(Path(path), n=_MAX_CANDIDATE_LINES, max_bytes=max_bytes)
    records = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
    return records[-n:]


# Bounds for the tail-bounded near-miss/distribution summary fed to
# scripts.daily_data_summary.summarize_rows -- this runs on the
# SummaryCache's own background thread (see below), never on a request
# thread, so a larger budget than /panel/scans' 256KiB default is fine.
# "24.0" is a LABEL only (matches summarize()'s own `window_hours`
# output field for familiarity) -- summarize_tail below does NOT
# actually filter by wall-clock time, it summarizes whatever fits in the
# byte budget, which is an approximation of "recent" good enough for a
# live dashboard. scripts/daily_data_analysis.sh's own scheduled run
# (via summarize(), the real time-filtered version) remains the source
# of truth if the two ever visibly disagree.
_SUMMARY_TAIL_BYTES = 4 * 1024 * 1024
_SUMMARY_TAIL_RECORDS = 50_000
_SUMMARY_WINDOW_HOURS_LABEL = 24.0


def summarize_tail(path: str) -> dict:
    from scripts import daily_data_summary  # local import: see _REPO_ROOT sys.path setup above
    rows = tail_records(path, n=_SUMMARY_TAIL_RECORDS, max_bytes=_SUMMARY_TAIL_BYTES)
    return daily_data_summary.summarize_rows(rows, _SUMMARY_WINDOW_HOURS_LABEL)


def gate_report(path: str) -> dict:
    """Whole-corpus by design (see scripts/gate_report.py's own module
    docstring) -- this is exactly the kind of call SummaryCache exists
    to keep off the request thread."""
    from scripts import gate_report as gate_report_mod
    return gate_report_mod.analyze(path)


class SummaryCache:
    """Background-refreshed cache for an expensive computation over a
    JSONL data file (near-miss ranking, the pre/post-gate A/B report)
    that must NEVER run on an HTTP request thread -- Limnoria's server
    handles requests serially (see http.py's module docstring), so a
    multi-second full-file scan would stall every other client for its
    entire duration.

    A background daemon thread recomputes on a `refresh_secs` interval,
    but SKIPS the actual (potentially expensive) `compute` call if the
    input file's (mtime, size) hasn't changed since the last successful
    computation -- an idle bot recomputes nothing. `get()` never blocks
    on I/O: it returns whatever was last computed (None before the first
    successful run), when, and the last error if the most recent attempt
    failed (the previous good result is kept rather than discarded).
    """

    def __init__(self, path_fn: Callable[[], str], compute: Callable[[str], dict],
                 refresh_secs: float):
        self._path_fn = path_fn
        self._compute = compute
        # No artificial floor here -- the registry values that drive this
        # in production (summaryRefreshSecs/gateRefreshSecs) are already
        # PositiveInteger (minimum 1), and tests want to pass a much
        # smaller interval to stay fast without waiting real minutes.
        self._refresh_secs = refresh_secs
        self._lock = threading.Lock()
        self._result: Optional[dict] = None
        self._computed_at: float = 0.0
        self._last_error: Optional[str] = None
        self._last_stat_key: Optional[tuple] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="WebPanel-SummaryCache")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def get(self) -> Tuple[Optional[dict], float, Optional[str]]:
        """(result, computed_at_epoch, last_error) -- result is None
        until the first successful computation; last_error is set
        whenever the MOST RECENT attempt failed, even if an older
        result is still being returned."""
        with self._lock:
            return self._result, self._computed_at, self._last_error

    def _run(self) -> None:
        # Compute once immediately on start (don't make the first
        # request wait a full refresh_secs for any data at all), then on
        # the configured interval.
        self._maybe_refresh()
        while not self._stop.wait(self._refresh_secs):
            self._maybe_refresh()

    def _maybe_refresh(self) -> None:
        path = self._path_fn()
        try:
            st = os.stat(path)
            stat_key = (path, st.st_mtime, st.st_size)
        except OSError:
            stat_key = (path, None, None)
        if stat_key == self._last_stat_key:
            return
        try:
            result = self._compute(path)
        except Exception as e:  # noqa: BLE001 - a background refresher must never crash the thread
            with self._lock:
                self._last_error = repr(e)
            return
        with self._lock:
            self._result = result
            self._computed_at = time.time()
            self._last_stat_key = stat_key
            self._last_error = None
