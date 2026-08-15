"""Unit tests for scripts/daily_data_summary.py's summarize_rows -- in
particular the activity_heatmap bucketing added alongside WebPanel's
heatmap view (plugins/WebPanel/render.py's activity_heatmap renders this
output). No existing test file covered summarize_rows before this.
"""
import sys
import time
from pathlib import Path

# scripts/ isn't a pip-installed package (unlike shildml) and pytest's
# default import mode doesn't guarantee the repo root is on sys.path --
# same resolution shild plugins/WebPanel/stats.py already uses for the
# same reason.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.daily_data_summary import summarize_rows  # noqa: E402


def _row(ts, **overrides):
    row = {"ts": ts, "fused": {"action": "allow", "source": "classifier"},
           "label_quality": "ok", "event_type": "join",
           "network": "libera", "channel": "#windrop"}
    row.update(overrides)
    return row


def test_empty_rows_gives_zeroed_heatmap():
    result = summarize_rows([], hours=24)
    grid = result["activity_heatmap"]
    assert len(grid) == 7
    assert all(len(row) == 24 for row in grid)
    assert all(v == 0 for row in grid for v in row)


def test_rows_without_ts_are_skipped_from_heatmap():
    result = summarize_rows([_row(ts=None), _row(ts=0)], hours=24)
    # ts=0 is falsy too (matches summarize_rows' `if ts:` guard, same as
    # the pre-existing top_near_miss handling of missing fields) -- both
    # rows must be excluded, not crash on None.
    grid = result["activity_heatmap"]
    assert all(v == 0 for row in grid for v in row)
    assert result["total_rows"] == 2  # still counted elsewhere, just not in the heatmap


def test_known_timestamp_lands_in_the_correct_bucket():
    # A fixed local time avoids any timezone ambiguity in the test itself
    # -- build the timestamp FROM a local struct_time via time.mktime,
    # mirroring exactly how summarize_rows reads it back with
    # time.localtime, so the test is timezone-independent.
    local = time.localtime()
    target = time.struct_time((
        local.tm_year, local.tm_mon, local.tm_mday,
        14, 30, 0, 2, 1, -1,  # 14:30, tm_wday=2 (Wednesday) placeholder, DST auto
    ))
    ts = time.mktime(target)
    expected_wday = time.localtime(ts).tm_wday
    expected_hour = time.localtime(ts).tm_hour

    result = summarize_rows([_row(ts=ts)], hours=24)
    grid = result["activity_heatmap"]
    assert grid[expected_wday][expected_hour] == 1
    total = sum(v for row in grid for v in row)
    assert total == 1


def test_multiple_events_in_the_same_bucket_accumulate():
    local = time.localtime()
    ts = time.mktime((local.tm_year, local.tm_mon, local.tm_mday,
                       9, 0, 0, 0, 1, -1))
    wday = time.localtime(ts).tm_wday
    hour = time.localtime(ts).tm_hour

    result = summarize_rows([_row(ts=ts), _row(ts=ts + 1), _row(ts=ts + 2)], hours=24)
    assert result["activity_heatmap"][wday][hour] == 3
