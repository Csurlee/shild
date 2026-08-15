"""3-hourly OWM forecast entries -> daily summaries. Pure, no supybot
import, no I/O -- takes plain dicts (the parsed JSON body of OWM's
/data/2.5/forecast response) and a tz offset, returns DayForecast
objects. See units.py's module docstring for why every date/time
computation here goes through units.local_date()/local_hhmm() rather
than any host-local time function.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import symbols, units

# How many future days a clean call always returns when there's enough
# data -- OWM's free /forecast endpoint covers 5 days, so 3 always fits
# comfortably even after excluding "today".
DEFAULT_DAYS = 3

# Local-hour window treated as "daytime" when picking a day's
# representative condition -- see representative_icon()'s docstring.
_DAY_START_HOUR = 9
_DAY_END_HOUR = 18


@dataclass
class DayForecast:
    weekday: str
    symbol: str
    high_c: float
    low_c: float


def _entry_local(entry: dict, tz_offset_secs: int):
    """Returns (date, hour) in the target's local time for one 3-hourly
    entry, or None if the entry is malformed -- callers must skip a
    None rather than raise, same per-record tolerance as
    plugins/SpamGuard/terms.py's TermStore._load.
    """
    try:
        dt_epoch = int(entry["dt"])
    except (KeyError, TypeError, ValueError):
        return None
    d = units.local_date(dt_epoch, tz_offset_secs)
    hour = ((dt_epoch + tz_offset_secs) // 3600) % 24
    return d, hour


def representative_icon(entries: list, tz_offset_secs: int) -> Optional[str]:
    """Picks one icon code to summarize a whole day's worth of 3-hourly
    entries -- the entry with the highest symbols.severity() among
    "daytime" (local 09:00-18:00) entries, falling back to all entries
    if none fall in that window (can happen at the far edge of the
    5-day horizon, where only a couple of entries exist for the last
    day). This is deliberately NOT "pick the noon-nearest entry" --
    a severity-ranked pick is what reproduces the reference's
    "Sat: ☁" on an otherwise-36°C day (a single stormy afternoon entry
    outranks several clear-morning ones). Returns None for an empty or
    entirely-malformed entry list.
    """
    daytime = []
    all_valid = []
    for e in entries:
        local = _entry_local(e, tz_offset_secs)
        if local is None:
            continue
        _, hour = local
        icon = (e.get("weather") or [{}])[0].get("icon")
        all_valid.append(icon)
        if _DAY_START_HOUR <= hour <= _DAY_END_HOUR:
            daytime.append(icon)
    pool = daytime or all_valid
    if not pool:
        return None
    best = max(pool, key=symbols.severity)
    return symbols.day_variant(best) or best


def daily_forecast(
    entries: list,
    tz_offset_secs: int,
    now_utc: int,
    days: int = DEFAULT_DAYS,
) -> list:
    """Groups 3-hourly forecast entries into up to `days` DayForecast
    objects, one per upcoming calendar day IN THE TARGET LOCATION'S
    timezone (never UTC, never the host's) -- see units.py. "Today" is
    always excluded, matching the reference (queried Fri 10:25 local,
    first forecast row is Sat) even though most of today's data window
    is still in the future at query time.
    """
    today = units.local_date(now_utc, tz_offset_secs)

    buckets: dict = {}
    for e in entries:
        local = _entry_local(e, tz_offset_secs)
        if local is None:
            continue
        d, _ = local
        try:
            main = e["main"]
            temp = float(main["temp"])
        except (KeyError, TypeError, ValueError):
            continue
        high = float(main.get("temp_max", temp))
        low = float(main.get("temp_min", temp))
        bucket = buckets.setdefault(d, {"entries": [], "high": high, "low": low})
        bucket["entries"].append(e)
        bucket["high"] = max(bucket["high"], high)
        bucket["low"] = min(bucket["low"], low)

    future_dates = sorted(d for d in buckets if d > today)[:days]

    result = []
    for d in future_dates:
        b = buckets[d]
        icon = representative_icon(b["entries"], tz_offset_secs)
        result.append(DayForecast(
            weekday=units.weekday_abbrev(d),
            symbol=symbols.symbol_for_icon(icon),
            high_c=b["high"],
            low_c=b["low"],
        ))
    return result
