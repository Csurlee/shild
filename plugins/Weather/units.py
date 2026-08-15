"""Pure unit-conversion and time-rendering helpers -- no supybot import,
no I/O. Two things here are load-bearing, not cosmetic, and both were
verified against a real reference line before being written this way
(see CLAUDE.md's Weather section):

1. Fahrenheit is derived from the INTEGER Celsius, then truncated (never
   rounded, never derived from the raw float) -- `int(c*9/5+32)` matches
   all 7 verified pairs from the reference; `round(...)` mismatches 4 of
   them (27C->80F not 81F, 36C->96F not 97F, 17C->62F not 63F,
   21C->69F not 70F).
2. Every clock rendering here takes an explicit `tz_offset_secs` and
   never touches the host's own local time -- `local_hhmm`/`local_date`
   shift a UTC epoch by the target location's own offset and format as
   aware UTC, so a run on this server (Europe/Berlin) renders the same
   result as a run anywhere else. A bare `datetime.fromtimestamp(x)`
   (naive, host-local) must never appear in this plugin -- see the grep
   guard in the module docstring pattern used by evidence.py/fusion.py's
   own "never break this invariant" comments elsewhere in this repo.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone, date

_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def c_int(celsius: float) -> int:
    """Round-half-up to the nearest whole Celsius degree, explicitly --
    NOT Python's builtin round() (banker's rounding, rounds 0.5 to even)
    and NOT a bare int() (truncates toward zero, wrong for negatives).
    math.floor(x + 0.5) is correct for both positive and negative input
    in the range weather ever produces.
    """
    return math.floor(celsius + 0.5)


def f_int(c: int) -> int:
    """Fahrenheit from an ALREADY-ROUNDED integer Celsius value, then
    truncated (int(), not round()) -- see module docstring for why this
    exact order and rounding mode is required to match the reference.
    """
    return int(c * 9 / 5 + 32)


def temp_paren(celsius: float) -> str:
    """'27°C (80°F)' -- used for current temperature and the 'max:' field."""
    c = c_int(celsius)
    return f"{c}°C ({f_int(c)}°F)"


def temp_slash(celsius: float) -> str:
    """'27°C / 80°F' -- used for feels-like and every forecast high/low.
    Deliberately a different separator than temp_paren() -- both shapes
    appear in the same reference line and must be reproduced verbatim.
    """
    c = c_int(celsius)
    return f"{c}°C / {f_int(c)}°F"


def wind_kmh(meters_per_sec: float) -> int:
    return round(meters_per_sec * 3.6)


def wind_mph(meters_per_sec: float) -> int:
    return round(meters_per_sec * 2.236936)


def local_hhmm(utc_epoch: int, tz_offset_secs: int) -> str:
    """The target location's own wall-clock time, computed by shifting a
    UTC epoch by its own tz offset (OWM's "timezone" field, seconds) and
    formatting as AWARE UTC -- never datetime.fromtimestamp(x) alone
    (naive, silently uses the host's own local timezone instead).
    """
    dt = datetime.fromtimestamp(utc_epoch + tz_offset_secs, tz=timezone.utc)
    return dt.strftime("%H:%M")


def local_date(utc_epoch: int, tz_offset_secs: int) -> date:
    """Same shift as local_hhmm, but returns just the calendar date --
    used by forecast.py to bucket 3-hourly entries by the TARGET
    location's local day, not UTC and not the host's.
    """
    dt = datetime.fromtimestamp(utc_epoch + tz_offset_secs, tz=timezone.utc)
    return dt.date()


def weekday_abbrev(d: date) -> str:
    """Explicit English 3-letter abbreviation, NOT strftime("%a") --
    strftime is locale-dependent, and this bot runs in channels
    (#erdely, #kezdi) where the process locale could plausibly be
    Hungarian, which would silently emit "Szo"/"Vas" instead of
    "Sat"/"Sun". This table is deliberately independent of the process
    locale.
    """
    return _WEEKDAYS[d.weekday()]
