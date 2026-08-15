"""OWM condition-icon -> IRC-safe symbol mapping. Pure, no supybot import.

OWM's `weather[0].icon` is a code like "01d"/"10n" -- a 2-digit condition
group plus a day("d")/night("n") suffix. We map on the group, with an
explicit day/night split only for "01" (clear) and "02" (few clouds) --
every other group (broken clouds, rain, thunderstorm, snow, mist) reads
the same regardless of time of day, so splitting those would just be two
copies of the same symbol.

Deliberately restricted to the Basic Multilingual Plane (single UTF-16
code unit, single "wide-ish" glyph in most terminal/IRC-client fonts) --
astral-plane weather emoji (unicode 🌧 ⛈ 🌫 etc.) render as a missing-
glyph box on several IRC clients (mIRC, older irssi builds) and cost more
UTF-8 bytes per character, eating into render.py's line-length budget for
no benefit. Only "☀" and "☁" are actually pinned by the reference line
this plugin was built to reproduce (see units.py's module docstring) --
the rest of this table is a judgement call and is deliberately a single,
easy-to-edit dict rather than scattered logic.
"""
from __future__ import annotations

from typing import Optional

_SYMBOLS = {
    "01d": "☀", "01n": "☾",
    "02d": "⛅", "02n": "☁",
    "03d": "☁", "03n": "☁",
    "04d": "☁", "04n": "☁",
    "09d": "☔", "09n": "☔",
    "10d": "☂", "10n": "☂",
    "11d": "⚡", "11n": "⚡",
    "13d": "❄", "13n": "❄",
    "50d": "≡", "50n": "≡",
}
_FALLBACK = "·"

# Severity ranking for forecast.py's representative_icon() -- higher
# number wins when picking one symbol to summarize a whole day's worth
# of 3-hourly entries. Index is the icon group (first 2 digits).
_SEVERITY = {
    "11": 9,  # thunderstorm
    "13": 8,  # snow
    "10": 7,  # rain (showers)
    "09": 6,  # rain (drizzle/shower)
    "50": 5,  # mist/fog/haze
    "04": 4,  # overcast clouds
    "03": 3,  # scattered/broken clouds
    "02": 2,  # few clouds
    "01": 1,  # clear
}


def symbol_for_icon(icon: Optional[str]) -> str:
    """The display symbol for a raw OWM icon code, e.g. "01d" -> "☀".
    Unknown/missing codes fall back to a neutral marker rather than
    raising -- a symbol lookup must never be why a weather reply fails.
    """
    if not icon:
        return _FALLBACK
    return _SYMBOLS.get(icon, _FALLBACK)


def day_variant(icon: Optional[str]) -> Optional[str]:
    """Normalizes a possibly-night icon code to its "d" (day) form --
    used by forecast.py so a forecast row (which describes a whole day,
    not a specific hour) never shows the night-only moon symbol ("01n"
    -> "☾") just because the 3-hourly entry it was picked from happened
    to fall after dark. Returns None for an unrecognized/missing code so
    the caller can fall back to its own default rather than silently
    keying off a made-up code.
    """
    if not icon or len(icon) != 3:
        return None
    group = icon[:2]
    if group not in _SEVERITY:
        return None
    return f"{group}d"


def severity(icon: Optional[str]) -> int:
    """0 for an unknown/missing code (lowest priority -- never wins a
    representative-icon pick over a real reading), else the ranking in
    _SEVERITY above.
    """
    if not icon or len(icon) < 2:
        return 0
    return _SEVERITY.get(icon[:2], 0)
