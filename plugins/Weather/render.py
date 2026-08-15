"""Builds the final one-line IRC reply. Pure, no supybot import --
deliberately named render.py rather than format.py: `import supybot`
(pulled in transitively the moment anything else in this plugin process
is loaded) monkeypatches the builtin `format()` function process-wide,
and a module named `format` sitting in `plugins/Weather/` would invite
exactly the same `from . import format` shadowing mistake already
documented as a real incident in CLAUDE.md (plugins/WebPanel/render.py
hit the bare-format() version of this bug directly).

The whole point of this module is reproducing one specific reference
line character-for-character -- see tests/test_weather_render.py's
golden test, and CLAUDE.md's Weather section for the reference itself
and the two things about it that are load-bearing, not cosmetic:
Fahrenheit truncated from the integer Celsius (units.py), and the two
different current/max-vs-feels-like-and-forecast temperature renderings
appearing in the SAME line.
"""
from __future__ import annotations

from typing import Optional

from . import units, symbols
from .owm import CurrentWeather
from .forecast import DayForecast
from .airquality import AirQuality


def _core_segment(current: CurrentWeather) -> str:
    return (
        f"weather: {current.label}: {symbols.symbol_for_icon(current.icon)} "
        f"{units.temp_paren(current.temp_c)}, max: {units.temp_paren(current.temp_max_c)}, "
        f"{current.humidity_pct}% humidity, "
        f"{units.wind_kmh(current.wind_speed_ms)} km/h ({units.wind_mph(current.wind_speed_ms)} mph) wind, "
        f"feels like: {units.temp_slash(current.feels_like_c)}, "
        f"{current.clouds_pct}% cloud cover ({current.description})"
    )


def format_day(day: DayForecast) -> str:
    """'Sat: ☁ (high: 36°C / 96°F, low: 17°C / 62°F)'"""
    return (
        f"{day.weekday}: {day.symbol} "
        f"(high: {units.temp_slash(day.high_c)}, low: {units.temp_slash(day.low_c)})"
    )


def format_air_fragment(air: AirQuality) -> str:
    """'air: AQI 42 (good), PM2.5 8.4 µg/m³' -- the short form appended
    to the main weather line. See render_aqi_line() for the standalone
    !aqi command's fuller version.
    """
    return f"air: AQI {air.aqi} ({air.category}), PM2.5 {air.pm25:g} µg/m³"


def render_aqi_line(label: str, air: Optional[AirQuality], radius_meters: int) -> str:
    """Standalone !aqi command output -- fuller than the fragment
    appended to the weather line (includes distance/station name).
    """
    if air is None:
        radius_km = radius_meters // 1000
        return f"aqi: no air-quality station within {radius_km} km of {label}."
    distance = f", {air.distance_km}km away" if air.distance_km is not None else ""
    return (
        f"aqi: {label}: AQI {air.aqi} ({air.category}), PM2.5 {air.pm25:g} µg/m³ "
        f"-- station: {air.station_name}{distance}"
    )


def _byte_len(s: str) -> int:
    return len(s.encode("utf-8"))


def format_weather_line(
    current: CurrentWeather,
    days: list,
    air: Optional[AirQuality],
    now_utc: int,
    max_line_bytes: int = 430,
    forecast_error: bool = False,
) -> str:
    """Assembles the full " -- "-joined reply line and enforces
    max_line_bytes (measured in UTF-8 bytes -- "°"/"☀"/"µ" are all
    multi-byte, so a naive len(str) budget would under-count and still
    produce an over-length IRC line). Drop order on overflow: the air
    fragment first, then forecast days from the LAST one back -- never
    the core weather segment, never the first forecast day, and never a
    partial/truncated-mid-word segment (whole segments are dropped, not
    sliced).
    """
    core = [
        _core_segment(current),
        f"time: {units.local_hhmm(now_utc, current.tz_offset_secs)}",
        f"sunrise: {units.local_hhmm(current.sunrise_epoch, current.tz_offset_secs)}",
        f"sunset: {units.local_hhmm(current.sunset_epoch, current.tz_offset_secs)}",
    ]

    forecast_segs = []
    if days:
        forecast_segs.append(f"forecast: {format_day(days[0])}")
        for d in days[1:]:
            forecast_segs.append(format_day(d))
    elif forecast_error:
        forecast_segs.append("forecast unavailable")

    air_segs = [format_air_fragment(air)] if air is not None else []

    segments = core + forecast_segs + air_segs
    line = " -- ".join(segments)

    if _byte_len(line) <= max_line_bytes:
        return line

    # Overflow: drop air first, then forecast days from the last back,
    # keeping core + at least the first forecast segment (if any).
    droppable_tail = list(range(len(core) + len(forecast_segs), len(segments)))  # air
    droppable_tail += list(range(len(segments) - 1, len(core), -1))  # forecast days, last-first
    seen = set()
    order = [i for i in droppable_tail if not (i in seen or seen.add(i))]

    kept = list(segments)
    drop_set = set()
    for idx in order:
        drop_set.add(idx)
        trial = " -- ".join(s for i, s in enumerate(kept) if i not in drop_set)
        if _byte_len(trial) <= max_line_bytes:
            return trial
    # Could not fit even after dropping everything droppable -- return
    # core-only rather than continuing to guess.
    return " -- ".join(core)
