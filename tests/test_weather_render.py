"""Pure unit tests for plugins/Weather/render.py -- no supybot import,
no plugin test harness needed. The golden test reproduces the exact
reference line this plugin was built to match (see CLAUDE.md's Weather
section); everything else pins the two format details that are easy to
get subtly wrong (Fahrenheit truncation, paren-vs-slash).
"""
from datetime import datetime, timezone

from plugins.Weather.owm import CurrentWeather
from plugins.Weather.forecast import DayForecast
from plugins.Weather.airquality import AirQuality
from plugins.Weather import render, units


REFERENCE_LINE = (
    "weather: Stuttgart, DE: ☀ 27°C (80°F), max: 25°C (77°F), "
    "38% humidity, 1 km/h (1 mph) wind, feels like: 27°C / 80°F, "
    "0% cloud cover (clear sky) -- time: 10:25 -- sunrise: 06:14 -- sunset: 20:41 -- "
    "forecast: Sat: ☁ (high: 36°C / 96°F, low: 17°C / 62°F) -- "
    "Sun: ☀ (high: 30°C / 86°F, low: 21°C / 69°F) -- "
    "Mon: ☀ (high: 25°C / 77°F, low: 18°C / 64°F)"
)


def _epoch_at(hh, mm, tz_offset_secs):
    """A UTC epoch whose local wall-clock time (per tz_offset_secs) is
    hh:mm on 2026-08-14 (an arbitrary fixed date -- only the time of day
    matters for the reference line).
    """
    base = datetime(2026, 8, 14, tzinfo=timezone.utc).timestamp()
    return int(base + hh * 3600 + mm * 60 - tz_offset_secs)


def _reference_current():
    tz_offset = 7200  # CEST, UTC+2 -- consistent with the 06:14/20:41/10:25 times
    return CurrentWeather(
        label="Stuttgart, DE",
        temp_c=27.0,
        temp_max_c=25.0,
        feels_like_c=27.0,
        humidity_pct=38,
        wind_speed_ms=1 / 3.6,  # renders to 1 km/h
        clouds_pct=0,
        description="clear sky",
        icon="01d",
        tz_offset_secs=tz_offset,
        sunrise_epoch=_epoch_at(6, 14, tz_offset),
        sunset_epoch=_epoch_at(20, 41, tz_offset),
    ), tz_offset


def _reference_days():
    return [
        DayForecast(weekday="Sat", symbol="☁", high_c=36.0, low_c=17.0),
        DayForecast(weekday="Sun", symbol="☀", high_c=30.0, low_c=21.0),
        DayForecast(weekday="Mon", symbol="☀", high_c=25.0, low_c=18.0),
    ]


def test_the_idefix_reference_line_is_reproduced_character_for_character():
    current, tz_offset = _reference_current()
    now_utc = _epoch_at(10, 25, tz_offset)
    line = render.format_weather_line(current, _reference_days(), None, now_utc)
    assert line == REFERENCE_LINE


def test_fahrenheit_is_derived_from_the_integer_celsius_and_truncated():
    pairs = [
        (27, 80), (25, 77), (36, 96), (17, 62), (30, 86), (21, 69), (18, 64),
    ]
    for c, f in pairs:
        assert units.f_int(c) == f, f"{c}C should render as {f}F"


def test_rounding_would_have_produced_different_values_for_four_pairs():
    # Documents WHY f_int must truncate, not round -- these four pairs
    # from the reference would mismatch under round().
    mismatches = [(27, 80), (36, 96), (17, 62), (21, 69)]
    for c, f in mismatches:
        assert round(c * 9 / 5 + 32) != f


def test_current_and_max_use_parentheses_while_feels_like_uses_a_slash():
    assert units.temp_paren(27.0) == "27°C (80°F)"
    assert units.temp_slash(27.0) == "27°C / 80°F"


def test_wind_renders_kmh_and_mph_from_metres_per_second():
    assert units.wind_kmh(1 / 3.6) == 1
    assert units.wind_mph(1 / 3.6) == 1


def test_air_fragment_is_appended_only_when_air_quality_is_present():
    current, tz_offset = _reference_current()
    now_utc = _epoch_at(10, 25, tz_offset)
    without_air = render.format_weather_line(current, _reference_days(), None, now_utc)
    air = AirQuality(aqi=42, category="moderate", pm25=8.4, station_name="x", distance_km=1.2)
    with_air = render.format_weather_line(current, _reference_days(), air, now_utc)
    assert "air:" not in without_air
    assert with_air == without_air + " -- air: AQI 42 (moderate), PM2.5 8.4 µg/m³"


def test_forecast_unavailable_degrades_instead_of_erroring():
    current, tz_offset = _reference_current()
    now_utc = _epoch_at(10, 25, tz_offset)
    line = render.format_weather_line(current, [], None, now_utc, forecast_error=True)
    assert line.endswith("forecast unavailable")
    assert "Traceback" not in line


def test_no_forecast_and_no_error_omits_the_forecast_segment_entirely():
    current, tz_offset = _reference_current()
    now_utc = _epoch_at(10, 25, tz_offset)
    line = render.format_weather_line(current, [], None, now_utc, forecast_error=False)
    assert "forecast" not in line


def test_line_over_the_byte_limit_drops_air_then_the_last_forecast_days():
    current, tz_offset = _reference_current()
    now_utc = _epoch_at(10, 25, tz_offset)
    air = AirQuality(aqi=42, category="moderate", pm25=8.4, station_name="x", distance_km=1.2)
    full = render.format_weather_line(current, _reference_days(), air, now_utc, max_line_bytes=10_000)
    # A budget that fits everything except the air fragment:
    budget = len(full.encode("utf-8")) - len(" -- air: AQI 42 (moderate), PM2.5 8.4 µg/m³".encode("utf-8"))
    trimmed = render.format_weather_line(current, _reference_days(), air, now_utc, max_line_bytes=budget)
    assert "air:" not in trimmed
    assert "Mon:" in trimmed  # forecast days still intact at this budget


def test_line_length_is_measured_in_utf8_bytes_not_characters():
    current, tz_offset = _reference_current()
    now_utc = _epoch_at(10, 25, tz_offset)
    line = render.format_weather_line(current, _reference_days(), None, now_utc)
    # The reference line has plenty of multi-byte characters (degree
    # signs, weather symbols) -- byte length must exceed character length.
    assert len(line.encode("utf-8")) > len(line)


def test_a_severely_tight_budget_never_drops_the_core_segment():
    current, tz_offset = _reference_current()
    now_utc = _epoch_at(10, 25, tz_offset)
    air = AirQuality(aqi=42, category="moderate", pm25=8.4, station_name="x", distance_km=1.2)
    line = render.format_weather_line(current, _reference_days(), air, now_utc, max_line_bytes=1)
    assert line.startswith("weather: Stuttgart, DE:")


def test_render_aqi_line_reports_no_station_within_radius():
    line = render.render_aqi_line("Stuttgart, DE", None, 25000)
    assert line == "aqi: no air-quality station within 25 km of Stuttgart, DE."


def test_render_aqi_line_includes_distance_and_station_name():
    air = AirQuality(aqi=42, category="moderate", pm25=8.4, station_name="Am Neckartor", distance_km=1.2)
    line = render.render_aqi_line("Stuttgart, DE", air, 25000)
    assert "Am Neckartor" in line
    assert "1.2km away" in line
    assert "AQI 42 (moderate)" in line
