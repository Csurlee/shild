"""OpenWeatherMap client: current conditions + 5-day/3-hour forecast.
Free tier only -- data/2.5/weather and data/2.5/forecast, NOT One Call
3.0 (that tier requires a credit card on file, deliberately avoided).

Split, same convention as plugins/GitHubWatch/github.py: the fetch_*
functions are the only things that touch the network (aiohttp, never
raise, always return a (value, error) tuple); parse_* is pure and
unit-testable against canned response fixtures.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import aiohttp

CURRENT_URL = "https://api.openweathermap.org/data/2.5/weather"
FORECAST_URL = "https://api.openweathermap.org/data/2.5/forecast"


@dataclass
class CurrentWeather:
    label: str  # "Stuttgart, DE" -- OWM's own name+country, not Nominatim's
    temp_c: float
    temp_max_c: float
    feels_like_c: float
    humidity_pct: int
    wind_speed_ms: float
    clouds_pct: int
    description: str
    icon: Optional[str]
    tz_offset_secs: int
    sunrise_epoch: int
    sunset_epoch: int


async def fetch_current(
    session: aiohttp.ClientSession, lat: float, lon: float, api_key: str, timeout: float
) -> tuple[Optional[dict], Optional[str]]:
    """Raw parsed JSON body, or (None, error). Never raises -- any
    failure mode returns a short error tag so the caller can produce a
    one-line IRC reply rather than a traceback.
    """
    params = {"lat": lat, "lon": lon, "appid": api_key, "units": "metric"}
    try:
        async with session.get(
            CURRENT_URL, params=params, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            if resp.status == 401:
                return None, "http_401"
            if resp.status == 404:
                return None, "http_404"
            if resp.status == 429:
                return None, "http_429"
            if resp.status != 200:
                return None, f"http_{resp.status}"
            data = await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001 -- fail-open network boundary
        return None, type(e).__name__
    if not isinstance(data, dict):
        return None, "unexpected_response"
    return data, None


async def fetch_forecast(
    session: aiohttp.ClientSession, lat: float, lon: float, api_key: str, timeout: float
) -> tuple[Optional[list], Optional[str]]:
    """Raw forecast entry list ("list" key of the response body), or
    (None, error). Same never-raises contract as fetch_current.
    """
    params = {"lat": lat, "lon": lon, "appid": api_key, "units": "metric"}
    try:
        async with session.get(
            FORECAST_URL, params=params, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            if resp.status == 401:
                return None, "http_401"
            if resp.status == 429:
                return None, "http_429"
            if resp.status != 200:
                return None, f"http_{resp.status}"
            data = await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__
    if not isinstance(data, dict) or not isinstance(data.get("list"), list):
        return None, "unexpected_response"
    return data["list"], None


def parse_current(data: dict) -> Optional[CurrentWeather]:
    """Pure. Returns None (never raises) if the response is missing a
    field this plugin actually needs -- a malformed/unexpected OWM
    response must degrade to a one-line error, not a traceback.
    """
    try:
        main = data["main"]
        weather0 = (data.get("weather") or [{}])[0]
        wind = data.get("wind") or {}
        sys_ = data.get("sys") or {}
        name = data.get("name") or ""
        country = sys_.get("country") or ""
        label = f"{name}, {country}" if country else (name or "unknown location")
        return CurrentWeather(
            label=label,
            temp_c=float(main["temp"]),
            temp_max_c=float(main.get("temp_max", main["temp"])),
            feels_like_c=float(main.get("feels_like", main["temp"])),
            humidity_pct=int(main.get("humidity", 0)),
            wind_speed_ms=float(wind.get("speed", 0.0)),
            clouds_pct=int((data.get("clouds") or {}).get("all", 0)),
            description=weather0.get("description", "unknown"),
            icon=weather0.get("icon"),
            tz_offset_secs=int(data.get("timezone", 0)),
            sunrise_epoch=int(sys_.get("sunrise", 0)),
            sunset_epoch=int(sys_.get("sunset", 0)),
        )
    except (KeyError, TypeError, ValueError):
        return None
