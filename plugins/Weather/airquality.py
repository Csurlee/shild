"""OpenAQ v3 client: nearest station lookup + latest PM2.5 -> US AQI.

Least-verified part of this plugin (see CLAUDE.md's Weather section) --
the two-step "find nearby locations" -> "get that location's latest
values" flow and the exact response shape are taken from OpenAQ's own
docs, not a captured live response (a keyless request confirmed a bare
401, consistent with docs, but nothing past that was verified live).
Every parser here returns None on any response shape it doesn't
recognize rather than raising, and the plugin-side caller (client.py)
treats a None air-quality result as "omit the fragment", never as an
error -- so a docs/reality mismatch here can degrade the air-quality
feature but can never break the primary weather line.

Same never-raises fetch contract as owm.py/geocode.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import aiohttp

BASE_URL = "https://api.openaq.org/v3"

# US EPA PM2.5 24-hr breakpoints: (conc_low, conc_high, aqi_low, aqi_high, category)
_PM25_BREAKPOINTS = [
    (0.0, 12.0, 0, 50, "good"),
    (12.1, 35.4, 51, 100, "moderate"),
    (35.5, 55.4, 101, 150, "unhealthy for sensitive groups"),
    (55.5, 150.4, 151, 200, "unhealthy"),
    (150.5, 250.4, 201, 300, "very unhealthy"),
    (250.5, 500.4, 301, 500, "hazardous"),
]


@dataclass
class AirQuality:
    aqi: int
    category: str
    pm25: float
    station_name: str
    distance_km: Optional[float]


def pm25_to_aqi(pm25: float) -> Optional[tuple]:
    """Returns (aqi, category) via the standard EPA piecewise-linear
    breakpoint formula, or None if pm25 is negative/out of the defined
    range entirely (never raises, never extrapolates past "hazardous").
    """
    if pm25 < 0:
        return None
    for lo, hi, aqi_lo, aqi_hi, category in _PM25_BREAKPOINTS:
        if lo <= pm25 <= hi:
            aqi = ((aqi_hi - aqi_lo) / (hi - lo)) * (pm25 - lo) + aqi_lo
            return round(aqi), category
    if pm25 > _PM25_BREAKPOINTS[-1][1]:
        return 500, "hazardous"
    return None


async def fetch_nearby_locations(
    session: aiohttp.ClientSession,
    lat: float,
    lon: float,
    api_key: str,
    radius_meters: int,
    timeout: float,
) -> tuple[Optional[list], Optional[str]]:
    headers = {"X-API-Key": api_key}
    params = {"coordinates": f"{lat},{lon}", "radius": radius_meters, "limit": 5}
    try:
        async with session.get(
            f"{BASE_URL}/locations", headers=headers, params=params,
            timeout=aiohttp.ClientTimeout(total=timeout),
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
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None, "unexpected_response"
    return data["results"], None


async def fetch_latest(
    session: aiohttp.ClientSession, location_id, api_key: str, timeout: float
) -> tuple[Optional[list], Optional[str]]:
    headers = {"X-API-Key": api_key}
    try:
        async with session.get(
            f"{BASE_URL}/locations/{location_id}/latest", headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
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
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None, "unexpected_response"
    return data["results"], None


def nearest_location(locations: list) -> Optional[dict]:
    """The nearest entry from fetch_nearby_locations()'s result list, or
    None if the list is empty or every entry is malformed. OpenAQ sorts
    by distance already, but this doesn't assume that -- picks the
    smallest "distance" field explicitly, falling back to the first
    entry if none carry a usable distance.

    NOT used for picking which station to query for PM2.5 -- see
    pm25_capable_locations() below for why. Kept as a general "nearest
    station regardless of what it measures" utility.
    """
    if not locations:
        return None
    with_distance = [loc for loc in locations if isinstance(loc.get("distance"), (int, float))]
    if with_distance:
        return min(with_distance, key=lambda loc: loc["distance"])
    return locations[0]


def _has_pm25_sensor(location: dict) -> bool:
    sensors = location.get("sensors") or []
    if not isinstance(sensors, list):
        return False
    return any(
        isinstance(s, dict) and (s.get("parameter") or {}).get("name") == "pm25"
        for s in sensors
    )


def pm25_capable_locations(locations: list) -> list:
    """Locations that actually have a PM2.5 sensor, nearest first --
    filters BEFORE sorting by distance, unlike nearest_location().

    Found live 2026-08-14 (Stuttgart, real OpenAQ data) that picking the
    single overall-nearest station and giving up if it lacked PM2.5 was
    a real bug, not a hypothetical: the nearest station (797m) measured
    no PM2.5 at all, while two other stations within the same 25km
    search radius (5km and 11.4km away) did. The caller (client.py) now
    tries candidates from this list in order until one actually yields a
    value, rather than only ever looking at the single nearest station.
    """
    capable = [loc for loc in locations if _has_pm25_sensor(loc)]
    with_distance = [loc for loc in capable if isinstance(loc.get("distance"), (int, float))]
    if len(with_distance) == len(capable):
        return sorted(capable, key=lambda loc: loc["distance"])
    return capable


def parse_air_quality(location: dict, latest_results: list) -> Optional[AirQuality]:
    """Pure. Matches the PM2.5 sensor's id (from `location["sensors"]`)
    against the latest-values response, converts to US AQI. Returns None
    for any shape this doesn't recognize -- a no-PM2.5-sensor station
    (some OpenAQ stations only report NO2/O3/etc) is a legitimate,
    silent None, not an error.
    """
    try:
        sensors = location.get("sensors") or []
        pm25_sensor_ids = {
            s["id"] for s in sensors
            if isinstance(s, dict) and (s.get("parameter") or {}).get("name") == "pm25"
        }
        if not pm25_sensor_ids:
            return None
        pm25_value = None
        for r in latest_results:
            if not isinstance(r, dict):
                continue
            if r.get("sensorsId") in pm25_sensor_ids and isinstance(r.get("value"), (int, float)):
                pm25_value = float(r["value"])
                break
        if pm25_value is None:
            return None
        result = pm25_to_aqi(pm25_value)
        if result is None:
            return None
        aqi, category = result
        distance = location.get("distance")
        distance_km = round(distance / 1000.0, 1) if isinstance(distance, (int, float)) else None
        return AirQuality(
            aqi=aqi,
            category=category,
            pm25=pm25_value,
            station_name=location.get("name") or "unknown station",
            distance_km=distance_km,
        )
    except (KeyError, TypeError, ValueError):
        return None
