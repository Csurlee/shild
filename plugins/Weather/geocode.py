"""OpenStreetMap Nominatim client: place name -> lat/lon. Pure parsing +
one fetch function, same split as owm.py/airquality.py.

Nominatim's usage policy (operations.osmfoundation.org/policies/nominatim)
imposes real, non-optional constraints this module exists to satisfy:
max 1 request/second (enforced by client.py's TokenBucket, capacity
forced to 1.0 -- see cache.py), a mandatory identifying User-Agent (never
a library default), and mandatory client-side caching of results (see
store.py's GeocodeStore -- persisted, not just in-process, specifically
because of this requirement). This is the one external relationship this
plugin can permanently damage if these are ignored.
"""
from __future__ import annotations

import re
from typing import Optional

import aiohttp

from .store import GeocodeRecord

SEARCH_URL = "https://nominatim.openstreetmap.org/search"

_WHITESPACE_RE = re.compile(r"\s+")


def normalize_query(raw: str) -> str:
    """Collapses whitespace and lowercases for use as a cache key --
    "  Stuttgart " and "stuttgart" must share one cache entry (and one
    rate-limited Nominatim request), never two.
    """
    return _WHITESPACE_RE.sub(" ", raw.strip()).lower()


async def fetch_geocode(
    session: aiohttp.ClientSession,
    query: str,
    user_agent: str,
    timeout: float,
) -> tuple[Optional[list], Optional[str]]:
    """Raw Nominatim result list, or (None, error). Never raises. An
    empty list ([], None) is a legitimate MISS, not an error -- the
    caller (parse_geocode) is what turns that into a negative-cached
    GeocodeRecord.
    """
    headers = {"User-Agent": user_agent, "Accept-Language": "en"}
    params = {"q": query, "format": "jsonv2", "limit": 1, "addressdetails": 1}
    try:
        async with session.get(
            SEARCH_URL, headers=headers, params=params,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status == 429:
                return None, "http_429"
            if resp.status != 200:
                return None, f"http_{resp.status}"
            data = await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__
    if not isinstance(data, list):
        return None, "unexpected_response"
    return data, None


def parse_geocode(results: list, query: str, fetched_at: float) -> GeocodeRecord:
    """Pure. `results` is Nominatim's raw response list (already fetched)
    -- an empty list becomes a `miss=True` record rather than raising or
    returning None, so the caller always has a record to cache (negative
    caching, see store.py's module docstring).
    """
    if not results:
        return GeocodeRecord(
            query=query, lat=None, lon=None, display_name="", short_name="",
            country_code="", fetched_at=fetched_at, miss=True,
        )
    top = results[0]
    try:
        lat = float(top["lat"])
        lon = float(top["lon"])
    except (KeyError, TypeError, ValueError):
        return GeocodeRecord(
            query=query, lat=None, lon=None, display_name="", short_name="",
            country_code="", fetched_at=fetched_at, miss=True,
        )
    display_name = top.get("display_name", "")
    address = top.get("address") or {}
    city = address.get("city") or address.get("town") or address.get("village") or address.get("municipality")
    country_code = (address.get("country_code") or "").upper()
    if city and country_code:
        short_name = f"{city}, {country_code}"
    elif display_name:
        short_name = display_name.split(",")[0].strip()
    else:
        short_name = query
    return GeocodeRecord(
        query=query, lat=lat, lon=lon, display_name=display_name,
        short_name=short_name, country_code=country_code,
        fetched_at=fetched_at, miss=False,
    )
