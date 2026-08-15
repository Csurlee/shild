"""Orchestrates one weather (or air-quality) lookup: geocode -> current +
forecast + air-quality, the last three fetched CONCURRENTLY via
asyncio.gather (independent calls, same reasoning as the latency work
done on plugins/Shild/reputation.py's Tier 1/2 -- see CLAUDE.md's
"Reputation-gathering latency" section: running independent awaits
sequentially is treated as a bug in this codebase, not a style choice).

This module is the one place aiohttp sessions get created. Each call
creates its OWN session inside the coroutine passed to asyncio.run() --
a module-level session reused across separate asyncio.run() calls would
be bound to a now-closed event loop and raise. The cost (a fresh
TCP/TLS handshake per command) is deliberately accepted and mitigated by
the caches, not avoided by a long-lived shared session -- see plugin.py's
`threaded = True` for why "a persistent worker thread/loop" (Shild's own
pattern) isn't used here.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

import aiohttp

from . import geocode, owm, airquality
from .cache import TokenBucket, TTLCache
from .forecast import daily_forecast
from .store import GeocodeRecord, GeocodeStore


@dataclass
class ClientConfig:
    owm_key: Optional[str]
    openaq_key: Optional[str]
    user_agent: str
    timeout_secs: float
    forecast_days: int
    current_ttl_secs: float
    forecast_ttl_secs: float
    air_quality_ttl_secs: float
    geocode_hit_ttl_secs: float
    geocode_miss_ttl_secs: float
    air_quality_radius_meters: int


@dataclass
class WeatherResult:
    current: Optional[owm.CurrentWeather]
    days: list
    air: Optional[airquality.AirQuality]
    forecast_error: bool
    error: Optional[str]  # set only when `current` could not be obtained at all


class WeatherClient:
    """Owns the caches/rate limiters (persist across calls within one
    plugin instance) but never a network session -- see module
    docstring. Constructed once in plugin.py's __init__ and reused for
    every command.
    """

    def __init__(self, geocode_store: GeocodeStore, nominatim_rate_per_min: float,
                 owm_rate_per_min: float, openaq_rate_per_min: float, cache_maxsize: int = 2000):
        self._geocode_store = geocode_store
        self._geo_cache = TTLCache(maxsize=cache_maxsize)
        self._weather_cache = TTLCache(maxsize=cache_maxsize)
        # capacity=1.0 -- NOT the default (rate_per_min) -- Nominatim's
        # policy forbids any burst above 1 request/second. See cache.py.
        self._nominatim_bucket = TokenBucket(rate_per_min=nominatim_rate_per_min, capacity=1.0)
        self._owm_bucket = TokenBucket(rate_per_min=owm_rate_per_min)
        self._openaq_bucket = TokenBucket(rate_per_min=openaq_rate_per_min)

    async def _geocode(self, session: aiohttp.ClientSession, query: str,
                        cfg: ClientConfig) -> tuple[Optional[GeocodeRecord], Optional[str]]:
        norm = geocode.normalize_query(query)
        now = time.time()

        cached, hit = self._geo_cache.get(("geo", norm))
        if hit:
            rec = cached
        else:
            rec = self._geocode_store.get(norm)

        if rec is not None:
            ttl = cfg.geocode_miss_ttl_secs if rec.miss else cfg.geocode_hit_ttl_secs
            fresh = (now - rec.fetched_at) <= ttl
            if fresh:
                self._geo_cache.set(("geo", norm), rec, ttl)
                return (None, "geocode_miss") if rec.miss else (rec, None)
            # Stale -- fall through to try a live refresh, but keep the
            # stale record as a fallback if Nominatim can't be reached.

        if not self._nominatim_bucket.try_acquire():
            if rec is not None:
                return (None, "geocode_miss") if rec.miss else (rec, None)  # stale-serve
            return None, "geocode_rate_limited"

        results, err = await geocode.fetch_geocode(session, query, cfg.user_agent, cfg.timeout_secs)
        if err is not None:
            if rec is not None:
                return (None, "geocode_miss") if rec.miss else (rec, None)  # stale-serve
            return None, err

        new_rec = geocode.parse_geocode(results, norm, fetched_at=now)
        self._geocode_store.put(new_rec)
        self._geo_cache.set(("geo", norm), new_rec,
                             cfg.geocode_miss_ttl_secs if new_rec.miss else cfg.geocode_hit_ttl_secs)
        if new_rec.miss:
            return None, "geocode_miss"
        return new_rec, None

    async def _fetch_current(self, session, lat, lon, cfg: ClientConfig):
        cache_key = ("current", round(lat, 3), round(lon, 3))
        cached, hit = self._weather_cache.get(cache_key)
        if hit:
            return cached, None
        if not self._owm_bucket.try_acquire():
            return None, "owm_rate_limited"
        data, err = await owm.fetch_current(session, lat, lon, cfg.owm_key, cfg.timeout_secs)
        if err is not None:
            return None, err
        current = owm.parse_current(data)
        if current is None:
            return None, "unexpected_response"
        self._weather_cache.set(cache_key, current, cfg.current_ttl_secs)
        return current, None

    async def _fetch_forecast_days(self, session, lat, lon, cfg: ClientConfig):
        """Returns (raw 3-hourly entries, failed). Deliberately does NOT
        resolve a timezone offset of its own -- forecast.py's
        module docstring: bucketing always uses the CURRENT endpoint's
        "timezone" field (fetched concurrently by _fetch_current), never
        the forecast endpoint's own "city.timezone", so the clock and
        the day boundaries in one reply can never disagree.
        """
        cache_key = ("forecast", round(lat, 3), round(lon, 3))
        cached, hit = self._weather_cache.get(cache_key)
        if hit:
            return cached, False
        if not self._owm_bucket.try_acquire():
            return [], True
        entries, err = await owm.fetch_forecast(session, lat, lon, cfg.owm_key, cfg.timeout_secs)
        if err is not None:
            return [], True
        self._weather_cache.set(cache_key, entries, cfg.forecast_ttl_secs)
        return entries, False

    # Bounds how many candidate stations _fetch_air tries per lookup --
    # each candidate costs one openaq_bucket token and one HTTP call, so
    # this caps worst-case spend on a search radius with many stations,
    # most of which don't measure PM2.5 (the common case, confirmed live
    # -- see airquality.pm25_capable_locations()'s docstring).
    _MAX_AIR_CANDIDATES = 3

    async def _fetch_air(self, session, lat, lon, label, cfg: ClientConfig):
        if not cfg.openaq_key:
            return None
        cache_key = ("air", round(lat, 3), round(lon, 3))
        cached, hit = self._weather_cache.get(cache_key)
        if hit:
            return cached
        if not self._openaq_bucket.try_acquire():
            return None
        locations, err = await airquality.fetch_nearby_locations(
            session, lat, lon, cfg.openaq_key, cfg.air_quality_radius_meters, cfg.timeout_secs)
        if err is not None or not locations:
            return None
        candidates = airquality.pm25_capable_locations(locations)[: self._MAX_AIR_CANDIDATES]
        for loc in candidates:
            # Each retry after the first also needs its own budget token
            # -- a station with no usable recent data must not let this
            # loop bypass the rate limiter.
            if loc is not candidates[0] and not self._openaq_bucket.try_acquire():
                break
            latest, err = await airquality.fetch_latest(session, loc["id"], cfg.openaq_key, cfg.timeout_secs)
            if err is not None:
                continue
            air = airquality.parse_air_quality(loc, latest)
            if air is not None:
                self._weather_cache.set(cache_key, air, cfg.air_quality_ttl_secs)
                return air
        return None

    async def _lookup(self, query: str, cfg: ClientConfig, want_air: bool) -> WeatherResult:
        async with aiohttp.ClientSession() as session:
            rec, geo_err = await self._geocode(session, query, cfg)
            if rec is None:
                return WeatherResult(None, [], None, False, geo_err)

            now_utc = int(time.time())
            current_task = self._fetch_current(session, rec.lat, rec.lon, cfg)
            forecast_task = self._fetch_forecast_days(session, rec.lat, rec.lon, cfg)
            air_task = (
                self._fetch_air(session, rec.lat, rec.lon, rec.short_name, cfg)
                if want_air else _noop()
            )

            # All three are independent of each other (only the geocode
            # result above is a shared prerequisite) -- fetched
            # concurrently, not sequentially. See module docstring.
            (current_result, current_err), (forecast_entries, forecast_failed), air = \
                await asyncio.gather(current_task, forecast_task, air_task)
            if current_result is None:
                return WeatherResult(None, [], None, False, current_err)

            days = daily_forecast(
                forecast_entries, current_result.tz_offset_secs, now_utc, days=cfg.forecast_days,
            ) if forecast_entries else []

            return WeatherResult(current_result, days, air, forecast_failed, None)

    def lookup(self, query: str, cfg: ClientConfig, want_air: bool = True) -> WeatherResult:
        """Synchronous entry point for plugin.py's threaded command
        methods -- asyncio.run() over the async pipeline above. Called
        from a dedicated command thread (threaded = True on the plugin
        class), never from the main IRC loop.
        """
        return asyncio.run(self._lookup(query, cfg, want_air))

    def geocode_only(self, query: str, cfg: ClientConfig) -> tuple[Optional[GeocodeRecord], Optional[str]]:
        """Used by setweather -- a live geocode with no weather fetch,
        so setweather can reject a place Nominatim can't find without
        spending an OWM/OpenAQ call.
        """
        async def _run():
            async with aiohttp.ClientSession() as session:
                return await self._geocode(session, query, cfg)
        return asyncio.run(_run())


async def _noop():
    return None
