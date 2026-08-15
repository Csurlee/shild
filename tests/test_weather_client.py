"""Integration-style pure tests for plugins/Weather/client.py's
WeatherClient -- no supybot import. Monkeypatches the fetch_* functions
(owm/geocode/airquality) so NO real network call is ever made; this
proves the geocode -> concurrent(current, forecast, air) wiring and the
caching/rate-limiting layers work, without touching any real API.
"""
import time

import pytest

from plugins.Weather import airquality, client, geocode, owm
from plugins.Weather.store import GeocodeStore


def _make_client(tmp_path, **cfg_overrides):
    store = GeocodeStore(tmp_path / "geocode.json")
    c = client.WeatherClient(
        geocode_store=store,
        nominatim_rate_per_min=6000,
        owm_rate_per_min=6000,
        openaq_rate_per_min=6000,
    )
    cfg = client.ClientConfig(
        owm_key="fake-owm-key",
        openaq_key="fake-openaq-key",
        user_agent="test-agent",
        timeout_secs=5.0,
        forecast_days=3,
        current_ttl_secs=600,
        forecast_ttl_secs=3600,
        air_quality_ttl_secs=1800,
        geocode_hit_ttl_secs=86400,
        geocode_miss_ttl_secs=3600,
        air_quality_radius_meters=25000,
    )
    cfg.__dict__.update(cfg_overrides)
    return c, cfg


_GEOCODE_RESULTS = [{
    "lat": "48.7758", "lon": "9.1829",
    "display_name": "Stuttgart, Baden-Württemberg, Deutschland",
    "address": {"city": "Stuttgart", "country_code": "de"},
}]

_CURRENT_RESPONSE = {
    "name": "Stuttgart", "sys": {"country": "DE", "sunrise": 100, "sunset": 200},
    "main": {"temp": 27.0, "temp_max": 25.0, "feels_like": 27.0, "humidity": 38},
    "wind": {"speed": 0.28}, "clouds": {"all": 0},
    "weather": [{"description": "clear sky", "icon": "01d"}], "timezone": 7200,
}

_FORECAST_ENTRIES = [
    # "Tomorrow" relative to real wall-clock time, so daily_forecast()'s
    # today-exclusion filter (which compares against the real now_utc
    # client.py passes it) doesn't drop this entry as already-past.
    {"dt": int(time.time()) + 86400, "main": {"temp": 20.0, "temp_min": 18.0, "temp_max": 22.0},
     "weather": [{"icon": "01d"}]},
]


@pytest.fixture(autouse=True)
def _patch_network(monkeypatch):
    calls = {"geocode": 0, "current": 0, "forecast": 0, "air_locations": 0, "air_latest": 0}

    async def fake_fetch_geocode(session, query, user_agent, timeout):
        calls["geocode"] += 1
        return _GEOCODE_RESULTS, None

    async def fake_fetch_current(session, lat, lon, api_key, timeout):
        calls["current"] += 1
        return _CURRENT_RESPONSE, None

    async def fake_fetch_forecast(session, lat, lon, api_key, timeout):
        calls["forecast"] += 1
        return _FORECAST_ENTRIES, None

    async def fake_fetch_nearby(session, lat, lon, api_key, radius, timeout):
        calls["air_locations"] += 1
        # Nearest station has NO pm25 sensor -- regression coverage for
        # the real bug found live 2026-08-14: picking only the overall-
        # nearest station silently dropped real PM2.5 data available at
        # a farther one. The client must skip station 1 and use station 2.
        return [
            {"id": 1, "name": "NearestNoData", "distance": 100,
             "sensors": [{"id": 5, "parameter": {"name": "no2"}}]},
            {"id": 2, "name": "Station", "distance": 500,
             "sensors": [{"id": 9, "parameter": {"name": "pm25"}}]},
        ], None

    async def fake_fetch_latest(session, location_id, api_key, timeout):
        calls["air_latest"] += 1
        return [{"sensorsId": 9, "value": 8.4}], None

    monkeypatch.setattr(geocode, "fetch_geocode", fake_fetch_geocode)
    monkeypatch.setattr(owm, "fetch_current", fake_fetch_current)
    monkeypatch.setattr(owm, "fetch_forecast", fake_fetch_forecast)
    monkeypatch.setattr(airquality, "fetch_nearby_locations", fake_fetch_nearby)
    monkeypatch.setattr(airquality, "fetch_latest", fake_fetch_latest)
    return calls


def test_lookup_returns_current_forecast_and_air(tmp_path, _patch_network):
    c, cfg = _make_client(tmp_path)
    result = c.lookup("stuttgart", cfg)
    assert result.error is None
    assert result.current is not None
    assert result.current.label == "Stuttgart, DE"
    assert len(result.days) == 1
    assert result.air is not None
    assert result.air.pm25 == 8.4


def test_lookup_without_wanting_air_never_calls_openaq(tmp_path, _patch_network):
    c, cfg = _make_client(tmp_path)
    result = c.lookup("stuttgart", cfg, want_air=False)
    assert result.air is None
    assert _patch_network["air_locations"] == 0


def test_second_lookup_for_the_same_place_uses_the_cache(tmp_path, _patch_network):
    c, cfg = _make_client(tmp_path)
    c.lookup("stuttgart", cfg)
    c.lookup("stuttgart", cfg)
    assert _patch_network["geocode"] == 1
    assert _patch_network["current"] == 1
    assert _patch_network["forecast"] == 1


def test_lookup_without_an_openaq_key_never_calls_openaq(tmp_path, _patch_network):
    c, cfg = _make_client(tmp_path, openaq_key=None)
    result = c.lookup("stuttgart", cfg)
    assert result.air is None
    assert _patch_network["air_locations"] == 0


def test_geocode_only_does_not_touch_owm_or_openaq(tmp_path, _patch_network):
    c, cfg = _make_client(tmp_path)
    rec, err = c.geocode_only("stuttgart", cfg)
    assert err is None
    assert rec.lat == 48.7758
    assert _patch_network["current"] == 0
    assert _patch_network["forecast"] == 0
    assert _patch_network["air_locations"] == 0


def test_lookup_reports_a_geocode_miss(tmp_path, monkeypatch, _patch_network):
    async def fake_miss(session, query, user_agent, timeout):
        return [], None
    monkeypatch.setattr(geocode, "fetch_geocode", fake_miss)

    c, cfg = _make_client(tmp_path)
    result = c.lookup("xyzzy-nonexistent-place", cfg)
    assert result.current is None
    assert result.error == "geocode_miss"


def test_lookup_degrades_when_forecast_fails_but_current_succeeds(tmp_path, monkeypatch, _patch_network):
    async def fake_forecast_fail(session, lat, lon, api_key, timeout):
        return None, "http_500"
    monkeypatch.setattr(owm, "fetch_forecast", fake_forecast_fail)

    c, cfg = _make_client(tmp_path)
    result = c.lookup("stuttgart", cfg)
    assert result.current is not None
    assert result.days == []
    assert result.forecast_error is True


def test_lookup_reports_current_fetch_failure(tmp_path, monkeypatch, _patch_network):
    async def fake_current_fail(session, lat, lon, api_key, timeout):
        return None, "http_401"
    monkeypatch.setattr(owm, "fetch_current", fake_current_fail)

    c, cfg = _make_client(tmp_path)
    result = c.lookup("stuttgart", cfg)
    assert result.current is None
    assert result.error == "http_401"
