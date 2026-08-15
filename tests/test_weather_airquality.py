"""Pure unit tests for plugins/Weather/airquality.py -- no supybot
import, no real network call. See the module's own docstring: the
OpenAQ v3 response shape assumed here is taken from docs, not a
captured live response (a keyless request confirmed a bare 401,
nothing past that verified live) -- these tests pin the code's
INTENDED behavior against that assumed shape, not ground truth.
"""
import pytest

from plugins.Weather.airquality import (
    nearest_location,
    parse_air_quality,
    pm25_capable_locations,
    pm25_to_aqi,
)


@pytest.mark.parametrize("pm25,expected_category", [
    (0.0, "good"),
    (12.0, "good"),
    (12.1, "moderate"),
    (35.4, "moderate"),
    (35.5, "unhealthy for sensitive groups"),
    (55.4, "unhealthy for sensitive groups"),
    (55.5, "unhealthy"),
    (150.4, "unhealthy"),
    (150.5, "very unhealthy"),
    (250.4, "very unhealthy"),
    (250.5, "hazardous"),
    (500.4, "hazardous"),
])
def test_pm25_breakpoints_map_to_the_expected_category(pm25, expected_category):
    result = pm25_to_aqi(pm25)
    assert result is not None
    aqi, category = result
    assert category == expected_category
    assert 0 <= aqi <= 500


def test_pm25_zero_maps_to_aqi_zero():
    aqi, category = pm25_to_aqi(0.0)
    assert aqi == 0


def test_pm25_negative_returns_none():
    assert pm25_to_aqi(-1.0) is None


def test_pm25_far_above_scale_caps_at_hazardous_500():
    aqi, category = pm25_to_aqi(9999.0)
    assert aqi == 500
    assert category == "hazardous"


def test_no_locations_in_range_is_a_miss_not_an_error():
    assert nearest_location([]) is None


def test_nearest_location_picks_the_smallest_distance():
    locations = [
        {"id": 1, "distance": 5000},
        {"id": 2, "distance": 1200},
        {"id": 3, "distance": 9000},
    ]
    nearest = nearest_location(locations)
    assert nearest["id"] == 2


def test_nearest_location_falls_back_to_first_when_no_distance_field():
    locations = [{"id": 1}, {"id": 2}]
    assert nearest_location(locations)["id"] == 1


def test_latest_values_are_matched_to_the_right_sensor_id():
    location = {
        "id": 42, "name": "Stuttgart Am Neckartor", "distance": 1200,
        "sensors": [
            {"id": 100, "parameter": {"name": "no2"}},
            {"id": 101, "parameter": {"name": "pm25"}},
        ],
    }
    latest = [
        {"sensorsId": 100, "value": 30.0},
        {"sensorsId": 101, "value": 8.4},
    ]
    air = parse_air_quality(location, latest)
    assert air is not None
    assert air.pm25 == 8.4
    assert air.station_name == "Stuttgart Am Neckartor"
    assert air.distance_km == 1.2


def test_a_station_with_no_pm25_sensor_returns_none():
    location = {
        "id": 42, "name": "X", "sensors": [{"id": 100, "parameter": {"name": "no2"}}],
    }
    latest = [{"sensorsId": 100, "value": 30.0}]
    assert parse_air_quality(location, latest) is None


def test_missing_latest_value_for_the_pm25_sensor_returns_none():
    location = {"id": 42, "name": "X", "sensors": [{"id": 101, "parameter": {"name": "pm25"}}]}
    assert parse_air_quality(location, []) is None


def test_an_unexpected_response_shape_returns_none_not_an_exception():
    assert parse_air_quality({}, []) is None
    assert parse_air_quality({"sensors": "not-a-list"}, []) is None


def _station(id_, distance, has_pm25):
    sensors = [{"id": id_ * 10, "parameter": {"name": "pm25"}}] if has_pm25 else \
        [{"id": id_ * 10, "parameter": {"name": "no2"}}]
    return {"id": id_, "name": f"station{id_}", "distance": distance, "sensors": sensors}


def test_pm25_capable_locations_filters_out_stations_without_a_pm25_sensor():
    # Regression: confirmed live 2026-08-14 against real Stuttgart data --
    # the single nearest station (797m) had no PM2.5 sensor while two
    # farther stations (5km, 11.4km) did. Picking only the overall-
    # nearest station silently produced no air-quality data even though
    # real PM2.5 data existed nearby.
    locations = [_station(1, 797, has_pm25=False), _station(2, 5031, has_pm25=True),
                 _station(3, 11358, has_pm25=True)]
    result = pm25_capable_locations(locations)
    assert [loc["id"] for loc in result] == [2, 3]  # nearest-first, among PM2.5-capable only


def test_pm25_capable_locations_empty_when_none_measure_pm25():
    locations = [_station(1, 100, has_pm25=False), _station(2, 200, has_pm25=False)]
    assert pm25_capable_locations(locations) == []


def test_pm25_capable_locations_empty_list_input():
    assert pm25_capable_locations([]) == []


def test_pm25_capable_locations_tolerates_malformed_sensors_field():
    locations = [{"id": 1, "distance": 100, "sensors": "not-a-list"}]
    assert pm25_capable_locations(locations) == []
