"""Pure unit tests for plugins/Weather/owm.py's parsers -- no supybot
import, no real network call.
"""
from plugins.Weather.owm import parse_current


def _current_response(**overrides):
    base = {
        "name": "Stuttgart",
        "sys": {"country": "DE", "sunrise": 100, "sunset": 200},
        "main": {"temp": 27.0, "temp_max": 25.0, "feels_like": 27.0, "humidity": 38},
        "wind": {"speed": 0.28},
        "clouds": {"all": 0},
        "weather": [{"description": "clear sky", "icon": "01d"}],
        "timezone": 7200,
    }
    base.update(overrides)
    return base


def test_a_current_response_is_parsed_into_currentweather():
    cw = parse_current(_current_response())
    assert cw is not None
    assert cw.label == "Stuttgart, DE"
    assert cw.temp_c == 27.0
    assert cw.temp_max_c == 25.0
    assert cw.humidity_pct == 38
    assert cw.description == "clear sky"
    assert cw.icon == "01d"
    assert cw.tz_offset_secs == 7200
    assert cw.sunrise_epoch == 100
    assert cw.sunset_epoch == 200


def test_the_label_comes_from_owm_name_and_country_not_nominatim():
    cw = parse_current(_current_response(name="Different Name"))
    assert cw.label == "Different Name, DE"


def test_max_comes_from_main_temp_max_even_when_below_current():
    resp = _current_response()
    resp["main"]["temp"] = 27.0
    resp["main"]["temp_max"] = 25.0  # deliberately lower -- OWM's real quirk
    cw = parse_current(resp)
    assert cw.temp_max_c == 25.0
    assert cw.temp_c == 27.0


def test_missing_optional_fields_do_not_crash_the_parser():
    minimal = {
        "name": "Nowhere",
        "main": {"temp": 10.0},
        "weather": [{}],
    }
    cw = parse_current(minimal)
    assert cw is not None
    assert cw.label == "Nowhere"
    assert cw.temp_max_c == 10.0  # falls back to temp
    assert cw.feels_like_c == 10.0
    assert cw.humidity_pct == 0
    assert cw.wind_speed_ms == 0.0
    assert cw.icon is None


def test_a_response_missing_the_required_temp_field_returns_none():
    assert parse_current({"main": {}, "weather": [{}]}) is None


def test_a_completely_unexpected_shape_returns_none_not_an_exception():
    assert parse_current({"unexpected": "shape"}) is None
    assert parse_current({}) is None
