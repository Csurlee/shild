"""Pure unit tests for plugins/Weather/geocode.py -- no supybot import,
no real network call (fetch_geocode is never invoked; parse_geocode is
tested directly against canned Nominatim-shaped response lists, same
convention as tests/test_weather_owm.py).
"""
from plugins.Weather.geocode import normalize_query, parse_geocode


def _nominatim_result(lat="48.7758", lon="9.1829", city="Stuttgart", country_code="de"):
    return {
        "lat": lat,
        "lon": lon,
        "display_name": f"{city}, Baden-Württemberg, Deutschland",
        "address": {"city": city, "country_code": country_code},
    }


def test_query_normalisation_collapses_whitespace_and_case():
    assert normalize_query("  Stuttgart  ") == "stuttgart"
    assert normalize_query("New   York") == "new york"


def test_a_nominatim_response_is_parsed_into_a_record():
    rec = parse_geocode([_nominatim_result()], "stuttgart", fetched_at=100.0)
    assert rec.miss is False
    assert rec.lat == 48.7758
    assert rec.lon == 9.1829
    assert rec.short_name == "Stuttgart, DE"
    assert rec.query == "stuttgart"


def test_an_empty_nominatim_response_is_a_miss_not_an_error():
    rec = parse_geocode([], "xyzzy", fetched_at=100.0)
    assert rec.miss is True
    assert rec.lat is None


def test_a_malformed_lat_lon_is_a_miss_not_an_exception():
    result = _nominatim_result(lat="not-a-number")
    rec = parse_geocode([result], "stuttgart", fetched_at=100.0)
    assert rec.miss is True


def test_short_name_falls_back_to_display_name_prefix_without_address_details():
    result = {
        "lat": "1.0", "lon": "2.0",
        "display_name": "Somewhere, Some Region, Some Country",
        "address": {},
    }
    rec = parse_geocode([result], "somewhere", fetched_at=100.0)
    assert rec.short_name == "Somewhere"


def test_short_name_falls_back_to_the_query_when_nothing_else_is_available():
    result = {"lat": "1.0", "lon": "2.0"}
    rec = parse_geocode([result], "somewhere", fetched_at=100.0)
    assert rec.short_name == "somewhere"


def test_only_the_first_result_is_used():
    results = [_nominatim_result(city="First"), _nominatim_result(city="Second")]
    rec = parse_geocode(results, "ambiguous", fetched_at=100.0)
    assert rec.short_name == "First, DE"
