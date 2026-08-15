"""Pure unit tests for plugins/Weather/store.py -- no supybot import."""
import json

from plugins.Weather.store import (
    GeocodeRecord,
    GeocodeStore,
    LocationStore,
    SavedLocation,
    location_key,
    rfc1459_lower,
)


def _loc(key, place="Stuttgart", **kw):
    defaults = dict(label="Stuttgart, DE", lat=48.77, lon=9.18, saved_by="csurlee", saved_at=1.0)
    defaults.update(kw)
    return SavedLocation(key=key, place=place, **defaults)


# -- key derivation --------------------------------------------------

def test_rfc1459_lowercasing_folds_bracket_characters():
    assert rfc1459_lower("Foo[x]") == rfc1459_lower("foo{x}")


def test_account_key_and_nick_key_are_distinct():
    assert location_key("csurlee", "libera", "csurlee") != location_key(None, "libera", "csurlee")


def test_nick_key_is_rfc1459_lowercased():
    assert location_key(None, "libera", "Morfeus") == location_key(None, "libera", "morfeus")


def test_same_nick_on_two_networks_gets_two_keys():
    a = location_key(None, "libera", "morfeus")
    b = location_key(None, "undernet", "morfeus")
    assert a != b


def test_account_takes_priority_over_nick_when_both_present():
    key = location_key("csurlee", "libera", "someothernick")
    assert key == "acct:csurlee"


# -- LocationStore -----------------------------------------------------

def test_saved_location_round_trips_across_instances(tmp_path):
    path = tmp_path / "locations.json"
    store1 = LocationStore(path)
    assert store1.set(_loc("acct:csurlee")) is True

    store2 = LocationStore(path)
    got = store2.get("acct:csurlee")
    assert got is not None
    assert got.place == "Stuttgart"
    assert got.lat == 48.77


def test_missing_file_loads_as_empty(tmp_path):
    store = LocationStore(tmp_path / "does-not-exist.json")
    assert store.all() == []


def test_corrupt_file_is_treated_as_an_empty_store(tmp_path):
    path = tmp_path / "locations.json"
    path.write_text("{not valid json")
    store = LocationStore(path)
    assert store.all() == []
    assert store.set(_loc("acct:x")) is True  # still writable afterward


def test_one_malformed_record_does_not_discard_the_others(tmp_path):
    path = tmp_path / "locations.json"
    path.write_text(json.dumps({"locations": [
        {"key": "acct:good", "place": "X", "label": "X", "lat": 1.0, "lon": 2.0,
         "saved_by": "a", "saved_at": 1.0},
        {"place": "missing-key-field"},
    ]}))
    store = LocationStore(path)
    assert store.get("acct:good") is not None
    assert len(store.all()) == 1


def test_unset_returns_the_removed_record_and_persists_the_removal(tmp_path):
    path = tmp_path / "locations.json"
    store = LocationStore(path)
    store.set(_loc("acct:csurlee"))
    removed = store.unset("acct:csurlee")
    assert removed is not None
    assert removed.key == "acct:csurlee"
    assert LocationStore(path).get("acct:csurlee") is None


def test_unset_missing_key_returns_none(tmp_path):
    store = LocationStore(tmp_path / "locations.json")
    assert store.unset("acct:nobody") is None


def test_save_leaves_no_tmp_file_behind(tmp_path):
    path = tmp_path / "locations.json"
    store = LocationStore(path)
    store.set(_loc("acct:csurlee"))
    assert not path.with_suffix(".tmp").exists()
    assert path.exists()


# -- GeocodeStore --------------------------------------------------------

def _rec(query, miss=False, fetched_at=1.0):
    return GeocodeRecord(
        query=query, lat=48.77, lon=9.18, display_name="Stuttgart, DE",
        short_name="Stuttgart, DE", country_code="de", fetched_at=fetched_at, miss=miss,
    )


def test_geocode_record_round_trips(tmp_path):
    path = tmp_path / "geocode.json"
    store = GeocodeStore(path)
    store.put(_rec("stuttgart"))
    got = GeocodeStore(path).get("stuttgart")
    assert got is not None
    assert got.lat == 48.77


def test_geocode_store_prunes_to_max_entries(tmp_path):
    store = GeocodeStore(tmp_path / "geocode.json", max_entries=3)
    for i in range(5):
        store.put(_rec(f"place{i}", fetched_at=float(i)))
    assert len(store) == 3
    # The oldest (lowest fetched_at) entries should be the ones evicted.
    assert store.get("place0") is None
    assert store.get("place4") is not None


def test_geocode_store_prune_removes_expired_hits_and_misses_separately(tmp_path):
    store = GeocodeStore(tmp_path / "geocode.json")
    store.put(_rec("fresh-hit", miss=False, fetched_at=100.0))
    store.put(_rec("old-hit", miss=False, fetched_at=0.0))
    store.put(_rec("old-miss", miss=True, fetched_at=90.0))
    removed = store.prune(now=100.0, hit_ttl=50.0, miss_ttl=5.0)
    assert removed == 2
    assert store.get("fresh-hit") is not None
    assert store.get("old-hit") is None
    assert store.get("old-miss") is None


def test_geocode_store_clear_empties_and_persists(tmp_path):
    path = tmp_path / "geocode.json"
    store = GeocodeStore(path)
    store.put(_rec("stuttgart"))
    n = store.clear()
    assert n == 1
    assert len(GeocodeStore(path)) == 0


def test_corrupt_geocode_file_loads_as_empty(tmp_path):
    path = tmp_path / "geocode.json"
    path.write_text("not json at all")
    store = GeocodeStore(path)
    assert len(store) == 0
