import pytest

from plugins.Shild import geoip


@pytest.fixture(autouse=True)
def _reset():
    # geoip.py caches readers/failures per-path at module level -- reset
    # around every test so one test's monkeypatched/missing path never
    # leaks into another (same class of cross-test state leak this
    # codebase has hit repeatedly for registry values, see CLAUDE.md).
    geoip.reset_cache()
    yield
    geoip.reset_cache()


def test_missing_db_file_returns_none(tmp_path):
    assert geoip.lookup_country("1.1.1.1", str(tmp_path / "nope.mmdb")) is None


def test_invalid_ip_returns_none(tmp_path):
    # No DB needed -- must fail on the input before ever touching a reader.
    assert geoip.lookup_country("not-an-ip", str(tmp_path / "nope.mmdb")) is None
    assert geoip.lookup_country("256.1.1.1", str(tmp_path / "nope.mmdb")) is None


def test_corrupt_db_file_does_not_crash(tmp_path):
    p = tmp_path / "bad.mmdb"
    p.write_bytes(b"not a real mmdb file")
    assert geoip.lookup_country("1.1.1.1", str(p)) is None


def test_valid_db_returns_country(tmp_path, monkeypatch):
    class FakeReader:
        def get(self, ip):
            return {"country": {"iso_code": "DE", "names": {"en": "Germany"}}}

    p = tmp_path / "fake.mmdb"
    p.write_bytes(b"placeholder")  # only needs to exist -- open_database is monkeypatched
    monkeypatch.setattr(geoip.maxminddb, "open_database", lambda path: FakeReader())

    assert geoip.lookup_country("203.0.113.9", str(p)) == "DE"


def test_lookup_miss_returns_none(tmp_path, monkeypatch):
    class FakeReader:
        def get(self, ip):
            return None

    p = tmp_path / "fake.mmdb"
    p.write_bytes(b"placeholder")
    monkeypatch.setattr(geoip.maxminddb, "open_database", lambda path: FakeReader())

    assert geoip.lookup_country("203.0.113.9", str(p)) is None


def test_missing_country_key_returns_none(tmp_path, monkeypatch):
    class FakeReader:
        def get(self, ip):
            return {"city": {"names": {"en": "Somewhere"}}}  # no "country" block

    p = tmp_path / "fake.mmdb"
    p.write_bytes(b"placeholder")
    monkeypatch.setattr(geoip.maxminddb, "open_database", lambda path: FakeReader())

    assert geoip.lookup_country("203.0.113.9", str(p)) is None


def test_reader_opened_once_and_cached(tmp_path, monkeypatch):
    opens = []

    class FakeReader:
        def get(self, ip):
            return {"country": {"iso_code": "US"}}

    def fake_open(path):
        opens.append(path)
        return FakeReader()

    p = tmp_path / "fake.mmdb"
    p.write_bytes(b"placeholder")
    monkeypatch.setattr(geoip.maxminddb, "open_database", fake_open)

    for _ in range(5):
        assert geoip.lookup_country("203.0.113.9", str(p)) == "US"
    assert len(opens) == 1


def test_open_failure_remembered_not_retried(tmp_path, monkeypatch):
    opens = []

    def fake_open(path):
        opens.append(path)
        raise ValueError("corrupt")

    p = tmp_path / "fake.mmdb"
    p.write_bytes(b"placeholder")
    monkeypatch.setattr(geoip.maxminddb, "open_database", fake_open)

    assert geoip.lookup_country("1.1.1.1", str(p)) is None
    assert geoip.lookup_country("1.1.1.1", str(p)) is None
    assert len(opens) == 1  # not retried on every call


def test_maxminddb_not_installed_fails_closed(tmp_path, monkeypatch):
    p = tmp_path / "fake.mmdb"
    p.write_bytes(b"placeholder")
    monkeypatch.setattr(geoip, "maxminddb", None)

    assert geoip.lookup_country("1.1.1.1", str(p)) is None
