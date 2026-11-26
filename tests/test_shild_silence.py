"""Pure unit tests for plugins/Shild/silence.py -- no supybot import, no
plugin test harness needed. Plugin-level wiring (_maybe_silence, the
`verify` command) is covered separately in plugins/Shild/test.py.
"""
import json
import threading

from plugins.Shild.silence import SilenceRecord, SilenceStore, generate_code


def _record(**overrides) -> SilenceRecord:
    fields = dict(
        network="test", channel="#chan", host="203.0.113.5", nick="aop",
        mask="*!*@203.0.113.5", mode_char="q", code="ABC123",
        reason="SHILD: 203.0.113.5 flooding (score: 55)",
        silenced_at=1000.0, expires_at=2000.0,
    )
    fields.update(overrides)
    return SilenceRecord(**fields)


# ---- generate_code ----

def test_generate_code_default_length_is_six():
    assert len(generate_code()) == 6


def test_generate_code_excludes_ambiguous_characters():
    codes = "".join(generate_code(50) for _ in range(50))
    assert not (set(codes) & set("01IOL"))


def test_generate_code_is_not_constant():
    codes = {generate_code() for _ in range(20)}
    assert len(codes) > 1


# ---- SilenceRecord round trip ----

def test_record_to_dict_from_dict_round_trip():
    r = _record()
    assert SilenceRecord.from_dict(r.to_dict()) == r


def test_record_key_is_network_channel_host():
    r = _record()
    assert r.key() == ("test", "#chan", "203.0.113.5")


# ---- SilenceStore basics ----

def test_add_and_get(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    r = _record()
    store.add(r)
    assert store.get("test", "#chan", "203.0.113.5") == r


def test_get_missing_returns_none(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    assert store.get("test", "#chan", "nobody.example") is None


def test_get_by_code(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    r = _record(code="ZZZ999")
    store.add(r)
    assert store.get_by_code("ZZZ999") == r
    assert store.get_by_code("NOPE12") is None


def test_remove(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    r = _record()
    store.add(r)
    assert store.remove(r.key()) is True
    assert store.get("test", "#chan", "203.0.113.5") is None
    assert store.remove(r.key()) is False  # already gone


def test_len_and_all(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    store.add(_record(host="203.0.113.5"))
    store.add(_record(host="203.0.113.6"))
    assert len(store) == 2
    assert {r.host for r in store.all()} == {"203.0.113.5", "203.0.113.6"}


def test_persists_and_reloads_across_instances(tmp_path):
    path = tmp_path / "silences.json"
    store = SilenceStore(path)
    store.add(_record())
    reloaded = SilenceStore(path)
    assert reloaded.get("test", "#chan", "203.0.113.5") is not None


def test_corrupt_file_fails_closed_to_empty(tmp_path):
    path = tmp_path / "silences.json"
    path.write_text("{not valid json")
    store = SilenceStore(path)
    assert len(store) == 0


def test_missing_file_starts_empty(tmp_path):
    store = SilenceStore(tmp_path / "does-not-exist.json")
    assert len(store) == 0


def test_saved_file_shape(tmp_path):
    path = tmp_path / "silences.json"
    store = SilenceStore(path)
    store.add(_record())
    raw = json.loads(path.read_text())
    assert raw["silences"][0]["host"] == "203.0.113.5"


# ---- prune_expired ----

def test_prune_expired_removes_and_returns_only_past_deadline(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    store.add(_record(host="expired", expires_at=100.0))
    store.add(_record(host="still-active", expires_at=9999.0))

    expired = store.prune_expired(now=500.0)

    assert [r.host for r in expired] == ["expired"]
    assert store.get("test", "#chan", "expired") is None
    assert store.get("test", "#chan", "still-active") is not None


def test_prune_expired_boundary_is_inclusive(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    store.add(_record(host="edge", expires_at=1000.0))
    expired = store.prune_expired(now=1000.0)
    assert [r.host for r in expired] == ["edge"]


def test_prune_expired_nothing_to_prune_is_a_noop(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    store.add(_record(expires_at=9999.0))
    assert store.prune_expired(now=0.0) == []
    assert len(store) == 1


# ---- concurrency (mirrors the 2026-08-24 BanIdStore/TermStore fix) ----

def test_concurrent_add_and_remove_never_corrupts_the_store(tmp_path):
    store = SilenceStore(tmp_path / "silences.json")
    errors = []

    def worker(i):
        try:
            for j in range(50):
                r = _record(host=f"host-{i}-{j}", code=f"C{i}{j}")
                store.add(r)
                store.remove(r.key())
        except Exception as e:  # pragma: no cover - failure path only
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    json.loads((tmp_path / "silences.json").read_text())  # still valid JSON
