"""Pure unit tests for plugins/SpamGuard/hostbans.py -- no supybot
import, no plugin test harness needed.
"""
from plugins.SpamGuard.hostbans import HostBanStore


def test_record_first_sighting_sets_every_field(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    r = store.record("31.171.130.159", "SpamGuard: \"Czura\" - ... [id: 1]",
                      1, "Czura", "content", now=1000.0)
    assert r.host == "31.171.130.159"
    assert r.kick_reason == "SpamGuard: \"Czura\" - ... [id: 1]"
    assert r.term_id == 1
    assert r.term_text == "Czura"
    assert r.field == "content"
    assert r.first_seen_at == 1000.0
    assert r.last_seen_at == 1000.0
    assert r.hit_count == 1


def test_record_second_fresh_sighting_refreshes_timestamp_not_reason(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.record("1.1.1.1", "original reason", 1, "Czura", "content", now=1000.0)
    r2 = store.record("1.1.1.1", "a DIFFERENT reason text", 2, "other", "realname", now=2000.0)
    # kick_reason/term_id/term_text/field stay pinned to the FIRST match --
    # the whole point is a future reban reuses the ORIGINAL message.
    assert r2.kick_reason == "original reason"
    assert r2.term_id == 1
    assert r2.term_text == "Czura"
    assert r2.field == "content"
    assert r2.first_seen_at == 1000.0
    assert r2.last_seen_at == 2000.0
    assert r2.hit_count == 2


def test_touch_bumps_hit_count_and_last_seen_without_changing_reason(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.record("1.1.1.1", "original reason", 1, "Czura", "content", now=1000.0)
    store.touch("1.1.1.1", now=5000.0)
    r = store.get("1.1.1.1", now=5000.0, retention_secs=999999)
    assert r.kick_reason == "original reason"
    assert r.hit_count == 2
    assert r.last_seen_at == 5000.0
    assert r.first_seen_at == 1000.0


def test_touch_on_unknown_host_is_a_noop(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.touch("9.9.9.9", now=1000.0)  # must not raise
    assert store.get("9.9.9.9", now=1000.0, retention_secs=999999) is None


def test_get_returns_none_for_unknown_host(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    assert store.get("2.2.2.2", now=1000.0, retention_secs=999999) is None


def test_get_returns_none_once_past_retention_window(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.record("1.1.1.1", "reason", 1, "Czura", "content", now=1000.0)
    # 100s retention, checked 200s later -- well past expiry.
    assert store.get("1.1.1.1", now=1200.0, retention_secs=100.0) is None


def test_get_still_returns_record_within_retention_window(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.record("1.1.1.1", "reason", 1, "Czura", "content", now=1000.0)
    r = store.get("1.1.1.1", now=1050.0, retention_secs=100.0)
    assert r is not None
    assert r.host == "1.1.1.1"


def test_persists_to_disk_and_reloads(tmp_path):
    path = tmp_path / "hostbans.json"
    store = HostBanStore(path)
    store.record("1.1.1.1", "reason", 1, "Czura", "content", now=1000.0)
    reloaded = HostBanStore(path)
    r = reloaded.get("1.1.1.1", now=1000.0, retention_secs=999999)
    assert r is not None
    assert r.kick_reason == "reason"
    assert r.hit_count == 1


def test_remove_deletes_and_returns_true(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.record("1.1.1.1", "reason", 1, "Czura", "content", now=1000.0)
    assert store.remove("1.1.1.1") is True
    assert store.get("1.1.1.1", now=1000.0, retention_secs=999999) is None


def test_remove_unknown_host_returns_false(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    assert store.remove("9.9.9.9") is False


def test_prune_expired_deletes_only_past_retention(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.record("old.host", "reason", 1, "Czura", "content", now=1000.0)
    store.record("fresh.host", "reason", 2, "other", "content", now=9000.0)
    removed = store.prune_expired(now=9100.0, retention_secs=100.0)
    assert removed == 1
    assert store.get("old.host", now=9100.0, retention_secs=999999) is None
    assert store.get("fresh.host", now=9100.0, retention_secs=999999) is not None


def test_corrupt_file_loads_as_empty_not_crash(tmp_path):
    path = tmp_path / "hostbans.json"
    path.write_text("{not valid json")
    store = HostBanStore(path)
    assert len(store) == 0
    # Still usable afterward -- overwrites cleanly on the next record().
    store.record("1.1.1.1", "reason", 1, "Czura", "content", now=1000.0)
    assert len(store) == 1


def test_missing_file_loads_as_empty(tmp_path):
    store = HostBanStore(tmp_path / "does_not_exist.json")
    assert len(store) == 0


def test_all_sorted_most_recently_seen_first(tmp_path):
    store = HostBanStore(tmp_path / "hostbans.json")
    store.record("older", "r", 1, "t", "content", now=1000.0)
    store.record("newer", "r", 2, "t", "content", now=2000.0)
    hosts = [r.host for r in store.all()]
    assert hosts == ["newer", "older"]
