"""Pure unit tests for plugins/Shild/ban_ids.py -- no supybot import,
no plugin test harness needed.
"""
import json

from plugins.Shild.ban_ids import BanIdStore


def test_first_id_is_one(tmp_path):
    store = BanIdStore(tmp_path / "ban_ids.json")
    assert store.next_id() == 1


def test_ids_increment_sequentially(tmp_path):
    store = BanIdStore(tmp_path / "ban_ids.json")
    assert [store.next_id() for _ in range(3)] == [1, 2, 3]


def test_id_persists_and_never_resets_across_instances(tmp_path):
    path = tmp_path / "ban_ids.json"
    store = BanIdStore(path)
    store.next_id()
    store.next_id()

    reloaded = BanIdStore(path)
    assert reloaded.next_id() == 3


def test_corrupt_file_falls_back_to_one_not_crash(tmp_path):
    path = tmp_path / "ban_ids.json"
    path.write_text("{not valid json")
    store = BanIdStore(path)
    assert store.next_id() == 1


def test_missing_file_starts_at_one(tmp_path):
    store = BanIdStore(tmp_path / "does-not-exist.json")
    assert store.next_id() == 1


def test_saved_file_shape(tmp_path):
    path = tmp_path / "ban_ids.json"
    store = BanIdStore(path)
    store.next_id()
    raw = json.loads(path.read_text())
    assert raw == {"next_id": 2}
