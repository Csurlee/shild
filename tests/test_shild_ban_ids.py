"""Pure unit tests for plugins/Shild/ban_ids.py -- no supybot import,
no plugin test harness needed.
"""
import json
import threading

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


def test_concurrent_next_id_never_duplicates(tmp_path):
    """Regression for a real race found via code review, 2026-08-24:
    next_id() used to do an unguarded read-modify-write, called from
    both the worker thread and the main IRC thread in the live plugin
    -- a real ban could get the same id as another real ban. 8 threads
    x 200 calls each; every id handed out must be unique."""
    store = BanIdStore(tmp_path / "ban_ids.json")
    ids: list[int] = []
    lock = threading.Lock()

    def worker():
        for _ in range(200):
            got = store.next_id()
            with lock:
                ids.append(got)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ids) == len(set(ids)) == 1600
