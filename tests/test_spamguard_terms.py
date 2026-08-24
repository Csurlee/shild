"""Pure unit tests for plugins/SpamGuard/terms.py -- no supybot import,
no plugin test harness needed.
"""
import json
import threading

from plugins.SpamGuard.terms import TermStore


def test_add_assigns_sequential_ids_starting_at_one(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    a = store.add("word", "Czura")
    b = store.add("word", "another")
    assert a.id == 1
    assert b.id == 2


def test_add_persists_to_disk_and_reloads(tmp_path):
    path = tmp_path / "terms.json"
    store = TermStore(path)
    t = store.add("ident", "badident", added_by="csurlee")

    reloaded = TermStore(path)
    got = reloaded.get(t.id)
    assert got is not None
    assert got.text == "badident"
    assert got.category == "ident"
    assert got.added_by == "csurlee"


def test_removed_id_is_never_reused(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    first = store.add("word", "Czura")
    store.remove(first.id)
    second = store.add("word", "somethingelse")
    assert second.id != first.id
    assert second.id == 2


def test_remove_by_text_finds_and_removes(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    t = store.add("phrase", "lonely tonight")
    removed = store.remove_by_text("phrase", "lonely tonight")
    assert removed is not None
    assert removed.id == t.id
    assert store.get(t.id) is None


def test_remove_by_text_wrong_category_does_not_match(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    store.add("word", "Czura")
    assert store.remove_by_text("phrase", "Czura") is None


def test_by_category_sorted_by_id(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    store.add("word", "b")
    store.add("word", "a")
    store.add("ident", "c")
    words = store.by_category("word")
    assert [t.text for t in words] == ["b", "a"]
    assert [t.id for t in words] == [1, 2]


def test_search_by_exact_numeric_id(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    store.add("word", "Czura")
    t2 = store.add("word", "42")  # a term whose TEXT happens to be a number
    results = store.search(str(t2.id))
    assert len(results) == 1
    assert results[0].id == t2.id


def test_search_by_substring_case_insensitive(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    store.add("word", "Czura")
    store.add("ident", "scriptbot")
    results = store.search("czu")
    assert len(results) == 1
    assert results[0].text == "Czura"


def test_search_no_match_returns_empty(tmp_path):
    store = TermStore(tmp_path / "terms.json")
    store.add("word", "Czura")
    assert store.search("nothing-like-this") == []


def test_corrupt_file_loads_as_empty_not_crash(tmp_path):
    path = tmp_path / "terms.json"
    path.write_text("{not valid json")
    store = TermStore(path)
    assert store.all() == []
    # And it's still writable afterward.
    t = store.add("word", "x")
    assert t.id == 1


def test_missing_file_loads_as_empty(tmp_path):
    store = TermStore(tmp_path / "does-not-exist.json")
    assert store.all() == []


def test_saved_file_shape_has_next_id_and_terms(tmp_path):
    path = tmp_path / "terms.json"
    store = TermStore(path)
    store.add("word", "Czura")
    raw = json.loads(path.read_text())
    assert raw["next_id"] == 2
    assert len(raw["terms"]) == 1
    assert raw["terms"][0]["text"] == "Czura"


def test_stale_next_id_lower_than_an_existing_term_does_not_cause_reuse(tmp_path):
    """Regression, 2026-08-24: a file with a next_id that's present but
    STALE (lower than an existing term's own id -- e.g. restored from an
    old backup, or hand-edited) used to be trusted verbatim, so the next
    add() would silently reuse an id already in use, violating this
    store's own "an id always means the same term forever" guarantee."""
    path = tmp_path / "terms.json"
    path.write_text(json.dumps({
        "next_id": 2,  # stale -- term id 5 already exists below
        "terms": [{"id": 5, "category": "word", "text": "existing",
                   "added_by": "", "added_at": 0.0}],
    }))
    store = TermStore(path)
    added = store.add("word", "new")
    assert added.id == 6
    assert store.get(5).text == "existing"  # untouched, not overwritten


def test_missing_next_id_still_falls_back_to_max_plus_one(tmp_path):
    """Same fallback as before this fix, for the genuinely-missing case
    (not just the stale-but-present case above)."""
    path = tmp_path / "terms.json"
    path.write_text(json.dumps({
        "terms": [{"id": 7, "category": "word", "text": "existing",
                   "added_by": "", "added_at": 0.0}],
    }))
    store = TermStore(path)
    added = store.add("word", "new")
    assert added.id == 8


def test_concurrent_add_never_duplicates_or_loses_ids(tmp_path):
    """Regression, 2026-08-24 (WebPanel write-support work): add() used
    to be an unguarded read-modify-write on self._next_id -- fine when
    only the main IRC thread ever called it, but WebPanel's new POST
    routes write this same store from the HTTP server thread. 8 threads
    x 200 adds each; every id handed out must be unique, and the final
    persisted file must contain exactly that many terms (proves no add
    was silently lost to a torn/overlapping save either)."""
    store = TermStore(tmp_path / "terms.json")
    ids: list[int] = []
    lock = threading.Lock()

    def worker(n):
        for i in range(200):
            t = store.add("word", f"term-{n}-{i}")
            with lock:
                ids.append(t.id)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ids) == len(set(ids)) == 1600
    assert len(store.all()) == 1600


def test_concurrent_remove_by_text_does_not_double_remove(tmp_path):
    """Regression, 2026-08-24: remove_by_text() used to be a separate
    find_by_text() + remove(id) pair -- a genuine check-then-act race
    between two concurrent callers racing to remove the SAME term. Now
    one atomic find-then-remove under a single lock acquisition. Many
    threads race to remove the one term; exactly one must report success."""
    store = TermStore(tmp_path / "terms.json")
    store.add("word", "Czura")
    results: list = []
    lock = threading.Lock()

    def worker():
        got = store.remove_by_text("word", "Czura")
        with lock:
            results.append(got)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r is not None]
    assert len(successes) == 1
    assert store.all() == []


def test_save_is_atomic_temp_file_then_replace(tmp_path):
    """Regression, 2026-08-24: _save() used to be a bare write_text(),
    so a crash mid-write (or a concurrent reader) could see a truncated
    file -- which _load()'s fail-closed-on-JSONDecodeError path turns
    into a silently EMPTIED block list. Confirms no stray .tmp file is
    left behind after a normal save (proves replace() actually ran, not
    just that the write didn't crash)."""
    path = tmp_path / "terms.json"
    store = TermStore(path)
    store.add("word", "Czura")
    assert path.exists()
    assert not path.with_suffix(".tmp").exists()
    # And the file is genuinely valid JSON, not a partial write.
    raw = json.loads(path.read_text())
    assert raw["terms"][0]["text"] == "Czura"


def test_truncated_file_still_fails_closed_to_empty_not_crash(tmp_path):
    """A truncated/partial JSON file (the exact failure mode the atomic
    save above is meant to prevent from ever being PRODUCED by this
    store itself) must still be handled the same fail-safe way as any
    other corrupt file -- this is the regression anchor proving the
    atomic-save fix didn't change _load()'s own fail-closed contract."""
    path = tmp_path / "terms.json"
    path.write_text('{"next_id": 3, "terms": [{"id": 1, "category":')  # cut off mid-write
    store = TermStore(path)
    assert store.all() == []
    t = store.add("word", "x")
    assert t.id == 1
