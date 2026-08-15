"""Pure unit tests for plugins/SpamGuard/terms.py -- no supybot import,
no plugin test harness needed.
"""
import json

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
