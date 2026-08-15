import pytest

from plugins.Shild import blocklist


@pytest.fixture(autouse=True)
def _reset():
    # blocklist.py caches parsed lists per (path, mtime) at module level --
    # reset around every test so one test's file never leaks into another
    # (same class of cross-test state leak this codebase has hit
    # repeatedly for registry values, see CLAUDE.md).
    blocklist.reset_cache()
    yield
    blocklist.reset_cache()


def _write(tmp_path, name, ips):
    p = tmp_path / f"{name}.txt"
    p.write_text("\n".join(ips) + "\n")
    return p


def test_missing_lists_dir_returns_no_hits(tmp_path):
    lists = {"foo": str(tmp_path / "nope.txt")}
    assert blocklist.lookup("1.2.3.4", lists) == []


def test_hit_returns_matching_list_name(tmp_path):
    _write(tmp_path, "proxies", ["1.2.3.4", "5.6.7.8"])
    lists = {"proxies": str(tmp_path / "proxies.txt")}
    assert blocklist.lookup("1.2.3.4", lists) == ["proxies"]
    assert blocklist.lookup("9.9.9.9", lists) == []


def test_hit_across_multiple_lists_returns_all_names(tmp_path):
    _write(tmp_path, "a", ["1.2.3.4"])
    _write(tmp_path, "b", ["1.2.3.4"])
    _write(tmp_path, "c", ["9.9.9.9"])
    lists = {
        "a": str(tmp_path / "a.txt"),
        "b": str(tmp_path / "b.txt"),
        "c": str(tmp_path / "c.txt"),
    }
    assert sorted(blocklist.lookup("1.2.3.4", lists)) == ["a", "b"]


def test_comment_and_blank_lines_ignored(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("# a comment\n\n1.2.3.4\n   \n# another\n5.6.7.8\n")
    lists = {"x": str(p)}
    assert blocklist.lookup("1.2.3.4", lists) == ["x"]
    assert blocklist.lookup("5.6.7.8", lists) == ["x"]


def test_one_missing_list_does_not_block_others(tmp_path):
    _write(tmp_path, "present", ["1.2.3.4"])
    lists = {
        "present": str(tmp_path / "present.txt"),
        "missing": str(tmp_path / "missing.txt"),
    }
    assert blocklist.lookup("1.2.3.4", lists) == ["present"]


def test_stale_cache_reloads_on_mtime_change(tmp_path):
    p = _write(tmp_path, "x", ["1.2.3.4"])
    lists = {"x": str(p)}
    assert blocklist.lookup("5.6.7.8", lists) == []

    import os
    import time
    time.sleep(0.01)
    p.write_text("5.6.7.8\n")
    os.utime(p, None)  # ensure mtime actually advances on fast filesystems

    assert blocklist.lookup("5.6.7.8", lists) == ["x"]
    assert blocklist.lookup("1.2.3.4", lists) == []


def test_unchanged_file_not_reparsed(tmp_path, monkeypatch):
    p = _write(tmp_path, "x", ["1.2.3.4"])
    lists = {"x": str(p)}
    blocklist.lookup("1.2.3.4", lists)

    reads = []
    real_open = blocklist.Path.open

    def counting_open(self, *a, **kw):
        reads.append(self)
        return real_open(self, *a, **kw)

    monkeypatch.setattr(blocklist.Path, "open", counting_open)
    for _ in range(5):
        blocklist.lookup("1.2.3.4", lists)
    assert reads == []  # cache hit every time -- mtime unchanged


def test_any_list_present_true_when_at_least_one_file_exists(tmp_path):
    _write(tmp_path, "a", ["1.2.3.4"])
    lists = {
        "a": str(tmp_path / "a.txt"),
        "b": str(tmp_path / "missing.txt"),
    }
    assert blocklist.any_list_present(lists) is True


def test_any_list_present_false_when_none_exist(tmp_path):
    lists = {"a": str(tmp_path / "missing1.txt"), "b": str(tmp_path / "missing2.txt")}
    assert blocklist.any_list_present(lists) is False
