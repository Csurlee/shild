"""Unit tests for plugins/WebPanel/logs.py -- the highest-risk module in
WebPanel, since the channel name in every /panel/log/<network>/<channel>
request comes straight from a URL a browser (or an attacker) controls.
"""
from pathlib import Path

from plugins.WebPanel.logs import enumerate_logs, is_safe_segment, resolve_log, tail_lines


def _make_log_tree(tmp_path: Path):
    (tmp_path / "libera" / "#windrop").mkdir(parents=True)
    (tmp_path / "libera" / "#windrop" / "#windrop.log").write_text("line1\nline2\n")
    (tmp_path / "undernet" / "#relay").mkdir(parents=True)
    (tmp_path / "undernet" / "#relay" / "#relay.log").write_text("hello\n")
    return tmp_path


# ---- is_safe_segment ----

def test_safe_segment_rejects_dot_dot():
    assert not is_safe_segment("..")


def test_safe_segment_rejects_dot():
    assert not is_safe_segment(".")


def test_safe_segment_rejects_slash():
    assert not is_safe_segment("foo/bar")


def test_safe_segment_rejects_backslash():
    assert not is_safe_segment("foo\\bar")


def test_safe_segment_rejects_nul():
    assert not is_safe_segment("foo\x00bar")


def test_safe_segment_rejects_empty():
    assert not is_safe_segment("")


def test_safe_segment_accepts_weird_but_legal_irc_channel_names():
    # IRC channel names may legally contain these characters.
    for name in ("#foo|bar", "#{a}", "#^b", "#`c", "##relay", "#a-b_c"):
        assert is_safe_segment(name), name


# ---- enumerate_logs ----

def test_enumerate_logs_finds_expected_pairs(tmp_path):
    _make_log_tree(tmp_path)
    index = enumerate_logs(str(tmp_path))
    assert set(index.keys()) == {("libera", "#windrop"), ("undernet", "#relay")}


def test_enumerate_logs_missing_base_dir_returns_empty():
    assert enumerate_logs("/does/not/exist/at/all") == {}


def test_enumerate_logs_skips_non_log_files(tmp_path):
    (tmp_path / "libera" / "#windrop").mkdir(parents=True)
    (tmp_path / "libera" / "#windrop" / "notes.txt").write_text("irrelevant")
    index = enumerate_logs(str(tmp_path))
    assert index == {}


def test_enumerate_logs_picks_most_recent_of_multiple_log_files(tmp_path):
    # Real scenario hit live 2026-08-06: a channel logging before
    # rotateLogs was turned on keeps its old un-rotated file forever
    # alongside each day's new rotated one -- and from day two of
    # rotation onward, EVERY channel has more than one .log file. Must
    # pick one (the newest), never skip the channel entirely.
    d = tmp_path / "libera" / "#windrop"
    d.mkdir(parents=True)
    old = d / "#windrop.log"
    old.write_text("old, pre-rotation content")
    import os
    import time
    new = d / "#windrop.2026-08-06.log"
    new.write_text("new, rotated content")
    # Ensure a real mtime ordering regardless of filesystem timestamp
    # resolution.
    now = time.time()
    os.utime(old, (now - 100, now - 100))
    os.utime(new, (now, now))
    index = enumerate_logs(str(tmp_path))
    assert index[("libera", "#windrop")].name == "#windrop.2026-08-06.log"


def test_enumerate_logs_empty_dir_is_skipped(tmp_path):
    d = tmp_path / "libera" / "#windrop"
    d.mkdir(parents=True)
    index = enumerate_logs(str(tmp_path))
    assert ("libera", "#windrop") not in index


def test_enumerate_logs_skips_symlinked_channel_dir(tmp_path):
    real = tmp_path / "real_target"
    real.mkdir()
    (real / "x.log").write_text("x")
    network_dir = tmp_path / "libera"
    network_dir.mkdir()
    (network_dir / "#windrop").symlink_to(real, target_is_directory=True)
    index = enumerate_logs(str(tmp_path))
    assert index == {}


# ---- resolve_log ----

def test_resolve_log_accepts_enumerated_pair(tmp_path):
    _make_log_tree(tmp_path)
    index = enumerate_logs(str(tmp_path))
    resolved = resolve_log(index, str(tmp_path), "libera", "#windrop")
    assert resolved is not None
    assert resolved.name == "#windrop.log"


def test_resolve_log_rejects_dot_dot(tmp_path):
    _make_log_tree(tmp_path)
    index = enumerate_logs(str(tmp_path))
    assert resolve_log(index, str(tmp_path), "..", "#windrop") is None
    assert resolve_log(index, str(tmp_path), "libera", "..") is None


def test_resolve_log_rejects_encoded_traversal_literal(tmp_path):
    # If a caller forgot to unquote (or double-unquoted) and the literal
    # string "%2e%2e%2f" ends up here, it's just an unknown key -- not a
    # real path component -- so it must 404, not resolve to anything.
    _make_log_tree(tmp_path)
    index = enumerate_logs(str(tmp_path))
    assert resolve_log(index, str(tmp_path), "%2e%2e%2f", "etc") is None


def test_resolve_log_rejects_embedded_slash(tmp_path):
    _make_log_tree(tmp_path)
    index = enumerate_logs(str(tmp_path))
    assert resolve_log(index, str(tmp_path), "libera", "foo/bar") is None


def test_resolve_log_rejects_unknown_pair(tmp_path):
    _make_log_tree(tmp_path)
    index = enumerate_logs(str(tmp_path))
    assert resolve_log(index, str(tmp_path), "libera", "#nosuchchannel") is None


def test_resolve_log_accepts_weird_but_legal_channel_name(tmp_path):
    d = tmp_path / "libera" / "#foo|bar"
    d.mkdir(parents=True)
    (d / "#foo|bar.log").write_text("hi\n")
    index = enumerate_logs(str(tmp_path))
    resolved = resolve_log(index, str(tmp_path), "libera", "#foo|bar")
    assert resolved is not None


def test_resolve_log_rejects_symlink_escaping_base_dir(tmp_path):
    # Belt-and-suspenders: even if something got into the index pointing
    # outside base_dir, resolve_log's own parents-check must catch it.
    outside = tmp_path / "outside.log"
    outside.write_text("secret")
    base = tmp_path / "base"
    base.mkdir()
    fake_index = {("libera", "#windrop"): outside}
    assert resolve_log(fake_index, str(base), "libera", "#windrop") is None


# ---- tail_lines ----

def test_tail_lines_returns_all_when_fewer_than_n(tmp_path):
    p = tmp_path / "f.log"
    p.write_text("a\nb\nc\n")
    assert tail_lines(p, n=10, max_bytes=1024) == ["a", "b", "c"]


def test_tail_lines_exact_n(tmp_path):
    p = tmp_path / "f.log"
    p.write_text("a\nb\nc\n")
    assert tail_lines(p, n=3, max_bytes=1024) == ["a", "b", "c"]


def test_tail_lines_more_than_n(tmp_path):
    p = tmp_path / "f.log"
    p.write_text("\n".join(str(i) for i in range(100)) + "\n")
    result = tail_lines(p, n=5, max_bytes=1024)
    assert result == ["95", "96", "97", "98", "99"]


def test_tail_lines_empty_file(tmp_path):
    p = tmp_path / "f.log"
    p.write_text("")
    assert tail_lines(p, n=10, max_bytes=1024) == []


def test_tail_lines_n_zero_or_negative(tmp_path):
    p = tmp_path / "f.log"
    p.write_text("a\nb\n")
    assert tail_lines(p, n=0, max_bytes=1024) == []
    assert tail_lines(p, n=-5, max_bytes=1024) == []


def test_tail_lines_missing_file(tmp_path):
    assert tail_lines(tmp_path / "nope.log", n=10, max_bytes=1024) == []


def test_tail_lines_discards_partial_leading_line_when_seeking(tmp_path):
    p = tmp_path / "f.log"
    # Each line is 4 bytes ("00\n" style padding) so max_bytes lands
    # mid-line deterministically.
    lines = [f"{i:03d}" for i in range(50)]
    p.write_text("\n".join(lines) + "\n")
    # max_bytes small enough to force a mid-file seek.
    result = tail_lines(p, n=1000, max_bytes=10)
    # Nothing in the result should be a truncated fragment of a real line.
    for line in result:
        assert line in lines


def test_tail_lines_invalid_utf8_is_replaced_not_raised(tmp_path):
    p = tmp_path / "f.log"
    p.write_bytes(b"good line\n\xff\xfe broken bytes\nanother good line\n")
    result = tail_lines(p, n=10, max_bytes=1024)
    assert "good line" in result
    assert "another good line" in result
