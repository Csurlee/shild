from plugins.SpamGuard.heuristics import (
    caps_percentage,
    highlighted_nick_count,
    prune_window,
)


# ---- prune_window ----

def test_prune_window_keeps_entries_within_window():
    result = prune_window([1.0, 5.0, 9.0], now=10.0, window_secs=5.0)
    assert result == [5.0, 9.0]


def test_prune_window_drops_everything_outside_window():
    result = prune_window([1.0, 2.0], now=100.0, window_secs=5.0)
    assert result == []


def test_prune_window_empty_input_is_empty_output():
    assert prune_window([], now=10.0, window_secs=5.0) == []


def test_prune_window_boundary_is_inclusive():
    # exactly window_secs old -- "now - t <= window_secs" keeps it
    assert prune_window([5.0], now=10.0, window_secs=5.0) == [5.0]


# ---- highlighted_nick_count ----

def test_highlighted_nick_count_counts_distinct_real_nicks():
    text = "hey Alice and Bob, check this out"
    count = highlighted_nick_count(text, {"Alice", "Bob", "Carol"}, "Dave")
    assert count == 2


def test_highlighted_nick_count_excludes_the_sender():
    text = "Alice: hey Alice, look at this"
    count = highlighted_nick_count(text, {"Alice", "Bob"}, "Alice")
    assert count == 0


def test_highlighted_nick_count_is_case_insensitive():
    text = "hey ALICE and bOb"
    count = highlighted_nick_count(text, {"Alice", "Bob"}, "Dave")
    assert count == 2


def test_highlighted_nick_count_skips_short_nicks_below_min_length():
    text = "a to be or not to be"
    count = highlighted_nick_count(text, {"a", "bo"}, "Dave", min_nick_len=3)
    assert count == 0


def test_highlighted_nick_count_respects_custom_min_length():
    text = "hey xy over there"
    assert highlighted_nick_count(text, {"xy"}, "Dave", min_nick_len=3) == 0
    assert highlighted_nick_count(text, {"xy"}, "Dave", min_nick_len=2) == 1


def test_highlighted_nick_count_no_channel_nicks_is_zero():
    assert highlighted_nick_count("anything at all", set(), "Dave") == 0


def test_highlighted_nick_count_no_matches_is_zero():
    text = "completely unrelated chatter"
    assert highlighted_nick_count(text, {"Alice", "Bob", "Carol"}, "Dave") == 0


# ---- caps_percentage ----

def test_caps_percentage_all_caps_is_one():
    assert caps_percentage("HELLO WORLD") == 1.0


def test_caps_percentage_all_lower_is_zero():
    assert caps_percentage("hello world") == 0.0


def test_caps_percentage_mixed_case():
    assert caps_percentage("HELLO world") == 0.5


def test_caps_percentage_ignores_non_letters():
    # 4 letters ("HI" + "OK"), all uppercase -> 1.0 regardless of
    # digits/punctuation surrounding them.
    assert caps_percentage("HI!!! 123 OK???") == 1.0


def test_caps_percentage_no_letters_is_zero():
    assert caps_percentage("12345 !!! ???") == 0.0


def test_caps_percentage_empty_string_is_zero():
    assert caps_percentage("") == 0.0
