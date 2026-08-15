"""Pure unit tests for plugins/SpamGuard/mojibake.py -- no supybot import,
no plugin test harness needed. Not testing the vendored regex table's
internals (that's python-ftfy's own test suite's job) -- just that the
entry point behaves sanely: clean text scores 0, known-garbled text scores
above 0, and the upstream-named alias points at the same function.
"""
from plugins.SpamGuard.mojibake import badness, mojibake_score


def test_clean_ascii_text_scores_zero():
    assert mojibake_score("Hello, how are you doing today?") == 0


def test_clean_text_with_normal_unicode_scores_zero():
    assert mojibake_score("Café résumé naïve — nice") == 0


def test_empty_string_scores_zero():
    assert mojibake_score("") == 0


def test_known_windows1252_mojibake_scores_above_zero():
    # A real UTF-8-as-Latin-1 mojibake sample: proper "left/right double
    # quotation marks" (U+201C/U+201D) misread as Windows-1252, giving the
    # classic "â€œ...â€\x9d" garble.
    garbled = "This is â€œgarbledâ€� text"
    assert mojibake_score(garbled) > 0


def test_badness_alias_is_the_same_function():
    assert badness is mojibake_score


def test_score_increases_with_more_garbled_sequences():
    one = "â€œhelloâ€�"
    two = one + one
    assert mojibake_score(two) >= mojibake_score(one)
