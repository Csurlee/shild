"""Pure unit tests for plugins/SpamGuard/matcher.py -- no supybot import,
no plugin test harness needed.
"""
from plugins.SpamGuard.matcher import compile_term, first_match

REAL_SPAM_LINE = "Hi Guys! It's Madeleine Czura! Just thought I'd leave my number here in case you're lonely ;) ."


def _pair(term_id, text, *, is_pattern=False):
    """Builds a (fake-term, regex) pair the way plugin.py's
    _rebuild_matchers does, using a plain int as the stand-in "term"
    object -- these tests only care about which one wins, not the real
    Term dataclass."""
    return term_id, compile_term(text, is_pattern=is_pattern)


def test_word_matches_as_substring_inside_real_spam_line():
    regex = compile_term("Czura")
    assert regex is not None
    assert first_match([("czura-term", regex)], REAL_SPAM_LINE) == "czura-term"


def test_word_match_is_case_insensitive():
    regex = compile_term("czura")
    assert first_match([("t", regex)], REAL_SPAM_LINE) == "t"


def test_clean_message_does_not_match():
    regex = compile_term("Czura")
    assert first_match([("t", regex)], "hey everyone, nice weather today") is None


def test_phrase_with_spaces_matches():
    regex = compile_term("lonely tonight")
    assert first_match([("t", regex)], "I'm feeling lonely tonight, msg me") is not None
    assert first_match([("t", regex)], "lonely, but not tonight") is None


def test_pattern_regex_matches_rotating_template():
    # A spam template that swaps the name each run: "It's <Name>!"
    regex = compile_term(r"It's [A-Z][a-z]+ [A-Z][a-z]+!", is_pattern=True)
    assert regex is not None
    assert first_match([("t", regex)], REAL_SPAM_LINE) is not None
    assert first_match([("t", regex)], "It's Bob Smith! completely different context") is not None


def test_invalid_pattern_returns_none():
    assert compile_term("(unclosed[", is_pattern=True) is None


def test_word_with_regex_metacharacters_is_treated_literally():
    """A non-pattern term is re.escape'd -- "a.b" must match only the
    literal text "a.b", not "axb" the way an unescaped regex would."""
    regex = compile_term("a.b")
    assert first_match([("t", regex)], "contains a.b literally") is not None
    assert first_match([("t", regex)], "contains axb instead") is None


def test_empty_text_produces_no_matcher():
    assert compile_term("") is None
    assert compile_term("", is_pattern=True) is None


def test_first_match_empty_list_is_none():
    assert first_match([], REAL_SPAM_LINE) is None


def test_first_match_returns_lowest_id_first_on_multiple_hits():
    """plugin.py builds the compiled list sorted by id -- first_match
    must return whichever pair comes first in that list when more than
    one term could fire on the same text."""
    czura = compile_term("Czura")
    madeleine = compile_term("Madeleine")
    assert first_match([("first", czura), ("second", madeleine)], REAL_SPAM_LINE) == "first"
    assert first_match([("second", madeleine), ("first", czura)], REAL_SPAM_LINE) == "second"


def test_first_match_skips_non_matching_terms_before_a_later_hit():
    clean = compile_term("nomatchhere")
    czura = compile_term("Czura")
    assert first_match([("a", clean), ("b", czura)], REAL_SPAM_LINE) == "b"
